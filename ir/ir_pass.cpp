#include "tools/traceql/ir/ir_pass.h"
#include "tools/traceql/analysis/behavior_classifier.h"
#include "../optimize/entropy_analyzer.h"
#include "tools/traceql/ir/ir_asm_classifier.h"
#include "tools/traceql/patterns/call_pattern.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace traceql {

    namespace {

        llvm::cl::opt<std::string>
            RuntimeDetectorIrOut("traceql-ir-out", llvm::cl::desc("Output path for TraceQL IR pass JSON telemetry"),
                                 llvm::cl::init(""));

        llvm::cl::opt<bool>
            RuntimeDetectorIrWarn("traceql-ir-warn",
                                  llvm::cl::desc("Emit stderr warnings for high-risk IR findings (risk_score >= 60)"),
                                  llvm::cl::init(false));

        bool isEnvTruthy(const char *value) noexcept {
            if (value == nullptr || *value == '\0') {
                return false;
            }
            const std::string_view sv(value);
            if (sv == "0" || sv == "false" || sv == "FALSE" || sv == "off" || sv == "OFF" || sv == "no") {
                return false;
            }
            return true;
        }

        std::string resolveOutputPath() {
            if (!RuntimeDetectorIrOut.empty()) {
                return RuntimeDetectorIrOut;
            }
            if (const char *env_out = std::getenv("TRACEQL_IR_OUT")) {
                if (*env_out != '\0') {
                    return std::string(env_out);
                }
            }
            return {};
        }

        bool resolveWarnEnabled() noexcept {
            if (RuntimeDetectorIrWarn) {
                return true;
            }
            return isEnvTruthy(std::getenv("TRACEQL_IR_WARN"));
        }

        std::string demangleFunctionName(llvm::StringRef mangled) {
            if (mangled.empty()) {
                return "<unknown>";
            }
            return llvm::demangle(mangled.str());
        }

        bool isIntToPtrValue(const llvm::Value *val) {
            if (val == nullptr) {
                return false;
            }
            const llvm::Value *stripped = val->stripPointerCasts();
            if (llvm::isa<llvm::IntToPtrInst>(stripped)) {
                return true;
            }
            if (const auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(stripped)) {
                return CE->getOpcode() == llvm::Instruction::IntToPtr;
            }
            return false;
        }

        bool functionHasIntToPtr(const llvm::Function &F) {
            for (const llvm::BasicBlock &BB : F) {
                for (const llvm::Instruction &I : BB) {
                    if (llvm::isa<llvm::IntToPtrInst>(&I)) {
                        return true;
                    }
                    for (const llvm::Use &U : I.operands()) {
                        if (isIntToPtrValue(U.get())) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        void populateDebugLocation(const llvm::Instruction &I, CallPatternRecord &rec) {
            const llvm::DebugLoc &DL = I.getDebugLoc();
            if (!DL) {
                return;
            }
            rec.line = DL.getLine();
            rec.column = DL.getCol();
            if (const auto *Scope = llvm::dyn_cast_or_null<llvm::DIScope>(DL.getScope())) {
                rec.source_file = Scope->getFilename().str();
            }
        }

        void appendUniqueFunction(const llvm::Function *F, llvm::SmallVectorImpl<const llvm::Function *> &out) {
            if (F == nullptr || out.size() >= 16) {
                return;
            }
            for (const llvm::Function *existing : out) {
                if (existing == F) {
                    return;
                }
            }
            out.push_back(F);
        }

        void collectFunctionsFromConstant(const llvm::Constant *C, llvm::SmallVectorImpl<const llvm::Function *> &out,
                                          int depth = 0) {
            if (C == nullptr || depth > 3 || out.size() >= 16) {
                return;
            }
            const llvm::Value *stripped = C->stripPointerCasts();
            if (const auto *F = llvm::dyn_cast<llvm::Function>(stripped)) {
                appendUniqueFunction(F, out);
                return;
            }
            if (const auto *GA = llvm::dyn_cast<llvm::GlobalAlias>(stripped)) {
                if (const auto *Aliasee = GA->getAliasee()) {
                    collectFunctionsFromConstant(Aliasee, out, depth + 1);
                }
                return;
            }
            if (llvm::isa<llvm::ConstantArray>(stripped) || llvm::isa<llvm::ConstantStruct>(stripped)) {
                const auto *Agg = llvm::cast<llvm::Constant>(stripped);
                const unsigned n = std::min<unsigned>(Agg->getNumOperands(), 32u);
                for (unsigned i = 0; i < n && out.size() < 16; ++i) {
                    if (const auto *Elem = llvm::dyn_cast<llvm::Constant>(Agg->getOperand(i))) {
                        collectFunctionsFromConstant(Elem, out, depth + 1);
                    }
                }
            }
        }

        void resolveIrIndirectTargetsImpl(const llvm::Value *callee_val,
                                          llvm::SmallVectorImpl<const llvm::Function *> &out,
                                          llvm::SmallPtrSetImpl<const llvm::Value *> &visited, int depth) {
            if (callee_val == nullptr || depth > 4 || out.size() >= 16) {
                return;
            }
            const llvm::Value *V = callee_val->stripPointerCasts();
            if (!visited.insert(V).second) {
                return;
            }

            if (const auto *F = llvm::dyn_cast<llvm::Function>(V)) {
                appendUniqueFunction(F, out);
                return;
            }
            if (const auto *GA = llvm::dyn_cast<llvm::GlobalAlias>(V)) {
                resolveIrIndirectTargetsImpl(GA->getAliasee(), out, visited, depth + 1);
                return;
            }
            if (const auto *Sel = llvm::dyn_cast<llvm::SelectInst>(V)) {
                resolveIrIndirectTargetsImpl(Sel->getTrueValue(), out, visited, depth + 1);
                resolveIrIndirectTargetsImpl(Sel->getFalseValue(), out, visited, depth + 1);
                return;
            }
            if (const auto *Phi = llvm::dyn_cast<llvm::PHINode>(V)) {
                const unsigned n = std::min<unsigned>(Phi->getNumIncomingValues(), 8u);
                for (unsigned i = 0; i < n && out.size() < 16; ++i) {
                    resolveIrIndirectTargetsImpl(Phi->getIncomingValue(i), out, visited, depth + 1);
                }
                return;
            }
            if (const auto *LI = llvm::dyn_cast<llvm::LoadInst>(V)) {
                const llvm::Value *ptr = LI->getPointerOperand()->stripPointerCasts();
                for (int step = 0; step < 4; ++step) {
                    if (const auto *GEP = llvm::dyn_cast<llvm::GEPOperator>(ptr)) {
                        ptr = GEP->getPointerOperand()->stripPointerCasts();
                    } else {
                        break;
                    }
                }
                if (const auto *GV = llvm::dyn_cast<llvm::GlobalVariable>(ptr)) {
                    if (GV->hasInitializer() && GV->isConstant()) {
                        collectFunctionsFromConstant(GV->getInitializer(), out, 0);
                    }
                }
            }
        }

        void resolveIrIndirectTargets(const llvm::Value *callee_val, llvm::SmallVectorImpl<const llvm::Function *> &out,
                                      int depth = 0) {
            llvm::SmallPtrSet<const llvm::Value *, 16> visited;
            resolveIrIndirectTargetsImpl(callee_val, out, visited, depth);
        }

        std::string extractPrintableLiteralFromConstant(const llvm::Constant *C, int depth = 0) {
            if (C == nullptr || depth > 2) {
                return {};
            }
            if (const auto *CDS = llvm::dyn_cast<llvm::ConstantDataSequential>(C)) {
                if (CDS->getElementByteSize() != 1) {
                    return {};
                }
                llvm::StringRef raw = CDS->getRawDataValues();
                while (!raw.empty() && raw.back() == '\0') {
                    raw = raw.drop_back(1);
                }
                if (raw.size() < 2 || raw.size() > 512) {
                    return {};
                }
                for (const char ch : raw) {
                    const unsigned char uc = static_cast<unsigned char>(ch);
                    if (uc < 0x20 || uc > 0x7e) {
                        return {};
                    }
                }
                return raw.str();
            }
            if (const auto *CS = llvm::dyn_cast<llvm::ConstantStruct>(C)) {
                if (CS->getNumOperands() > 0) {
                    if (const auto *Elem = llvm::dyn_cast<llvm::Constant>(CS->getOperand(0))) {
                        return extractPrintableLiteralFromConstant(Elem, depth + 1);
                    }
                }
            }
            return {};
        }

        std::vector<std::string> extractCallArgLiterals(const llvm::CallBase *CB) {
            std::vector<std::string> literals;
            std::unordered_set<std::string> seen;
            const unsigned n = std::min<unsigned>(CB->arg_size(), 16u);
            for (unsigned i = 0; i < n; ++i) {
                const llvm::Value *arg = CB->getArgOperand(i)->stripPointerCasts();
                for (int step = 0; step < 4; ++step) {
                    if (const auto *GEP = llvm::dyn_cast<llvm::GEPOperator>(arg)) {
                        arg = GEP->getPointerOperand()->stripPointerCasts();
                    } else {
                        break;
                    }
                }
                if (const auto *GV = llvm::dyn_cast<llvm::GlobalVariable>(arg)) {
                    if (GV->hasInitializer()) {
                        std::string lit = extractPrintableLiteralFromConstant(GV->getInitializer());
                        if (!lit.empty() && seen.insert(lit).second) {
                            literals.push_back(std::move(lit));
                        }
                    }
                }
            }
            return literals;
        }

        void collectStringsFromConstant(const llvm::Constant *C, std::vector<std::string> &out,
                                        std::unordered_set<std::string> &seen, int depth = 0) {
            if (C == nullptr || depth > 2 || out.size() >= 256) {
                return;
            }
            if (const auto *CDS = llvm::dyn_cast<llvm::ConstantDataSequential>(C)) {
                if (CDS->getElementByteSize() == 1) {
                    const llvm::StringRef raw = CDS->getRawDataValues();
                    std::string decoded = sanitizeRecoveredIrBytes(std::string_view(raw.data(), raw.size()));
                    if (!decoded.empty() && seen.insert(decoded).second) {
                        out.push_back(std::move(decoded));
                    }
                }
                return;
            }
            if (const auto *CS = llvm::dyn_cast<llvm::ConstantStruct>(C)) {
                const unsigned n = std::min<unsigned>(CS->getNumOperands(), 16u);
                for (unsigned i = 0; i < n && out.size() < 256; ++i) {
                    if (const auto *Elem = llvm::dyn_cast<llvm::Constant>(CS->getOperand(i))) {
                        collectStringsFromConstant(Elem, out, seen, depth + 1);
                    }
                }
            }
        }

        void recoverStackStringsInBasicBlock(const llvm::BasicBlock &BB, const llvm::DataLayout &DL,
                                             std::unordered_set<std::string> &seen_fn_strings,
                                             std::vector<std::pair<std::string, const llvm::Instruction *>> &out) {
            if (out.size() >= 64) {
                return;
            }

            struct AllocaBuffer {
                std::map<int64_t, uint8_t> bytes;
                const llvm::Instruction *first_inst{nullptr};
            };
            std::map<const llvm::Value *, AllocaBuffer> alloca_stores;

            for (const llvm::Instruction &I : BB) {
                const auto *SI = llvm::dyn_cast<llvm::StoreInst>(&I);
                if (SI == nullptr) {
                    continue;
                }
                const llvm::Value *val_op = SI->getValueOperand();
                const auto *CI = llvm::dyn_cast<llvm::ConstantInt>(val_op);
                const auto *CDV = llvm::dyn_cast<llvm::ConstantDataVector>(val_op);
                if (CI == nullptr && (CDV == nullptr || CDV->getElementByteSize() != 1)) {
                    continue;
                }
                if (CI != nullptr) {
                    const unsigned bits = CI->getBitWidth();
                    if (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
                        continue;
                    }
                }

                llvm::APInt offset_ap(DL.getIndexSizeInBits(SI->getPointerAddressSpace()), 0);
                const llvm::Value *base = SI->getPointerOperand()->stripAndAccumulateConstantOffsets(
                    DL, offset_ap, /*AllowNonInbounds=*/true);
                if (!llvm::isa<llvm::AllocaInst>(base)) {
                    continue;
                }

                const int64_t base_offset = offset_ap.getSExtValue();
                AllocaBuffer &buf = alloca_stores[base];
                if (buf.first_inst == nullptr) {
                    buf.first_inst = SI;
                }

                if (CI != nullptr) {
                    const uint64_t val = CI->getZExtValue();
                    const unsigned num_bytes = CI->getBitWidth() / 8;
                    for (unsigned b = 0; b < num_bytes; ++b) {
                        const uint8_t byte = static_cast<uint8_t>((val >> (8u * b)) & 0xffu);
                        buf.bytes[base_offset + static_cast<int64_t>(b)] = byte;
                    }
                } else if (CDV != nullptr) {
                    const llvm::StringRef raw = CDV->getRawDataValues();
                    for (size_t b = 0; b < raw.size() && b < 256; ++b) {
                        buf.bytes[base_offset + static_cast<int64_t>(b)] = static_cast<uint8_t>(raw[b]);
                    }
                }
            }

            for (const auto &[base, buf] : alloca_stores) {
                (void)base;
                std::string current;
                int64_t prev_offset = 0;
                bool has_prev = false;

                auto flushRun = [&]() {
                    if (out.size() < 64 && isUsefulRecoveredIrString(current) &&
                        seen_fn_strings.insert(current).second) {
                        out.emplace_back(current, buf.first_inst);
                    }
                    current.clear();
                    has_prev = false;
                };

                for (const auto &[offset, byte] : buf.bytes) {
                    const bool is_printable = (byte >= 0x20 && byte <= 0x7e);
                    if (!is_printable || (has_prev && offset != prev_offset + 1)) {
                        flushRun();
                        if (!is_printable) {
                            continue;
                        }
                    }
                    if (current.size() < 512) {
                        current.push_back(static_cast<char>(byte));
                    }
                    prev_offset = offset;
                    has_prev = true;
                }
                flushRun();
            }
        }

    } // namespace

    llvm::PreservedAnalyses RuntimeDetectorIRPass::run(llvm::Module &M, llvm::ModuleAnalysisManager &) {
        CallPatternCollector collector;
        const llvm::DataLayout &DL = M.getDataLayout();
        std::unordered_set<std::string> seen_folded_strings;

        for (llvm::Function &F : M) {
            if (F.isDeclaration()) {
                continue;
            }

            const std::string caller_name = demangleFunctionName(F.getName());
            const bool fn_has_inttoptr = functionHasIntToPtr(F);
            std::vector<std::pair<std::string, const llvm::Instruction *>> stack_strings;

            for (llvm::BasicBlock &BB : F) {
                recoverStackStringsInBasicBlock(BB, DL, seen_folded_strings, stack_strings);

                for (llvm::Instruction &I : BB) {
                    const auto *CB = llvm::dyn_cast<llvm::CallBase>(&I);
                    if (CB == nullptr) {
                        continue;
                    }

                    if (CB->isInlineAsm()) {
                        const auto *IA = llvm::dyn_cast<llvm::InlineAsm>(CB->getCalledOperand());
                        if (IA == nullptr) {
                            continue;
                        }
                        const IrAsmFinding finding = classifyInlineAsm(IA->getAsmString());
                        if (!finding.matched) {
                            continue;
                        }

                        CallPatternRecord rec;
                        rec.caller_function = caller_name;
                        rec.kind = "ir_inline_asm";
                        rec.symbol = "__asm_" + finding.mnemonic;
                        rec.is_inline_asm = true;
                        rec.behavior_category = finding.category;
                        rec.behavior_tags = {finding.tag};
                        rec.risk_score = finding.risk_score;
                        populateDebugLocation(I, rec);
                        collector.add(std::move(rec));
                        continue;
                    }

                    if (CB->getCalledFunction() == nullptr) {
                        const llvm::Value *called_op = CB->getCalledOperand();
                        const bool is_inttoptr_call = isIntToPtrValue(called_op) || fn_has_inttoptr;

                        if (is_inttoptr_call) {
                            CallPatternRecord rec;
                            rec.caller_function = caller_name;
                            rec.is_indirect_call = true;
                            populateDebugLocation(I, rec);
                            rec.kind = "ir_inttoptr_exec";
                            rec.symbol = "<ir_inttoptr_call>";
                            rec.behavior_category = "MemoryProtection";
                            rec.behavior_tags = {"ir-inttoptr-exec"};
                            rec.tainted_exec_flow = true;
                            rec.risk_score = 80;
                            collector.add(std::move(rec));
                            continue;
                        }

                        llvm::SmallVector<const llvm::Function *, 8> resolved_targets;
                        resolveIrIndirectTargets(called_op, resolved_targets);
                        if (!resolved_targets.empty()) {
                            const std::vector<std::string> arg_literals = extractCallArgLiterals(CB);
                            for (const llvm::Function *TargetF : resolved_targets) {
                                BehaviorFeatures features;
                                features.call_kind = "indirect";
                                features.resolved_from_symbol = true;
                                features.is_variadic = TargetF->isVarArg();
                                features.string_literals = arg_literals;
                                features.caller_function = caller_name;

                                const BehaviorAssessment assessment = BehaviorClassifier::classify(features);
                                uint32_t risk = assessment.risk_score;
                                if (TargetF->isDeclaration() && risk < 55) {
                                    risk = 55;
                                }

                                CallPatternRecord rec;
                                rec.caller_function = caller_name;
                                rec.kind = "ir_resolved_indirect_call";
                                rec.symbol = TargetF->getName().str();
                                rec.is_indirect_call = true;
                                rec.arg_literals = arg_literals;
                                rec.behavior_category = getBehaviorCategoryName(assessment.primary_category);
                                if (rec.behavior_category == "Benign") {
                                    rec.behavior_category = "IndirectCall";
                                }
                                rec.behavior_tags = {"ir-resolved-indirect-call"};
                                for (const std::string &tag : assessment.tags) {
                                    if (std::find(rec.behavior_tags.begin(), rec.behavior_tags.end(), tag) ==
                                        rec.behavior_tags.end()) {
                                        rec.behavior_tags.push_back(tag);
                                    }
                                }
                                rec.risk_score = risk;
                                rec.behavior_rationale = assessment.rationale;
                                populateDebugLocation(I, rec);
                                collector.add(std::move(rec));
                            }
                            continue;
                        }

                        CallPatternRecord rec;
                        rec.caller_function = caller_name;
                        rec.is_indirect_call = true;
                        populateDebugLocation(I, rec);
                        rec.kind = "ir_indirect_call";
                        rec.symbol = "<ir_indirect_call>";
                        rec.behavior_category = "IndirectCall";
                        rec.behavior_tags = {"ir-indirect-call"};
                        rec.risk_score = 30;
                        collector.add(std::move(rec));
                    }
                }
            }

            for (const auto &[decoded, inst] : stack_strings) {
                CallPatternRecord rec;
                rec.caller_function = caller_name;
                rec.kind = "ir_folded_string";
                rec.symbol = "<ir_folded_string>";
                rec.behavior_category = "Benign";
                rec.behavior_tags = {"ir-folded-stack-string"};
                rec.risk_score = 0;
                rec.arg_literals = {decoded};
                if (inst != nullptr) {
                    populateDebugLocation(*inst, rec);
                }
                collector.add(std::move(rec));
            }
        }

        std::vector<std::string> global_strings;
        for (const llvm::GlobalVariable &GV : M.globals()) {
            if (!GV.hasInitializer()) {
                continue;
            }

            collectStringsFromConstant(GV.getInitializer(), global_strings, seen_folded_strings);

            const auto *CDS = llvm::dyn_cast<llvm::ConstantDataSequential>(GV.getInitializer());
            if (CDS == nullptr || CDS->getElementByteSize() != 1 || CDS->getNumElements() < 32) {
                continue;
            }

            const llvm::StringRef raw = CDS->getRawDataValues();
            const double ent =
                EntropyAnalyzer::computeByteEntropy(reinterpret_cast<const uint8_t *>(raw.data()), raw.size());
            if (ent >= 7.2) {
                CallPatternRecord rec;
                rec.caller_function = "<global>";
                rec.kind = "ir_high_entropy_global";
                rec.symbol = GV.getName().str();
                rec.arg_entropy = ent;
                rec.has_high_entropy_literal = true;
                rec.behavior_category = "Obfuscation";
                rec.behavior_tags = {"ir-high-entropy-global"};
                rec.risk_score = 60;
                collector.add(std::move(rec));
            }
        }

        for (const std::string &decoded : global_strings) {
            CallPatternRecord rec;
            rec.caller_function = "<global>";
            rec.kind = "ir_folded_string";
            rec.symbol = "<ir_folded_string>";
            rec.behavior_category = "Benign";
            rec.behavior_tags = {"ir-folded-global-string"};
            rec.risk_score = 0;
            rec.arg_literals = {decoded};
            collector.add(std::move(rec));
        }

        const std::string out_path = resolveOutputPath();
        if (!out_path.empty()) {
            if (!collector.writeJsonFile(out_path)) {
                llvm::errs() << "[traceql-ir] failed to write JSON output to: " << out_path << "\n";
            }
        }

        if (resolveWarnEnabled()) {
            for (const CallPatternRecord &rec : collector.records()) {
                if (rec.risk_score >= 60) {
                    llvm::errs() << "[traceql-ir] risk=" << rec.risk_score << " category=" << rec.behavior_category
                                 << " kind=" << rec.kind << " symbol=" << rec.symbol
                                 << " caller=" << rec.caller_function;
                    if (!rec.source_file.empty() || rec.line != 0) {
                        llvm::errs() << " (" << rec.source_file << ":" << rec.line << ":" << rec.column << ")";
                    }
                    llvm::errs() << "\n";
                }
            }
        }

        return llvm::PreservedAnalyses::all();
    }

} // namespace traceql

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "TraceQLIR", LLVM_VERSION_STRING, [](llvm::PassBuilder &PB) {
                PB.registerPipelineStartEPCallback([](llvm::ModulePassManager &MPM, llvm::OptimizationLevel Level) {
                    if (Level == llvm::OptimizationLevel::O0) {
                        MPM.addPass(traceql::RuntimeDetectorIRPass());
                    }
                });
                PB.registerOptimizerLastEPCallback(
                    [](llvm::ModulePassManager &MPM, llvm::OptimizationLevel Level, llvm::ThinOrFullLTOPhase) {
                        if (Level != llvm::OptimizationLevel::O0) {
                            MPM.addPass(traceql::RuntimeDetectorIRPass());
                        }
                    });
                PB.registerPipelineParsingCallback([](llvm::StringRef Name, llvm::ModulePassManager &MPM,
                                                      llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                    if (Name == "traceql-ir") {
                        MPM.addPass(traceql::RuntimeDetectorIRPass());
                        return true;
                    }
                    return false;
                });
            }};
}
