#include "patterns/call_pattern.h"

#include "optimize/entropy_analyzer.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace traceql {

    namespace {

        double round4(double value) {
            return std::round(value * 10000.0) / 10000.0;
        }

        bool hasTag(const CallPatternRecord &r, std::string_view tag) {
            for (const auto &t : r.behavior_tags) {
                if (t == tag) {
                    return true;
                }
            }
            return false;
        }

        bool isDynamicResolution(const CallPatternRecord &r) {
            return r.behavior_category == "DynamicResolution" || hasTag(r, "dynamic_resolution") ||
                   hasTag(r, "iat_evasion");
        }

        bool isIndirectInvocation(const CallPatternRecord &r) {
            return r.is_indirect_call || r.behavior_category == "IndirectCall" || !r.resolved_from_symbol.empty() ||
                   r.kind == "indirect" || r.kind == "fn_ptr_cast" || hasTag(r, "resolved_symbol_invocation");
        }

        bool isMemoryAllocation(const CallPatternRecord &r) {
            return r.behavior_category == "MemoryAllocation";
        }

        bool isMemoryProtection(const CallPatternRecord &r) {
            return r.behavior_category == "MemoryProtection";
        }

        bool isProcessThreadOp(const CallPatternRecord &r) {
            return r.behavior_category == "ProcessThreadOp";
        }

        bool isDirectSyscall(const CallPatternRecord &r) {
            return r.behavior_category == "DirectSyscall" ||
                   (r.is_inline_asm && (hasTag(r, "direct_syscall") || hasTag(r, "syscall")));
        }

        bool isAntiDebug(const CallPatternRecord &r) {
            return r.behavior_category == "AntiDebugOrTiming";
        }

        bool isHighEntropyPayload(const CallPatternRecord &r) {
            return (r.behavior_category == "ObfuscatedPayload" &&
                    (r.arg_entropy >= 6.8 || hasTag(r, "xor_decoding_loop"))) ||
                   (r.has_high_entropy_literal && r.arg_entropy >= 6.8);
        }

        bool isMemoryStagingOrIO(const CallPatternRecord &r) {
            return isMemoryProtection(r) || isProcessThreadOp(r) || isDirectSyscall(r) || isDynamicResolution(r) ||
                   hasTag(r, "rwx_protection") || hasTag(r, "executable_memory") || hasTag(r, "xor_decoding_loop");
        }

        bool isExecTrigger(const CallPatternRecord &r) {
            return isProcessThreadOp(r) || isIndirectInvocation(r) || isDirectSyscall(r);
        }

        bool isSuspiciousPostOp(const CallPatternRecord &r) {
            return isMemoryAllocation(r) || isMemoryProtection(r) || isProcessThreadOp(r) || isDirectSyscall(r) ||
                   isDynamicResolution(r) || isIndirectInvocation(r) || isHighEntropyPayload(r) || r.risk_score >= 40;
        }

        void addUniqueChain(std::vector<std::string> &chains, std::string name) {
            if (std::find(chains.begin(), chains.end(), name) == chains.end()) {
                chains.push_back(std::move(name));
            }
        }

        std::vector<std::string> detectBehavioralChains(const std::vector<const CallPatternRecord *> &calls) {
            std::vector<std::string> chains;

            // 1. dynamic_resolve_and_invoke: DynamicResolution -> IndirectCall (or resolved_from_symbol)
            for (size_t i = 0; i < calls.size(); ++i) {
                if (!calls[i]->resolved_from_symbol.empty() && isIndirectInvocation(*calls[i])) {
                    addUniqueChain(chains, "dynamic_resolve_and_invoke");
                    break;
                }
                if (isDynamicResolution(*calls[i])) {
                    for (size_t j = i + 1; j < calls.size(); ++j) {
                        if (isIndirectInvocation(*calls[j])) {
                            addUniqueChain(chains, "dynamic_resolve_and_invoke");
                            break;
                        }
                    }
                }
                if (std::find(chains.begin(), chains.end(), "dynamic_resolve_and_invoke") != chains.end()) {
                    break;
                }
            }

            // 2. alloc_protect_exec_chain: MemoryAllocation -> MemoryProtection -> Execution (or RWX alloc -> exec)
            for (size_t i = 0; i < calls.size(); ++i) {
                if (!isMemoryAllocation(*calls[i])) {
                    continue;
                }
                bool found = false;
                const bool alloc_rwx = hasTag(*calls[i], "rwx_protection") || hasTag(*calls[i], "executable_memory");
                for (size_t j = i + 1; j < calls.size(); ++j) {
                    if (isMemoryProtection(*calls[j])) {
                        for (size_t k = j + 1; k < calls.size(); ++k) {
                            if (isExecTrigger(*calls[k])) {
                                addUniqueChain(chains, "alloc_protect_exec_chain");
                                found = true;
                                break;
                            }
                        }
                        if (found)
                            break;
                    } else if (alloc_rwx && isExecTrigger(*calls[j])) {
                        addUniqueChain(chains, "alloc_protect_exec_chain");
                        found = true;
                        break;
                    }
                }
                if (found)
                    break;
            }

            // 3. high_entropy_payload_staging: high-entropy literal/payload paired with memory/IO staging
            bool has_high_ent = false;
            bool has_staging = false;
            for (const CallPatternRecord *r : calls) {
                if (isHighEntropyPayload(*r)) {
                    has_high_ent = true;
                }
                if (isMemoryStagingOrIO(*r)) {
                    has_staging = true;
                }
            }
            if (has_high_ent && has_staging) {
                addUniqueChain(chains, "high_entropy_payload_staging");
            }

            // 4. direct_syscall_evasion: raw syscall / direct syscall instruction usage
            for (const CallPatternRecord *r : calls) {
                if (isDirectSyscall(*r)) {
                    addUniqueChain(chains, "direct_syscall_evasion");
                    break;
                }
            }

            // 5. anti_debug_gated_execution: AntiDebugOrTiming -> suspicious post-check operation
            for (size_t i = 0; i < calls.size(); ++i) {
                if (!isAntiDebug(*calls[i])) {
                    continue;
                }
                bool gated = false;
                for (size_t j = i + 1; j < calls.size(); ++j) {
                    if (isSuspiciousPostOp(*calls[j])) {
                        addUniqueChain(chains, "anti_debug_gated_execution");
                        gated = true;
                        break;
                    }
                }
                if (gated)
                    break;
            }

            // 6. cross_process_memory_or_thread_chain: ProcessThreadOp correlated with memory/evasion ops
            bool has_proc_op = false;
            bool has_mem_or_evasion = false;
            bool explicit_cross_proc = false;
            for (const CallPatternRecord *r : calls) {
                if (isProcessThreadOp(*r)) {
                    has_proc_op = true;
                }
                if (isMemoryAllocation(*r) || isMemoryProtection(*r) || isDynamicResolution(*r) ||
                    isDirectSyscall(*r)) {
                    has_mem_or_evasion = true;
                }
                if (hasTag(*r, "cross_process") || hasTag(*r, "process_injection") || hasTag(*r, "remote_thread")) {
                    explicit_cross_proc = true;
                }
            }
            if (explicit_cross_proc || (has_proc_op && has_mem_or_evasion)) {
                addUniqueChain(chains, "cross_process_memory_or_thread_chain");
            }

            return chains;
        }

        uint32_t computeCallerRiskScore(const std::vector<const CallPatternRecord *> &calls,
                                        const std::vector<std::string> &detected_chains, double max_arg_entropy) {
            uint32_t max_call_risk = 0;
            for (const CallPatternRecord *r : calls) {
                max_call_risk = std::max(max_call_risk, r->risk_score);
            }

            uint32_t score = max_call_risk;
            for (const auto &chain : detected_chains) {
                if (chain == "alloc_protect_exec_chain" || chain == "direct_syscall_evasion" ||
                    chain == "cross_process_memory_or_thread_chain") {
                    score += 20;
                } else {
                    score += 15;
                }
            }

            if (max_arg_entropy >= 6.8 && score > 0) {
                score += 5;
            }

            return std::min<uint32_t>(100, score);
        }

        bool isPseudoCaller(std::string_view caller) {
            return caller.empty() || caller == "<global>" || caller == "<unknown>";
        }

        void expandIntraTuCallsDfs(size_t current_idx, const std::string &root_caller,
                                   const std::vector<std::vector<const CallPatternRecord *>> &grouped_records,
                                   const std::unordered_map<std::string, size_t> &caller_to_index,
                                   std::unordered_set<size_t> &visited,
                                   std::vector<const CallPatternRecord *> &expanded_calls,
                                   std::vector<std::string> &transitive_callees) {
            for (const CallPatternRecord *rec : grouped_records[current_idx]) {
                expanded_calls.push_back(rec);

                const auto callee_it = caller_to_index.find(rec->symbol);
                const bool is_intra = rec->is_intra_tu_call || (callee_it != caller_to_index.end());
                if (!is_intra || rec->symbol.empty()) {
                    continue;
                }

                if (rec->symbol != root_caller && std::find(transitive_callees.begin(), transitive_callees.end(),
                                                            rec->symbol) == transitive_callees.end()) {
                    transitive_callees.push_back(rec->symbol);
                }

                if (callee_it != caller_to_index.end() && visited.insert(callee_it->second).second) {
                    expandIntraTuCallsDfs(callee_it->second, root_caller, grouped_records, caller_to_index, visited,
                                          expanded_calls, transitive_callees);
                }
            }
        }

    } // namespace

    std::string CallPatternRecord::formatSignature() const {
        std::ostringstream os;
        if (!return_type.empty()) {
            os << return_type << ' ';
        }
        os << symbol << '(';
        for (size_t i = 0; i < param_types.size(); ++i) {
            if (i > 0)
                os << ", ";
            os << param_types[i];
        }
        if (is_variadic) {
            if (!param_types.empty())
                os << ", ";
            os << "...";
        }
        os << ')';
        return os.str();
    }

    std::string CallPatternRecord::formatCanonicalPattern() const {
        std::ostringstream os;
        os << '[' << (library.empty() ? "external" : library) << "] " << formatSignature() << " @ (";
        for (size_t i = 0; i < arg_shapes.size(); ++i) {
            if (i > 0)
                os << ", ";
            os << arg_shapes[i];
        }
        os << ')';
        return os.str();
    }

    void CallPatternCollector::add(CallPatternRecord record) {
        records_.push_back(std::move(record));
    }

    void CallPatternCollector::clear() noexcept {
        records_.clear();
    }

    std::vector<FunctionCallSequence> CallPatternCollector::buildSequences() const {
        std::vector<FunctionCallSequence> sequences;
        std::vector<std::vector<const CallPatternRecord *>> grouped_records;
        std::unordered_map<std::string, size_t> caller_to_index;

        for (const auto &rec : records_) {
            const std::string caller = rec.caller_function.empty() ? std::string("<global>") : rec.caller_function;
            size_t idx = sequences.size();
            auto map_it = caller_to_index.find(caller);
            if (map_it != caller_to_index.end()) {
                idx = map_it->second;
            } else {
                for (size_t i = 0; i < sequences.size(); ++i) {
                    if (sequences[i].caller_function == caller) {
                        idx = i;
                        break;
                    }
                }
            }
            if (idx == sequences.size()) {
                FunctionCallSequence seq;
                seq.caller_function = caller;
                sequences.push_back(std::move(seq));
                grouped_records.emplace_back();
                if (!isPseudoCaller(caller)) {
                    caller_to_index.emplace(caller, idx);
                }
            }
            sequences[idx].call_patterns.push_back(rec.formatCanonicalPattern());
            if (rec.is_auto_init_entrypoint) {
                sequences[idx].is_auto_init_entrypoint = true;
                if (sequences[idx].entrypoint_kind.empty() && !rec.entrypoint_kind.empty()) {
                    sequences[idx].entrypoint_kind = rec.entrypoint_kind;
                }
            }
            grouped_records[idx].push_back(&rec);
        }

        for (size_t i = 0; i < sequences.size(); ++i) {
            auto &seq = sequences[i];
            const auto &direct_calls = grouped_records[i];

            seq.sequence_entropy = EntropyAnalyzer::computeSequenceEntropy(seq.call_patterns);
            const bool is_pseudo = isPseudoCaller(seq.caller_function);

            std::vector<const CallPatternRecord *> effective_calls;
            if (!is_pseudo) {
                std::unordered_set<size_t> visited;
                visited.insert(i);
                expandIntraTuCallsDfs(i, seq.caller_function, grouped_records, caller_to_index, visited,
                                      effective_calls, seq.transitive_callees);
                seq.detected_chains = detectBehavioralChains(effective_calls);
            } else {
                effective_calls = direct_calls;
            }

            double max_ent = 0.0;
            for (const CallPatternRecord *r : effective_calls) {
                max_ent = std::max(max_ent, r->arg_entropy);
            }
            seq.max_arg_entropy = max_ent;
            seq.caller_risk_score = computeCallerRiskScore(effective_calls, seq.detected_chains, max_ent);
        }

        return sequences;
    }

    std::string CallPatternCollector::toJson() const {
        uint32_t max_risk_score = 0;
        double max_entropy = 0.0;

        nlohmann::json calls_arr = nlohmann::json::array();
        for (const auto &r : records_) {
            max_risk_score = std::max(max_risk_score, r.risk_score);
            max_entropy = std::max(max_entropy, r.arg_entropy);

            nlohmann::json item = {
                {"caller", r.caller_function},
                {"symbol", r.symbol},
                {"mangled_symbol", r.mangled_symbol},
                {"library", r.library},
                {"category", r.category},
                {"kind", r.kind},
                {"signature", r.formatSignature()},
                {"pattern", r.formatCanonicalPattern()},
                {"all_args_constant", r.all_args_constant},
                {"arg_literals", r.arg_literals},
                {"file", r.source_file},
                {"line", r.line},
                {"column", r.column},
                {"behavior_category", r.behavior_category},
                {"behavior_tags", r.behavior_tags},
                {"risk_score", r.risk_score},
                {"arg_entropy", round4(r.arg_entropy)},
                {"has_high_entropy_literal", r.has_high_entropy_literal},
                {"is_indirect_call", r.is_indirect_call},
                {"is_inline_asm", r.is_inline_asm},
                {"is_auto_init_entrypoint", r.is_auto_init_entrypoint},
                {"entrypoint_kind", r.entrypoint_kind},
                {"is_intra_tu_call", r.is_intra_tu_call},
                {"tainted_exec_flow", r.tainted_exec_flow},
                {"resolved_from_symbol", r.resolved_from_symbol},
                {"behavior_rationale", r.behavior_rationale},
            };
            if (!r.lock_name.empty()) {
                item["lock_name"] = r.lock_name;
            }
            if (!r.lock_held_prev.empty()) {
                item["lock_held_prev"] = r.lock_held_prev;
            }
            if (!r.lifetime_kind.empty()) {
                item["lifetime_kind"] = r.lifetime_kind;
            }
            calls_arr.push_back(std::move(item));
        }

        const auto sequences = buildSequences();
        std::vector<std::string> high_risk_callers;
        nlohmann::json seq_arr = nlohmann::json::array();
        for (const auto &s : sequences) {
            max_risk_score = std::max(max_risk_score, s.caller_risk_score);
            max_entropy = std::max(max_entropy, s.max_arg_entropy);
            if (s.caller_risk_score >= 60) {
                high_risk_callers.push_back(s.caller_function);
            }

            seq_arr.push_back({
                {"caller", s.caller_function},
                {"chain", s.call_patterns},
                {"sequence_entropy", round4(s.sequence_entropy)},
                {"max_arg_entropy", round4(s.max_arg_entropy)},
                {"caller_risk_score", s.caller_risk_score},
                {"is_auto_init_entrypoint", s.is_auto_init_entrypoint},
                {"entrypoint_kind", s.entrypoint_kind},
                {"transitive_callees", s.transitive_callees},
                {"detected_chains", s.detected_chains},
            });
        }

        nlohmann::json root = {
            {"calls", std::move(calls_arr)},
            {"sequences", std::move(seq_arr)},
            {"summary",
             {
                 {"total_calls", records_.size()},
                 {"total_sequences", sequences.size()},
                 {"max_risk_score", max_risk_score},
                 {"max_entropy", round4(max_entropy)},
                 {"high_risk_callers", high_risk_callers},
             }},
        };
        return root.dump(2) + "\n";
    }

    bool CallPatternCollector::writeJsonFile(const std::string &path) const {
        std::ofstream out(path);
        if (!out.is_open()) {
            return false;
        }
        out << toJson();
        return out.good();
    }

} // namespace traceql
