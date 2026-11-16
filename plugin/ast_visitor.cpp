#include "tools/traceql/plugin/ast_visitor.h"
#include "../optimize/entropy_analyzer.h"
#include "tools/traceql/symbols/binary_symbol_parser.h"
#include "tools/traceql/symbols/remote_symbol_resolver.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <map>

#if CLANG_PLUGIN_AVAILABLE
#include "clang/AST/GlobalDecl.h"
#include "clang/Analysis/CFG.h"
#include "llvm/Support/raw_ostream.h"
#endif

#include <queue>

namespace traceql {

#if CLANG_PLUGIN_AVAILABLE

    namespace {

        bool isWordBoundaryChar(char ch) {
            return !std::isalnum(static_cast<unsigned char>(ch)) && ch != '_';
        }

        bool containsAsmMnemonic(std::string_view lower_asm, std::string_view mnemonic) {
            size_t pos = 0;
            while ((pos = lower_asm.find(mnemonic, pos)) != std::string_view::npos) {
                const bool left_ok = (pos == 0) || isWordBoundaryChar(lower_asm[pos - 1]);
                const size_t end = pos + mnemonic.size();
                const bool right_ok = (end == lower_asm.size()) || isWordBoundaryChar(lower_asm[end]);
                if (left_ok && right_ok) {
                    return true;
                }
                pos = end;
            }
            return false;
        }

        bool containsInt80(std::string_view lower_asm) {
            size_t pos = 0;
            while ((pos = lower_asm.find("int", pos)) != std::string_view::npos) {
                const bool left_ok = (pos == 0) || isWordBoundaryChar(lower_asm[pos - 1]);
                size_t cur = pos + 3;
                if (left_ok && cur < lower_asm.size() && std::isspace(static_cast<unsigned char>(lower_asm[cur]))) {
                    while (cur < lower_asm.size() && std::isspace(static_cast<unsigned char>(lower_asm[cur]))) {
                        ++cur;
                    }
                    if (cur < lower_asm.size() && lower_asm[cur] == '$') {
                        ++cur;
                    }
                    if (lower_asm.substr(cur, 4) == "0x80") {
                        const size_t end = cur + 4;
                        if (end == lower_asm.size() || isWordBoundaryChar(lower_asm[end])) {
                            return true;
                        }
                    }
                }
                pos += 3;
            }
            return false;
        }

        const char *classifyExplicitCastKind(const clang::CastExpr *CE) {
            if (llvm::isa<clang::CXXReinterpretCastExpr>(CE)) {
                return "reinterpret_cast";
            }
            if (llvm::isa<clang::CStyleCastExpr>(CE)) {
                return "c_style_cast";
            }
            if (llvm::isa<clang::CXXFunctionalCastExpr>(CE)) {
                return "functional_cast";
            }
            if (llvm::isa<clang::CXXStaticCastExpr>(CE)) {
                return "static_cast";
            }
            return "cast";
        }

        void collectOrComponents(const clang::Expr *expr, const clang::ASTContext &ctx, std::vector<uint64_t> &out,
                                 bool &is_or) {
            if (!expr)
                return;
            const clang::Expr *clean = expr->IgnoreParenImpCasts();
            if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(clean)) {
                if (BO->getOpcode() == clang::BO_Or) {
                    is_or = true;
                    collectOrComponents(BO->getLHS(), ctx, out, is_or);
                    collectOrComponents(BO->getRHS(), ctx, out, is_or);
                    return;
                }
            }
            if (!clean->isValueDependent() && !clean->isTypeDependent() && clean->getType()->isIntegerType()) {
                clang::Expr::EvalResult eval_res;
                if (clean->EvaluateAsInt(eval_res, ctx)) {
                    out.push_back(eval_res.Val.getInt().getZExtValue());
                }
            }
        }

        bool isInspectableBitmaskExpr(const clang::Expr *clean) {
            if (!clean || clean->isValueDependent() || clean->isTypeDependent()) {
                return false;
            }
            if (!clean->getType()->isIntegerType() || clean->getType()->isBooleanType()) {
                return false;
            }
            if (llvm::isa<clang::IntegerLiteral>(clean)) {
                return true;
            }
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(clean)) {
                return llvm::isa<clang::EnumConstantDecl>(DRE->getDecl());
            }
            if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(clean)) {
                return BO->getOpcode() == clang::BO_Or || BO->getOpcode() == clang::BO_Shl;
            }
            if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(clean)) {
                return UO->getOpcode() == clang::UO_Not;
            }
            return false;
        }

        bool isBufferOrPointerAccess(const clang::Expr *expr) {
            if (!expr)
                return false;
            const clang::Expr *clean = expr->IgnoreParenImpCasts();
            if (llvm::isa<clang::ArraySubscriptExpr>(clean)) {
                return true;
            }
            if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(clean)) {
                if (UO->getOpcode() == clang::UO_Deref) {
                    return true;
                }
            }
            if (const auto *OCE = llvm::dyn_cast<clang::CXXOperatorCallExpr>(clean)) {
                const auto op = OCE->getOperator();
                if (op == clang::OO_Subscript || op == clang::OO_Star) {
                    return true;
                }
            }
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(clean)) {
                const clang::QualType ty = DRE->getType();
                return ty->isPointerType() || ty->isArrayType();
            }
            return false;
        }

        class XorLoopDetector : public clang::RecursiveASTVisitor<XorLoopDetector> {
          public:
            explicit XorLoopDetector(const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr)
                : unreachable_(unreachable) {
            }

            bool found() const noexcept {
                return found_;
            }

            bool TraverseStmt(clang::Stmt *S) {
                if (!S || found_)
                    return !found_;
                if (unreachable_ && unreachable_->count(S))
                    return true;
                return clang::RecursiveASTVisitor<XorLoopDetector>::TraverseStmt(S);
            }

            bool TraverseLambdaExpr(clang::LambdaExpr *) {
                // Nested lambdas have their own FunctionDecl traversal.
                return true;
            }

            bool TraverseForStmt(clang::ForStmt *S) {
                if (!S || found_)
                    return !found_;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<XorLoopDetector>::TraverseForStmt(S);
                --loop_depth_;
                return ok && !found_;
            }

            bool TraverseWhileStmt(clang::WhileStmt *S) {
                if (!S || found_)
                    return !found_;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<XorLoopDetector>::TraverseWhileStmt(S);
                --loop_depth_;
                return ok && !found_;
            }

            bool TraverseDoStmt(clang::DoStmt *S) {
                if (!S || found_)
                    return !found_;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<XorLoopDetector>::TraverseDoStmt(S);
                --loop_depth_;
                return ok && !found_;
            }

            bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
                if (!S || found_)
                    return !found_;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<XorLoopDetector>::TraverseCXXForRangeStmt(S);
                --loop_depth_;
                return ok && !found_;
            }

            bool VisitBinaryOperator(clang::BinaryOperator *BO) {
                if (found_ || loop_depth_ == 0 || !BO)
                    return !found_;
                const auto op = BO->getOpcode();
                if (op == clang::BO_XorAssign) {
                    if (isBufferOrPointerAccess(BO->getLHS())) {
                        found_ = true;
                        return false;
                    }
                } else if (op == clang::BO_Xor) {
                    if (isBufferOrPointerAccess(BO->getLHS()) || isBufferOrPointerAccess(BO->getRHS())) {
                        found_ = true;
                        return false;
                    }
                }
                return true;
            }

          private:
            const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable_{nullptr};
            bool found_{false};
            unsigned loop_depth_{0};
        };

        bool containsBitwiseXorLoop(clang::Stmt *body,
                                    const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr) {
            if (!body)
                return false;
            XorLoopDetector detector(unreachable);
            detector.TraverseStmt(body);
            return detector.found();
        }

        void detectAutoInitEntrypoint(const clang::FunctionDecl *FD, bool &is_auto_init, std::string &entrypoint_kind) {
            is_auto_init = false;
            entrypoint_kind.clear();
            if (!FD)
                return;

            if (FD->hasAttr<clang::ConstructorAttr>()) {
                is_auto_init = true;
                entrypoint_kind = "constructor";
                return;
            }
            if (FD->hasAttr<clang::DestructorAttr>()) {
                is_auto_init = true;
                entrypoint_kind = "destructor";
                return;
            }
            if (const clang::IdentifierInfo *II = FD->getIdentifier()) {
                const llvm::StringRef name = II->getName();
                if (name == "DllMain") {
                    is_auto_init = true;
                    entrypoint_kind = "dllmain";
                    return;
                }
                if (name == "JNI_OnLoad") {
                    is_auto_init = true;
                    entrypoint_kind = "jni_onload";
                    return;
                }
            }
            if (const auto *SA = FD->getAttr<clang::SectionAttr>()) {
                const llvm::StringRef sec = SA->getName();
                if (sec.contains(".CRT$XL")) {
                    is_auto_init = true;
                    entrypoint_kind = "tls_callback";
                    return;
                }
                if (sec.contains(".init_array") || sec.contains(".preinit_array")) {
                    is_auto_init = true;
                    entrypoint_kind = "constructor";
                    return;
                }
            }
        }

        struct CryptoHashDetectionResult {
            bool has_constant{false};
            bool has_loop_pattern{false};
            std::vector<std::string> tags;
            clang::SourceLocation first_loc;
        };

        class CryptoHashLoopDetector : public clang::RecursiveASTVisitor<CryptoHashLoopDetector> {
          public:
            explicit CryptoHashLoopDetector(const clang::ASTContext &ctx,
                                            const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr)
                : ctx_(ctx), unreachable_(unreachable) {
            }

            bool TraverseStmt(clang::Stmt *S) {
                if (!S)
                    return true;
                if (unreachable_ && unreachable_->count(S))
                    return true;
                return clang::RecursiveASTVisitor<CryptoHashLoopDetector>::TraverseStmt(S);
            }

            bool TraverseLambdaExpr(clang::LambdaExpr *) {
                // Nested lambdas have their own FunctionDecl traversal.
                return true;
            }

            bool TraverseForStmt(clang::ForStmt *S) {
                if (!S)
                    return true;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<CryptoHashLoopDetector>::TraverseForStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseWhileStmt(clang::WhileStmt *S) {
                if (!S)
                    return true;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<CryptoHashLoopDetector>::TraverseWhileStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseDoStmt(clang::DoStmt *S) {
                if (!S)
                    return true;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<CryptoHashLoopDetector>::TraverseDoStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
                if (!S)
                    return true;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<CryptoHashLoopDetector>::TraverseCXXForRangeStmt(S);
                --loop_depth_;
                return ok;
            }

            bool VisitIntegerLiteral(clang::IntegerLiteral *IL) {
                if (!IL)
                    return true;
                const uint64_t val = IL->getValue().getLimitedValue();
                if (val == 0x811c9dc5ULL || val == 0x01000193ULL || val == 0xcbf29ce484222325ULL ||
                    val == 0x100000001b3ULL) {
                    addTag("fnv1a_hash", IL->getBeginLoc(), loop_depth_ > 0);
                } else if (val == 0xedb88320ULL || val == 0x04c11db7ULL) {
                    addTag("crc32_poly", IL->getBeginLoc(), loop_depth_ > 0);
                } else if (val == 0x61707865ULL || val == 0x3320646eULL || val == 0x79622d32ULL ||
                           val == 0x6b206574ULL) {
                    addTag("chacha20_const", IL->getBeginLoc(), loop_depth_ > 0);
                } else if (val == 5381ULL) {
                    saw_5381_ = true;
                    if (!djb2_loc_.isValid()) {
                        djb2_loc_ = IL->getBeginLoc();
                    }
                }
                return true;
            }

            bool VisitBinaryOperator(clang::BinaryOperator *BO) {
                if (!BO || loop_depth_ == 0)
                    return true;
                const auto op = BO->getOpcode();
                if (op == clang::BO_Shl) {
                    uint64_t rhs_val = 0;
                    if (evalConstInt(BO->getRHS(), rhs_val)) {
                        if (rhs_val == 5ULL) {
                            saw_djb2_step_in_loop_ = true;
                            if (!djb2_loc_.isValid())
                                djb2_loc_ = BO->getOperatorLoc();
                        } else if (rhs_val == 19ULL) {
                            saw_ror13_shl19_ = true;
                            if (!ror13_loc_.isValid())
                                ror13_loc_ = BO->getOperatorLoc();
                        }
                    }
                } else if (op == clang::BO_Shr) {
                    uint64_t rhs_val = 0;
                    if (evalConstInt(BO->getRHS(), rhs_val) && rhs_val == 13ULL) {
                        saw_ror13_shr13_ = true;
                        if (!ror13_loc_.isValid())
                            ror13_loc_ = BO->getOperatorLoc();
                    }
                } else if (op == clang::BO_Mul || op == clang::BO_MulAssign) {
                    uint64_t lhs_val = 0;
                    uint64_t rhs_val = 0;
                    if ((evalConstInt(BO->getRHS(), rhs_val) && rhs_val == 33ULL) ||
                        (op == clang::BO_Mul && evalConstInt(BO->getLHS(), lhs_val) && lhs_val == 33ULL)) {
                        saw_djb2_step_in_loop_ = true;
                        if (!djb2_loc_.isValid())
                            djb2_loc_ = BO->getOperatorLoc();
                    }
                }
                return true;
            }

            bool VisitInitListExpr(clang::InitListExpr *ILE) {
                if (!ILE || ILE->getNumInits() < 16)
                    return true;
                static constexpr std::array<uint64_t, 4> kAesSboxPrefix = {0x63, 0x7c, 0x77, 0x7b};
                for (unsigned i = 0; i < 4; ++i) {
                    uint64_t b = 0;
                    if (!evalConstInt(ILE->getInit(i), b) || b != kAesSboxPrefix[i]) {
                        return true;
                    }
                }
                addTag("aes_sbox", ILE->getBeginLoc(), loop_depth_ > 0);
                return true;
            }

            CryptoHashDetectionResult finalize() {
                if (saw_5381_ && saw_djb2_step_in_loop_) {
                    addTag("djb2_hash", djb2_loc_, true);
                }
                if (saw_ror13_shr13_ && saw_ror13_shl19_) {
                    addTag("ror13_hash", ror13_loc_, true);
                }
                return std::move(result_);
            }

          private:
            bool evalConstInt(const clang::Expr *expr, uint64_t &out) const {
                if (!expr)
                    return false;
                const clang::Expr *clean = expr->IgnoreParenImpCasts();
                if (clean->isValueDependent() || clean->isTypeDependent() || !clean->getType()->isIntegerType()) {
                    return false;
                }
                clang::Expr::EvalResult eval_res;
                if (!clean->EvaluateAsInt(eval_res, ctx_)) {
                    return false;
                }
                out = eval_res.Val.getInt().getZExtValue();
                return true;
            }

            void addTag(std::string_view tag, clang::SourceLocation loc, bool in_loop) {
                result_.has_constant = true;
                if (in_loop) {
                    result_.has_loop_pattern = true;
                }
                if (!result_.first_loc.isValid() && loc.isValid()) {
                    result_.first_loc = loc;
                }
                if (std::find(result_.tags.begin(), result_.tags.end(), tag) == result_.tags.end()) {
                    result_.tags.emplace_back(tag);
                }
            }

            const clang::ASTContext &ctx_;
            const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable_{nullptr};
            unsigned loop_depth_{0};
            bool saw_5381_{false};
            bool saw_djb2_step_in_loop_{false};
            bool saw_ror13_shr13_{false};
            bool saw_ror13_shl19_{false};
            clang::SourceLocation djb2_loc_;
            clang::SourceLocation ror13_loc_;
            CryptoHashDetectionResult result_;
        };

        CryptoHashDetectionResult
        detectCryptoAndHashConstants(const clang::ASTContext &ctx, clang::Stmt *body,
                                     const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr) {
            if (!body)
                return {};
            CryptoHashLoopDetector detector(ctx, unreachable);
            detector.TraverseStmt(body);
            return detector.finalize();
        }

        const clang::VarDecl *extractVarDeclFromExpr(const clang::Expr *expr) {
            if (!expr)
                return nullptr;
            const clang::Expr *clean = expr->IgnoreParenCasts();
            if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(clean)) {
                if (UO->getOpcode() == clang::UO_AddrOf || UO->getOpcode() == clang::UO_Deref) {
                    clean = UO->getSubExpr()->IgnoreParenCasts();
                }
            }
            if (const auto *ASE = llvm::dyn_cast<clang::ArraySubscriptExpr>(clean)) {
                clean = ASE->getBase()->IgnoreParenCasts();
            }
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(clean)) {
                return llvm::dyn_cast_or_null<clang::VarDecl>(DRE->getDecl());
            }
            return nullptr;
        }

        const clang::Expr *stripTaintExpr(const clang::Expr *expr) {
            while (expr) {
                expr = expr->IgnoreParenCasts();
                if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(expr)) {
                    if (UO->getOpcode() == clang::UO_Deref || UO->getOpcode() == clang::UO_AddrOf) {
                        expr = UO->getSubExpr();
                        continue;
                    }
                }
                break;
            }
            return expr;
        }

        std::string extractExprTaintKey(const clang::Expr *expr) {
            const clang::Expr *clean = stripTaintExpr(expr);
            if (!clean)
                return {};
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(clean)) {
                if (const auto *VD = llvm::dyn_cast_or_null<clang::VarDecl>(DRE->getDecl())) {
                    return VD->getNameAsString();
                }
                return {};
            }
            if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(clean)) {
                const clang::ValueDecl *member_decl = ME->getMemberDecl();
                if (!member_decl)
                    return {};
                const std::string member_name = member_decl->getNameAsString();
                if (member_name.empty())
                    return {};
                const clang::Expr *base = stripTaintExpr(ME->getBase());
                if (llvm::isa_and_nonnull<clang::CXXThisExpr>(base)) {
                    if (const auto *RD = llvm::dyn_cast_or_null<clang::RecordDecl>(member_decl->getDeclContext())) {
                        const std::string rec_name = RD->getNameAsString();
                        if (!rec_name.empty()) {
                            return rec_name + "::" + member_name;
                        }
                    }
                    return "this." + member_name;
                }
                const std::string base_key = extractExprTaintKey(ME->getBase());
                if (!base_key.empty()) {
                    return base_key + "." + member_name;
                }
                return {};
            }
            if (const auto *ASE = llvm::dyn_cast<clang::ArraySubscriptExpr>(clean)) {
                const std::string base_key = extractExprTaintKey(ASE->getBase());
                if (!base_key.empty()) {
                    return base_key + "[]";
                }
                return {};
            }
            return {};
        }

        bool extractPrintableAsciiOrNull(const clang::Expr *expr, char &out_ch, bool &is_null) {
            is_null = false;
            if (!expr)
                return false;
            const clang::Expr *clean = expr->IgnoreParenImpCasts();
            if (const auto *CL = llvm::dyn_cast<clang::CharacterLiteral>(clean)) {
                const unsigned val = CL->getValue();
                if (val == 0) {
                    is_null = true;
                    out_ch = '\0';
                    return true;
                }
                if (val >= 0x20 && val <= 0x7e) {
                    out_ch = static_cast<char>(val);
                    return true;
                }
                return false;
            }
            if (const auto *IL = llvm::dyn_cast<clang::IntegerLiteral>(clean)) {
                const llvm::APInt &ap = IL->getValue();
                if (ap.getBitWidth() <= 64) {
                    const uint64_t val = ap.getZExtValue();
                    if (val == 0) {
                        is_null = true;
                        out_ch = '\0';
                        return true;
                    }
                    if (val >= 0x20 && val <= 0x7e) {
                        out_ch = static_cast<char>(val);
                        return true;
                    }
                }
            }
            return false;
        }

        struct StackStringEntry {
            const clang::VarDecl *var{nullptr};
            std::string value;
            clang::SourceLocation loc;
        };

        class StackStringDetector : public clang::RecursiveASTVisitor<StackStringDetector> {
          public:
            explicit StackStringDetector(const clang::ASTContext &ctx,
                                         const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr)
                : ctx_(ctx), unreachable_(unreachable) {
            }

            bool TraverseStmt(clang::Stmt *S) {
                if (!S)
                    return true;
                if (unreachable_ && unreachable_->count(S))
                    return true;
                return clang::RecursiveASTVisitor<StackStringDetector>::TraverseStmt(S);
            }

            bool TraverseLambdaExpr(clang::LambdaExpr *) {
                return true;
            }
            bool TraverseFunctionDecl(clang::FunctionDecl *) {
                return true;
            }

            bool VisitVarDecl(clang::VarDecl *VD) {
                if (!VD || !VD->hasInit())
                    return true;
                const clang::Expr *init = VD->getInit()->IgnoreParenImpCasts();
                const auto *ILE = llvm::dyn_cast<clang::InitListExpr>(init);
                if (!ILE || ILE->getNumInits() < 6)
                    return true;

                std::string reconstructed;
                reconstructed.reserve(ILE->getNumInits());
                bool saw_null = false;
                for (unsigned i = 0; i < ILE->getNumInits(); ++i) {
                    char ch = '\0';
                    bool is_null = false;
                    if (!extractPrintableAsciiOrNull(ILE->getInit(i), ch, is_null)) {
                        return true;
                    }
                    if (is_null) {
                        saw_null = true;
                        continue;
                    }
                    if (saw_null) {
                        return true;
                    }
                    reconstructed.push_back(ch);
                }
                if (reconstructed.size() >= 6) {
                    results_.push_back(StackStringEntry{VD, std::move(reconstructed), VD->getLocation()});
                }
                return true;
            }

            bool VisitBinaryOperator(clang::BinaryOperator *BO) {
                if (!BO || BO->getOpcode() != clang::BO_Assign)
                    return true;
                const auto *ASE = llvm::dyn_cast<clang::ArraySubscriptExpr>(BO->getLHS()->IgnoreParenImpCasts());
                if (!ASE)
                    return true;
                const clang::VarDecl *base_vd = extractVarDeclFromExpr(ASE->getBase());
                if (!base_vd)
                    return true;

                const clang::Expr *idx_expr = ASE->getIdx()->IgnoreParenImpCasts();
                if (idx_expr->isValueDependent() || idx_expr->isTypeDependent() ||
                    !idx_expr->getType()->isIntegerType()) {
                    return true;
                }
                clang::Expr::EvalResult eval_res;
                if (!idx_expr->EvaluateAsInt(eval_res, ctx_)) {
                    return true;
                }
                const uint64_t idx = eval_res.Val.getInt().getZExtValue();

                char ch = '\0';
                bool is_null = false;
                if (!extractPrintableAsciiOrNull(BO->getRHS(), ch, is_null)) {
                    return true;
                }
                auto &entry = subscript_chars_[base_vd];
                if (!entry.first_loc.isValid()) {
                    entry.first_loc = BO->getOperatorLoc();
                }
                entry.chars[idx] = is_null ? '\0' : ch;
                return true;
            }

            std::vector<StackStringEntry> finalize() {
                for (const auto &[vd, data] : subscript_chars_) {
                    std::string current;
                    uint64_t expected_idx = 0;
                    bool active = false;
                    for (const auto &[idx, ch] : data.chars) {
                        if (ch == '\0') {
                            if (active && current.size() >= 6) {
                                results_.push_back(StackStringEntry{vd, current, data.first_loc});
                            }
                            current.clear();
                            active = false;
                            continue;
                        }
                        if (!active || idx != expected_idx) {
                            if (active && current.size() >= 6) {
                                results_.push_back(StackStringEntry{vd, current, data.first_loc});
                            }
                            current.clear();
                            current.push_back(ch);
                            expected_idx = idx + 1;
                            active = true;
                        } else {
                            current.push_back(ch);
                            expected_idx = idx + 1;
                        }
                    }
                    if (active && current.size() >= 6) {
                        results_.push_back(StackStringEntry{vd, std::move(current), data.first_loc});
                    }
                }
                return std::move(results_);
            }

          private:
            struct SubscriptBuffer {
                clang::SourceLocation first_loc;
                std::map<uint64_t, char> chars;
            };

            const clang::ASTContext &ctx_;
            const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable_{nullptr};
            std::map<const clang::VarDecl *, SubscriptBuffer> subscript_chars_;
            std::vector<StackStringEntry> results_;
        };

        std::vector<StackStringEntry>
        detectStackStringsInBody(const clang::ASTContext &ctx, clang::Stmt *body,
                                 const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr) {
            if (!body)
                return {};
            StackStringDetector detector(ctx, unreachable);
            detector.TraverseStmt(body);
            return detector.finalize();
        }

        bool isPrintableXorDecodedString(std::string_view text) {
            if (text.size() < 4)
                return false;
            for (const char c : text) {
                const unsigned char uc = static_cast<unsigned char>(c);
                const bool ok = (uc >= 0x20 && uc <= 0x7e) || c == '\t' || c == '\n' || c == '\r';
                if (!ok)
                    return false;
            }
            return true;
        }

        bool containsInlineXorOp(const clang::Expr *expr) {
            if (!expr)
                return false;
            const clang::Expr *clean = expr->IgnoreParenCasts();
            if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(clean)) {
                if (BO->getOpcode() == clang::BO_Xor) {
                    return true;
                }
                return containsInlineXorOp(BO->getLHS()) || containsInlineXorOp(BO->getRHS());
            }
            return false;
        }

        class StaticXorStringDeobfuscator : public clang::RecursiveASTVisitor<StaticXorStringDeobfuscator> {
          public:
            explicit StaticXorStringDeobfuscator(
                const clang::ASTContext &ctx, const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr)
                : ctx_(ctx), unreachable_(unreachable) {
            }

            bool TraverseStmt(clang::Stmt *S) {
                if (!S)
                    return true;
                if (unreachable_ && unreachable_->count(S))
                    return true;
                return clang::RecursiveASTVisitor<StaticXorStringDeobfuscator>::TraverseStmt(S);
            }

            bool TraverseLambdaExpr(clang::LambdaExpr *) {
                return true;
            }
            bool TraverseFunctionDecl(clang::FunctionDecl *) {
                return true;
            }

            bool TraverseForStmt(clang::ForStmt *S) {
                if (!S)
                    return true;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<StaticXorStringDeobfuscator>::TraverseForStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseWhileStmt(clang::WhileStmt *S) {
                if (!S)
                    return true;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<StaticXorStringDeobfuscator>::TraverseWhileStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseDoStmt(clang::DoStmt *S) {
                if (!S)
                    return true;
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<StaticXorStringDeobfuscator>::TraverseDoStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
                if (!S)
                    return true;
                const clang::VarDecl *loop_vd = S->getLoopVariable();
                const clang::VarDecl *range_vd = extractVarDeclFromExpr(S->getRangeInit());
                const bool pushed = (loop_vd && range_vd);
                if (pushed) {
                    range_bindings_.emplace_back(loop_vd, range_vd);
                }
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<StaticXorStringDeobfuscator>::TraverseCXXForRangeStmt(S);
                --loop_depth_;
                if (pushed) {
                    range_bindings_.pop_back();
                }
                return ok;
            }

            bool VisitVarDecl(clang::VarDecl *VD) {
                if (!VD || !VD->hasInit())
                    return true;
                const clang::Expr *init = VD->getInit()->IgnoreParenImpCasts();

                if (const auto *SL = llvm::dyn_cast<clang::StringLiteral>(init)) {
                    if (SL->isOrdinary() || SL->isUTF8()) {
                        const llvm::StringRef bytes = SL->getBytes();
                        if (bytes.size() >= 4) {
                            EncodedArrayData data;
                            data.loc = VD->getLocation();
                            data.bytes.reserve(bytes.size());
                            for (char ch : bytes) {
                                data.bytes.push_back(static_cast<uint8_t>(ch));
                            }
                            encoded_arrays_[VD] = std::move(data);
                        }
                    }
                    return true;
                }

                if (const auto *ILE = llvm::dyn_cast<clang::InitListExpr>(init)) {
                    if (ILE->getNumInits() < 4)
                        return true;
                    std::vector<uint8_t> bytes;
                    bytes.reserve(ILE->getNumInits());
                    bool has_inline_xor = false;
                    for (const clang::Expr *elem : ILE->inits()) {
                        if (!elem)
                            return true;
                        if (containsInlineXorOp(elem)) {
                            has_inline_xor = true;
                        }
                        const clang::Expr *clean = elem->IgnoreParenImpCasts();
                        if (clean->isValueDependent() || clean->isTypeDependent() ||
                            !clean->getType()->isIntegerType()) {
                            return true;
                        }
                        clang::Expr::EvalResult eval_res;
                        if (!clean->EvaluateAsInt(eval_res, ctx_)) {
                            return true;
                        }
                        const int64_t sval = eval_res.Val.getInt().getSExtValue();
                        if (sval < -128 || sval > 255) {
                            return true;
                        }
                        bytes.push_back(static_cast<uint8_t>(sval & 0xFF));
                    }

                    if (has_inline_xor) {
                        std::string decoded;
                        for (const uint8_t b : bytes) {
                            if (b == 0)
                                break;
                            decoded.push_back(static_cast<char>(b));
                        }
                        if (isPrintableXorDecodedString(decoded)) {
                            results_.push_back(StackStringEntry{VD, std::move(decoded), VD->getLocation()});
                        }
                    } else {
                        encoded_arrays_[VD] = EncodedArrayData{VD->getLocation(), std::move(bytes)};
                    }
                }
                return true;
            }

            bool VisitBinaryOperator(clang::BinaryOperator *BO) {
                if (!BO || loop_depth_ == 0)
                    return true;
                const auto op = BO->getOpcode();
                if (op == clang::BO_XorAssign) {
                    const clang::VarDecl *target = resolveTargetVar(BO->getLHS());
                    uint8_t key = 0;
                    if (target && evalConstByteKey(BO->getRHS(), key)) {
                        xor_ops_.push_back(XorOp{target, target, key, BO->getOperatorLoc()});
                    }
                } else if (op == clang::BO_Assign) {
                    const clang::VarDecl *dst = resolveTargetVar(BO->getLHS());
                    if (const auto *xor_bo =
                            llvm::dyn_cast<clang::BinaryOperator>(BO->getRHS()->IgnoreParenImpCasts())) {
                        if (xor_bo->getOpcode() == clang::BO_Xor) {
                            uint8_t key = 0;
                            const clang::VarDecl *src = nullptr;
                            if (evalConstByteKey(xor_bo->getRHS(), key)) {
                                src = resolveTargetVar(xor_bo->getLHS());
                            } else if (evalConstByteKey(xor_bo->getLHS(), key)) {
                                src = resolveTargetVar(xor_bo->getRHS());
                            }
                            if (src) {
                                xor_ops_.push_back(XorOp{src, dst ? dst : src, key, BO->getOperatorLoc()});
                            }
                        }
                    }
                }
                return true;
            }

            std::vector<StackStringEntry> finalize() {
                for (const auto &op : xor_ops_) {
                    const auto it = encoded_arrays_.find(op.src);
                    if (it == encoded_arrays_.end())
                        continue;
                    std::string decoded;
                    decoded.reserve(it->second.bytes.size());
                    for (const uint8_t b : it->second.bytes) {
                        const uint8_t dec = static_cast<uint8_t>(b ^ op.key);
                        if (dec == 0)
                            break;
                        decoded.push_back(static_cast<char>(dec));
                    }
                    if (!isPrintableXorDecodedString(decoded))
                        continue;
                    const clang::SourceLocation emit_loc = op.loc.isValid() ? op.loc : it->second.loc;
                    results_.push_back(StackStringEntry{op.src, decoded, emit_loc});
                    if (op.dst && op.dst != op.src) {
                        results_.push_back(StackStringEntry{op.dst, std::move(decoded), emit_loc});
                    }
                }
                return std::move(results_);
            }

          private:
            struct EncodedArrayData {
                clang::SourceLocation loc;
                std::vector<uint8_t> bytes;
            };

            struct XorOp {
                const clang::VarDecl *src{nullptr};
                const clang::VarDecl *dst{nullptr};
                uint8_t key{0};
                clang::SourceLocation loc;
            };

            const clang::VarDecl *resolveTargetVar(const clang::Expr *expr) const {
                const clang::VarDecl *vd = extractVarDeclFromExpr(expr);
                if (!vd)
                    return nullptr;
                for (auto it = range_bindings_.rbegin(); it != range_bindings_.rend(); ++it) {
                    if (it->first == vd) {
                        return it->second;
                    }
                }
                return vd;
            }

            bool evalConstByteKey(const clang::Expr *expr, uint8_t &out_key) const {
                if (!expr)
                    return false;
                const clang::Expr *clean = expr->IgnoreParenImpCasts();
                if (clean->isValueDependent() || clean->isTypeDependent() || !clean->getType()->isIntegerType()) {
                    return false;
                }
                clang::Expr::EvalResult eval_res;
                if (!clean->EvaluateAsInt(eval_res, ctx_)) {
                    return false;
                }
                const uint64_t val = eval_res.Val.getInt().getZExtValue();
                const uint8_t key = static_cast<uint8_t>(val & 0xFF);
                if (key == 0)
                    return false;
                out_key = key;
                return true;
            }

            const clang::ASTContext &ctx_;
            const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable_{nullptr};
            unsigned loop_depth_{0};
            std::vector<std::pair<const clang::VarDecl *, const clang::VarDecl *>> range_bindings_;
            std::map<const clang::VarDecl *, EncodedArrayData> encoded_arrays_;
            std::vector<XorOp> xor_ops_;
            std::vector<StackStringEntry> results_;
        };

        std::vector<StackStringEntry>
        detectXorDecodedStringsInBody(const clang::ASTContext &ctx, clang::Stmt *body,
                                      const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr) {
            if (!body)
                return {};
            StaticXorStringDeobfuscator deobf(ctx, unreachable);
            deobf.TraverseStmt(body);
            return deobf.finalize();
        }

        class StateVarMutationChecker : public clang::RecursiveASTVisitor<StateVarMutationChecker> {
          public:
            explicit StateVarMutationChecker(const clang::VarDecl *target) : target_(target) {
            }

            bool TraverseSwitchStmt(clang::SwitchStmt *) {
                return true;
            }
            bool TraverseLambdaExpr(clang::LambdaExpr *) {
                return true;
            }
            bool TraverseFunctionDecl(clang::FunctionDecl *) {
                return true;
            }

            bool VisitBinaryOperator(clang::BinaryOperator *BO) {
                if (BO && BO->isAssignmentOp()) {
                    if (extractVarDeclFromExpr(BO->getLHS()) == target_) {
                        mutated_ = true;
                    }
                }
                return true;
            }

            bool VisitUnaryOperator(clang::UnaryOperator *UO) {
                if (UO && UO->isIncrementDecrementOp()) {
                    if (extractVarDeclFromExpr(UO->getSubExpr()) == target_) {
                        mutated_ = true;
                    }
                }
                return true;
            }

            [[nodiscard]] bool mutated() const noexcept {
                return mutated_;
            }

          private:
            const clang::VarDecl *target_;
            bool mutated_{false};
        };

        bool stmtMutatesVar(clang::Stmt *S, const clang::VarDecl *target) {
            if (!S || !target)
                return false;
            StateVarMutationChecker checker(target);
            checker.TraverseStmt(S);
            return checker.mutated();
        }

        class CffDispatcherDetector : public clang::RecursiveASTVisitor<CffDispatcherDetector> {
          public:
            explicit CffDispatcherDetector(const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr)
                : unreachable_(unreachable) {
            }

            bool TraverseStmt(clang::Stmt *S) {
                if (!S || detected_)
                    return !detected_;
                if (unreachable_ && unreachable_->count(S))
                    return true;
                return clang::RecursiveASTVisitor<CffDispatcherDetector>::TraverseStmt(S);
            }

            bool TraverseLambdaExpr(clang::LambdaExpr *) {
                return true;
            }
            bool TraverseFunctionDecl(clang::FunctionDecl *) {
                return true;
            }

            bool TraverseWhileStmt(clang::WhileStmt *S) {
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<CffDispatcherDetector>::TraverseWhileStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseForStmt(clang::ForStmt *S) {
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<CffDispatcherDetector>::TraverseForStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseDoStmt(clang::DoStmt *S) {
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<CffDispatcherDetector>::TraverseDoStmt(S);
                --loop_depth_;
                return ok;
            }

            bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
                ++loop_depth_;
                const bool ok = clang::RecursiveASTVisitor<CffDispatcherDetector>::TraverseCXXForRangeStmt(S);
                --loop_depth_;
                return ok;
            }

            bool VisitSwitchStmt(clang::SwitchStmt *SS) {
                if (detected_ || !SS || loop_depth_ == 0)
                    return true;
                const clang::VarDecl *state_var = extractVarDeclFromExpr(SS->getCond());
                if (!state_var)
                    return true;

                llvm::SmallPtrSet<const clang::CaseStmt *, 8> mutating_cases;
                if (auto *body_cs = llvm::dyn_cast_or_null<clang::CompoundStmt>(SS->getBody())) {
                    const clang::CaseStmt *current_case = nullptr;
                    for (clang::Stmt *stmt : body_cs->body()) {
                        if (!stmt)
                            continue;
                        if (auto *CS = llvm::dyn_cast<clang::CaseStmt>(stmt)) {
                            clang::Stmt *sub = CS;
                            while (auto *inner_cs = llvm::dyn_cast_or_null<clang::CaseStmt>(sub)) {
                                current_case = inner_cs;
                                sub = inner_cs->getSubStmt();
                            }
                            if (current_case && stmtMutatesVar(sub, state_var)) {
                                mutating_cases.insert(current_case);
                            }
                        } else if (llvm::isa<clang::DefaultStmt>(stmt)) {
                            current_case = nullptr;
                        } else {
                            if (current_case && stmtMutatesVar(stmt, state_var)) {
                                mutating_cases.insert(current_case);
                            }
                            if (llvm::isa<clang::BreakStmt>(stmt) || llvm::isa<clang::ReturnStmt>(stmt)) {
                                current_case = nullptr;
                            }
                        }
                    }
                }

                if (mutating_cases.size() >= 3) {
                    detected_ = true;
                    switch_loc_ = SS->getSwitchLoc();
                }
                return true;
            }

            [[nodiscard]] bool detected() const noexcept {
                return detected_;
            }
            [[nodiscard]] clang::SourceLocation switch_loc() const noexcept {
                return switch_loc_;
            }

          private:
            const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable_{nullptr};
            unsigned loop_depth_{0};
            bool detected_{false};
            clang::SourceLocation switch_loc_;
        };

        bool detectCffDispatcher(clang::Stmt *body, clang::SourceLocation &out_loc,
                                 const llvm::SmallPtrSet<const clang::Stmt *, 32> *unreachable = nullptr) {
            if (!body)
                return false;
            CffDispatcherDetector detector(unreachable);
            detector.TraverseStmt(body);
            out_loc = detector.switch_loc();
            return detector.detected();
        }

        const clang::Expr *extractBranchCondition(const clang::Stmt *term) {
            if (!term)
                return nullptr;
            if (const auto *IS = llvm::dyn_cast<clang::IfStmt>(term)) {
                return IS->getCond();
            }
            if (const auto *WS = llvm::dyn_cast<clang::WhileStmt>(term)) {
                return WS->getCond();
            }
            if (const auto *FS = llvm::dyn_cast<clang::ForStmt>(term)) {
                return FS->getCond();
            }
            if (const auto *DS = llvm::dyn_cast<clang::DoStmt>(term)) {
                return DS->getCond();
            }
            if (const auto *CO = llvm::dyn_cast<clang::ConditionalOperator>(term)) {
                return CO->getCond();
            }
            return nullptr;
        }

        void computeUnreachableStmts(clang::FunctionDecl *FD, clang::ASTContext &ctx,
                                     llvm::SmallPtrSet<const clang::Stmt *, 32> &out_unreachable) {
            out_unreachable.clear();
            if (!FD || !FD->hasBody() || FD->isImplicit() || FD->isTemplated())
                return;

            clang::CFG::BuildOptions opts;
            opts.PruneTriviallyFalseEdges = true;
            std::unique_ptr<clang::CFG> cfg = clang::CFG::buildCFG(FD, FD->getBody(), &ctx, opts);
            if (!cfg)
                return;

            llvm::SmallPtrSet<const clang::CFGBlock *, 32> reachable_blocks;
            std::queue<const clang::CFGBlock *> worklist;
            const clang::CFGBlock *entry = &cfg->getEntry();
            reachable_blocks.insert(entry);
            worklist.push(entry);

            while (!worklist.empty()) {
                const clang::CFGBlock *block = worklist.front();
                worklist.pop();
                if (!block)
                    continue;

                const clang::Expr *cond = extractBranchCondition(block->getTerminatorStmt());
                if (cond && !cond->isValueDependent() && !cond->isTypeDependent() && block->succ_size() == 2) {
                    bool cond_val = false;
                    if (cond->EvaluateAsBooleanCondition(cond_val, ctx)) {
                        auto it = block->succ_begin();
                        const clang::CFGBlock *chosen =
                            cond_val ? it[0].getReachableBlock() : it[1].getReachableBlock();
                        if (chosen && reachable_blocks.insert(chosen).second) {
                            worklist.push(chosen);
                        }
                        continue;
                    }
                }

                for (const auto &succ : block->succs()) {
                    const clang::CFGBlock *succ_block = succ.getReachableBlock();
                    if (succ_block && reachable_blocks.insert(succ_block).second) {
                        worklist.push(succ_block);
                    }
                }
            }

            llvm::SmallPtrSet<const clang::Stmt *, 32> reachable_stmts;
            for (const clang::CFGBlock *block : reachable_blocks) {
                if (!block)
                    continue;
                if (const clang::Stmt *term = block->getTerminatorStmt()) {
                    reachable_stmts.insert(term);
                }
                for (const clang::CFGElement &elem : *block) {
                    if (const auto cs = elem.getAs<clang::CFGStmt>()) {
                        if (cs->getStmt()) {
                            reachable_stmts.insert(cs->getStmt());
                        }
                    }
                }
            }

            for (const clang::CFGBlock *block : *cfg) {
                if (!block || reachable_blocks.count(block))
                    continue;
                for (const clang::CFGElement &elem : *block) {
                    if (const auto cs = elem.getAs<clang::CFGStmt>()) {
                        if (const clang::Stmt *S = cs->getStmt()) {
                            if (!reachable_stmts.count(S)) {
                                out_unreachable.insert(S);
                            }
                        }
                    }
                }
            }
        }

        class VirtualOverrideCollector : public clang::RecursiveASTVisitor<VirtualOverrideCollector> {
          public:
            using OverrideMap = llvm::DenseMap<const clang::CXXMethodDecl *, std::vector<const clang::CXXMethodDecl *>>;

            explicit VirtualOverrideCollector(const clang::SourceManager &sm, OverrideMap &out) : sm_(sm), out_(out) {
            }

            bool VisitCXXMethodDecl(clang::CXXMethodDecl *MD) {
                if (!MD || !MD->isVirtual() || MD->isPureVirtual() || !MD->hasBody()) {
                    return true;
                }
                if (!MD->getLocation().isValid() || sm_.isInSystemHeader(MD->getLocation())) {
                    return true;
                }
                const clang::CXXMethodDecl *canon_derived = MD->getCanonicalDecl();
                for (const clang::CXXMethodDecl *base_md : MD->overridden_methods()) {
                    if (!base_md)
                        continue;
                    const clang::CXXMethodDecl *canon_base = base_md->getCanonicalDecl();
                    auto &vec = out_[canon_base];
                    if (std::find(vec.begin(), vec.end(), canon_derived) == vec.end()) {
                        vec.push_back(canon_derived);
                    }
                }
                return true;
            }

          private:
            const clang::SourceManager &sm_;
            OverrideMap &out_;
        };

        template <typename T>
        void setLockFieldsIfPresent(T &rec, const std::string &lock_name, const std::string &prev_lock) {
            if constexpr (requires { rec.lock_name; }) {
                rec.lock_name = lock_name;
            }
            if constexpr (requires { rec.lock_held_prev; }) {
                rec.lock_held_prev = prev_lock;
            }
        }

        template <typename T> void setLifetimeFieldIfPresent(T &rec, std::string_view lifetime_kind) {
            if constexpr (requires { rec.lifetime_kind; }) {
                rec.lifetime_kind = std::string(lifetime_kind);
            }
        }

        bool isLocalNonStaticVar(const clang::VarDecl *VD) {
            return VD && VD->hasLocalStorage() && !VD->isStaticLocal() && !llvm::isa<clang::ParmVarDecl>(VD);
        }

        bool isRaiiLockGuardType(clang::QualType qt) {
            if (qt.isNull())
                return false;
            const clang::QualType canon = qt.getCanonicalType().getUnqualifiedType();
            const clang::CXXRecordDecl *RD = canon->getAsCXXRecordDecl();
            if (!RD || !RD->isInStdNamespace())
                return false;
            const llvm::StringRef name = RD->getName();
            return name == "lock_guard" || name == "unique_lock" || name == "scoped_lock" || name == "shared_lock";
        }

        std::string extractLockExprName(const clang::Expr *expr) {
            if (!expr)
                return {};
            const clang::Expr *clean = expr->IgnoreParenImpCasts();
            for (unsigned depth = 0; depth < 8 && clean; ++depth) {
                if (const auto *BTE = llvm::dyn_cast<clang::CXXBindTemporaryExpr>(clean)) {
                    clean = BTE->getSubExpr()->IgnoreParenImpCasts();
                    continue;
                }
                if (const auto *MTE = llvm::dyn_cast<clang::MaterializeTemporaryExpr>(clean)) {
                    clean = MTE->getSubExpr()->IgnoreParenImpCasts();
                    continue;
                }
                if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(clean)) {
                    if (UO->getOpcode() == clang::UO_AddrOf || UO->getOpcode() == clang::UO_Deref) {
                        clean = UO->getSubExpr()->IgnoreParenImpCasts();
                        continue;
                    }
                }
                break;
            }
            if (!clean)
                return {};
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(clean)) {
                if (const clang::ValueDecl *VD = DRE->getDecl()) {
                    return VD->getNameAsString();
                }
                return {};
            }
            if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(clean)) {
                const clang::ValueDecl *MD = ME->getMemberDecl();
                if (!MD)
                    return {};
                const std::string member_name = MD->getNameAsString();
                if (member_name.empty())
                    return {};
                const clang::Expr *base = ME->getBase() ? ME->getBase()->IgnoreParenImpCasts() : nullptr;
                if (llvm::isa_and_nonnull<clang::CXXThisExpr>(base)) {
                    return "this->" + member_name;
                }
                const std::string base_name = extractLockExprName(base);
                if (!base_name.empty()) {
                    return base_name + (ME->isArrow() ? "->" : ".") + member_name;
                }
                return member_name;
            }
            if (const auto *ASE = llvm::dyn_cast<clang::ArraySubscriptExpr>(clean)) {
                const std::string base_name = extractLockExprName(ASE->getBase());
                if (!base_name.empty()) {
                    return base_name + "[...]";
                }
            }
            return {};
        }

        bool isStringViewOrSpanType(clang::QualType qt) {
            if (qt.isNull())
                return false;
            const clang::QualType canon = qt.getCanonicalType().getUnqualifiedType();
            const clang::CXXRecordDecl *RD = canon->getAsCXXRecordDecl();
            if (!RD || !RD->isInStdNamespace())
                return false;
            const llvm::StringRef name = RD->getName();
            return name == "basic_string_view" || name == "span";
        }

        bool isOwningContainerType(clang::QualType qt) {
            if (qt.isNull())
                return false;
            const clang::QualType canon = qt.getCanonicalType().getUnqualifiedType();
            const clang::CXXRecordDecl *RD = canon->getAsCXXRecordDecl();
            if (!RD || !RD->isInStdNamespace())
                return false;
            const llvm::StringRef name = RD->getName();
            return name == "basic_string" || name == "vector" || name == "array";
        }

        const clang::VarDecl *findDanglingLocalVar(const clang::Expr *expr, clang::QualType ret_type) {
            if (!expr || ret_type.isNull())
                return nullptr;
            const clang::QualType ret_canon = ret_type.getCanonicalType().getUnqualifiedType();
            const bool is_ptr = ret_canon->isPointerType();
            const bool is_ref = ret_canon->isReferenceType();
            const bool is_view = isStringViewOrSpanType(ret_canon);
            if (!is_ptr && !is_ref && !is_view)
                return nullptr;

            bool saw_addr_of = false;
            bool saw_container_data_call = false;
            const clang::Expr *cur = expr;

            for (unsigned depth = 0; depth < 16 && cur; ++depth) {
                cur = cur->IgnoreParenImpCasts();
                if (const auto *EWC = llvm::dyn_cast<clang::ExprWithCleanups>(cur)) {
                    cur = EWC->getSubExpr();
                    continue;
                }
                if (const auto *MTE = llvm::dyn_cast<clang::MaterializeTemporaryExpr>(cur)) {
                    cur = MTE->getSubExpr();
                    continue;
                }
                if (const auto *BTE = llvm::dyn_cast<clang::CXXBindTemporaryExpr>(cur)) {
                    cur = BTE->getSubExpr();
                    continue;
                }
                if (const auto *CE = llvm::dyn_cast<clang::CastExpr>(cur)) {
                    cur = CE->getSubExpr();
                    continue;
                }
                if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(cur)) {
                    if (UO->getOpcode() == clang::UO_AddrOf) {
                        saw_addr_of = true;
                        cur = UO->getSubExpr();
                        continue;
                    }
                    break;
                }
                if (const auto *CCE = llvm::dyn_cast<clang::CXXConstructExpr>(cur)) {
                    if (CCE->getNumArgs() >= 1 && (is_view || isStringViewOrSpanType(CCE->getType()))) {
                        cur = CCE->getArg(0);
                        continue;
                    }
                    break;
                }
                if (const auto *MCE = llvm::dyn_cast<clang::CXXMemberCallExpr>(cur)) {
                    const clang::FunctionDecl *MD = MCE->getDirectCallee();
                    const std::string mname = MD ? MD->getNameAsString() : std::string{};
                    if (mname == "c_str" || mname == "data" || mname == "begin" ||
                        mname.rfind("operator basic_string_view", 0) == 0) {
                        saw_container_data_call = true;
                        cur = MCE->getImplicitObjectArgument();
                        continue;
                    }
                    break;
                }
                break;
            }

            if (!cur)
                return nullptr;
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(cur)) {
                if (const auto *VD = llvm::dyn_cast_or_null<clang::VarDecl>(DRE->getDecl())) {
                    if (!isLocalNonStaticVar(VD))
                        return nullptr;
                    const clang::QualType vd_type = VD->getType().getCanonicalType().getUnqualifiedType();
                    if (saw_addr_of)
                        return VD;
                    if (is_ref) {
                        return vd_type->isReferenceType() ? nullptr : VD;
                    }
                    if (is_ptr) {
                        if (vd_type->isArrayType() || saw_container_data_call)
                            return VD;
                        return nullptr;
                    }
                    if (is_view) {
                        if (vd_type->isArrayType() || isOwningContainerType(vd_type) || saw_container_data_call) {
                            return VD;
                        }
                        return nullptr;
                    }
                }
            }
            return nullptr;
        }

    } // namespace

    RuntimeDependencyVisitor::RuntimeDependencyVisitor(clang::CompilerInstance &ci, unsigned diag_id,
                                                       TargetPlatform platform, CallPatternCollector *collector)
        : ci_(ci), sm_(ci.getSourceManager()), diags_(ci.getDiagnostics()), diag_id_(diag_id), platform_(platform),
          collector_(collector), mangle_ctx_(ci.getASTContext().createMangleContext()) {
    }

    bool RuntimeDependencyVisitor::TraverseTranslationUnitDecl(clang::TranslationUnitDecl *TUD) {
        if (!TUD)
            return true;
        virtual_overrides_.clear();
        VirtualOverrideCollector collector(sm_, virtual_overrides_);
        collector.TraverseTranslationUnitDecl(TUD);
        return clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseTranslationUnitDecl(TUD);
    }

    bool RuntimeDependencyVisitor::TraverseStmt(clang::Stmt *S) {
        if (!S)
            return true;
        if (current_unreachable_stmts_.count(S)) {
            return true;
        }
        return clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseStmt(S);
    }

    bool RuntimeDependencyVisitor::TraverseFunctionDecl(clang::FunctionDecl *FD) {
        return traverseFunctionWithContext(
            FD, [&]() { return clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseFunctionDecl(FD); });
    }

    bool RuntimeDependencyVisitor::TraverseCXXMethodDecl(clang::CXXMethodDecl *MD) {
        return traverseFunctionWithContext(
            MD, [&]() { return clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseCXXMethodDecl(MD); });
    }

    template <typename TraverseFn>
    bool RuntimeDependencyVisitor::traverseFunctionWithContext(clang::FunctionDecl *FD, TraverseFn &&traverse_fn) {
        if (!FD)
            return true;
        const bool is_user_body = FD->doesThisDeclarationHaveABody() && FD->getLocation().isValid() &&
                                  !sm_.isInSystemHeader(FD->getLocation());

        bool is_lambda_call_op = false;
        if (const auto *MD = llvm::dyn_cast<clang::CXXMethodDecl>(FD)) {
            if (MD->getParent() && MD->getParent()->isLambda()) {
                is_lambda_call_op = true;
            }
        }

        std::string prev_caller;
        llvm::DenseMap<const clang::VarDecl *, LocalPtrOrigin> prev_origins;
        bool prev_has_xor_loop = false;
        unsigned prev_loop_depth = 0;
        bool prev_is_auto_init = false;
        std::string prev_entrypoint_kind;
        bool prev_has_crypto_hash = false;
        std::vector<std::string> prev_crypto_hash_tags;
        bool prev_has_stack_string = false;
        std::vector<std::string> prev_stack_strings;
        llvm::DenseMap<const clang::VarDecl *, std::string> prev_decoded_var_strings;
        bool prev_has_cff = false;
        TaintTracker prev_taint_tracker;
        FunctionTaintSummary prev_fn_summary;
        llvm::DenseMap<const clang::ParmVarDecl *, uint32_t> prev_param_indices;
        llvm::DenseMap<uintptr_t, uint32_t> prev_param_flow;
        llvm::SmallPtrSet<const clang::Stmt *, 32> prev_unreachable_stmts;
        std::vector<std::string> prev_held_locks;
        std::unordered_set<std::string> prev_scoped_guards;
        std::unordered_set<const clang::VarDecl *> prev_local_vars;
        std::unordered_set<const clang::VarDecl *> prev_freed_vars;
        llvm::SmallPtrSet<const clang::DeclRefExpr *, 16> prev_free_arg_refs;
        clang::QualType prev_fn_return_type;
        if (is_user_body) {
            prev_held_locks = std::move(held_locks_);
            held_locks_.clear();
            prev_scoped_guards = std::move(scoped_guards_);
            scoped_guards_.clear();
            prev_local_vars = std::move(local_vars_);
            local_vars_.clear();
            prev_freed_vars = std::move(freed_vars_);
            freed_vars_.clear();
            prev_free_arg_refs = std::move(free_arg_refs_);
            free_arg_refs_.clear();
            prev_fn_return_type = current_fn_return_type_;
            current_fn_return_type_ = FD->getReturnType();
            prev_caller = std::move(current_caller_);
            current_caller_ = FD->getQualifiedNameAsString();
            prev_origins = std::move(local_ptr_origins_);
            local_ptr_origins_.clear();
            if (is_lambda_call_op) {
                local_ptr_origins_ = pending_lambda_var_origins_;
            }

            prev_unreachable_stmts = std::move(current_unreachable_stmts_);
            computeUnreachableStmts(FD, ci_.getASTContext(), current_unreachable_stmts_);

            prev_has_xor_loop = current_fn_has_xor_loop_;
            prev_loop_depth = loop_depth_;
            loop_depth_ = 0;
            current_fn_has_xor_loop_ = containsBitwiseXorLoop(FD->getBody(), &current_unreachable_stmts_);

            prev_is_auto_init = current_is_auto_init_;
            prev_entrypoint_kind = std::move(current_entrypoint_kind_);
            if (!is_lambda_call_op) {
                current_is_auto_init_ = false;
                current_entrypoint_kind_.clear();
                detectAutoInitEntrypoint(FD, current_is_auto_init_, current_entrypoint_kind_);
            } else {
                current_entrypoint_kind_ = prev_entrypoint_kind;
            }

            prev_has_crypto_hash = current_fn_has_crypto_hash_;
            prev_crypto_hash_tags = std::move(current_fn_crypto_hash_tags_);
            CryptoHashDetectionResult crypto_res =
                detectCryptoAndHashConstants(ci_.getASTContext(), FD->getBody(), &current_unreachable_stmts_);
            current_fn_has_crypto_hash_ = crypto_res.has_constant;
            current_fn_crypto_hash_tags_ = std::move(crypto_res.tags);

            prev_has_stack_string = current_fn_has_stack_string_;
            prev_stack_strings = std::move(current_fn_stack_strings_);
            prev_decoded_var_strings = std::move(current_fn_decoded_var_strings_);
            current_fn_decoded_var_strings_.clear();
            prev_has_cff = current_fn_has_cff_;
            prev_taint_tracker = std::move(taint_tracker_);
            taint_tracker_.clear();

            prev_fn_summary = std::move(current_fn_summary_);
            current_fn_summary_ = FunctionTaintSummary{};
            prev_param_indices = std::move(current_fn_param_indices_);
            current_fn_param_indices_.clear();
            prev_param_flow = std::move(current_fn_param_flow_);
            current_fn_param_flow_.clear();
            for (unsigned i = 0; i < FD->getNumParams() && i < 32; ++i) {
                if (const clang::ParmVarDecl *PVD = FD->getParamDecl(i)) {
                    current_fn_param_indices_[PVD] = i;
                    current_fn_param_flow_[TaintTracker::toKey(PVD)] = (1u << i);
                }
            }

            std::vector<StackStringEntry> stack_entries =
                detectStackStringsInBody(ci_.getASTContext(), FD->getBody(), &current_unreachable_stmts_);
            std::vector<StackStringEntry> xor_entries =
                detectXorDecodedStringsInBody(ci_.getASTContext(), FD->getBody(), &current_unreachable_stmts_);
            for (auto &xe : xor_entries) {
                stack_entries.push_back(std::move(xe));
            }

            current_fn_has_stack_string_ = !stack_entries.empty();
            current_fn_stack_strings_.clear();
            for (const auto &entry : stack_entries) {
                if (std::find(current_fn_stack_strings_.begin(), current_fn_stack_strings_.end(), entry.value) ==
                    current_fn_stack_strings_.end()) {
                    current_fn_stack_strings_.push_back(entry.value);
                }
                if (entry.var) {
                    current_fn_decoded_var_strings_[entry.var] = entry.value;
                    taint_tracker_.addTaint(TaintTracker::toKey(entry.var), TaintKind::StackString, entry.value);
                }
            }

            clang::SourceLocation cff_loc;
            current_fn_has_cff_ = detectCffDispatcher(FD->getBody(), cff_loc, &current_unreachable_stmts_);

            if (collector_ && !stack_entries.empty()) {
                for (const auto &entry : stack_entries) {
                    CallPatternRecord pat;
                    pat.caller_function = current_caller_;
                    pat.symbol = entry.value;
                    pat.mangled_symbol = entry.value;
                    pat.library = "stack-string";
                    pat.category = "ObfuscatedPayload";
                    pat.kind = "stack_string";
                    pat.return_type = entry.var ? entry.var->getType().getAsString() : "char[]";
                    pat.all_args_constant = true;
                    pat.arg_literals.push_back(entry.value);
                    const clang::SourceLocation emit_loc = entry.loc.isValid() ? entry.loc : FD->getLocation();
                    fillPresumedLocation(emit_loc, pat.source_file, pat.line, pat.column);

                    BehaviorFeatures features;
                    features.target_os = HeaderClassifier::platformToTargetOS(platform_);
                    features.call_kind = "data_blob";
                    features.return_type = pat.return_type;
                    features.inside_loop = (loop_depth_ > 0);
                    features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
                    features.has_crypto_or_hash_constant = current_fn_has_crypto_hash_;
                    features.crypto_hash_tags = current_fn_crypto_hash_tags_;
                    features.has_stack_string = true;
                    features.reconstructed_stack_strings.push_back(entry.value);
                    features.string_literals.push_back(entry.value);
                    features.has_cff_dispatcher = current_fn_has_cff_;
                    features.is_auto_init_entrypoint = current_is_auto_init_;
                    features.entrypoint_kind = current_entrypoint_kind_;
                    features.caller_function = current_caller_;
                    classifyAndPopulateRecord(pat, features);
                    collector_->add(std::move(pat));
                }
            }

            if (collector_ && current_fn_has_cff_) {
                CallPatternRecord pat;
                pat.caller_function = current_caller_;
                pat.symbol = "cff_dispatcher";
                pat.mangled_symbol = "cff_dispatcher";
                pat.library = "control-flow";
                pat.category = "ObfuscatedPayload";
                pat.kind = "cff_dispatcher";
                pat.return_type = FD->getReturnType().getAsString();
                const clang::SourceLocation emit_loc = cff_loc.isValid() ? cff_loc : FD->getLocation();
                fillPresumedLocation(emit_loc, pat.source_file, pat.line, pat.column);

                BehaviorFeatures features;
                features.target_os = HeaderClassifier::platformToTargetOS(platform_);
                features.call_kind = "direct";
                features.return_type = pat.return_type;
                features.inside_loop = true;
                features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
                features.has_crypto_or_hash_constant = current_fn_has_crypto_hash_;
                features.crypto_hash_tags = current_fn_crypto_hash_tags_;
                features.has_stack_string = current_fn_has_stack_string_;
                features.reconstructed_stack_strings = current_fn_stack_strings_;
                features.has_cff_dispatcher = true;
                features.is_auto_init_entrypoint = current_is_auto_init_;
                features.entrypoint_kind = current_entrypoint_kind_;
                features.caller_function = current_caller_;
                classifyAndPopulateRecord(pat, features);
                collector_->add(std::move(pat));
            }

            if (collector_ && crypto_res.has_loop_pattern) {
                CallPatternRecord pat;
                pat.caller_function = current_caller_;
                pat.symbol =
                    current_fn_crypto_hash_tags_.empty() ? "crypto_hash_loop" : current_fn_crypto_hash_tags_.front();
                pat.mangled_symbol = pat.symbol;
                pat.library = "crypto-hash";
                pat.category = "CryptoOrApiHash";
                pat.kind = "crypto_hash_loop";
                pat.return_type = FD->getReturnType().getAsString();
                const clang::SourceLocation emit_loc =
                    crypto_res.first_loc.isValid() ? crypto_res.first_loc : FD->getLocation();
                fillPresumedLocation(emit_loc, pat.source_file, pat.line, pat.column);

                BehaviorFeatures features;
                features.target_os = HeaderClassifier::platformToTargetOS(platform_);
                features.call_kind = "direct";
                features.return_type = pat.return_type;
                features.inside_loop = true;
                features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
                features.has_crypto_or_hash_constant = true;
                features.crypto_hash_tags = current_fn_crypto_hash_tags_;
                features.is_auto_init_entrypoint = current_is_auto_init_;
                features.entrypoint_kind = current_entrypoint_kind_;
                features.caller_function = current_caller_;
                classifyAndPopulateRecord(pat, features);
                collector_->add(std::move(pat));
            }
        }
        const bool ok = traverse_fn();
        if (is_user_body) {
            if (!current_fn_summary_.param_sinks.empty() || current_fn_summary_.return_taint_mask != 0 ||
                !current_fn_summary_.param_to_param.empty() || !current_fn_summary_.param_to_return.empty()) {
                summary_table_.recordSummary(current_caller_, current_fn_summary_);
            }
            current_caller_ = std::move(prev_caller);
            local_ptr_origins_ = std::move(prev_origins);
            current_fn_has_xor_loop_ = prev_has_xor_loop;
            loop_depth_ = prev_loop_depth;
            current_is_auto_init_ = prev_is_auto_init;
            current_entrypoint_kind_ = std::move(prev_entrypoint_kind);
            current_fn_has_crypto_hash_ = prev_has_crypto_hash;
            current_fn_crypto_hash_tags_ = std::move(prev_crypto_hash_tags);
            current_fn_has_stack_string_ = prev_has_stack_string;
            current_fn_stack_strings_ = std::move(prev_stack_strings);
            current_fn_decoded_var_strings_ = std::move(prev_decoded_var_strings);
            current_fn_has_cff_ = prev_has_cff;
            taint_tracker_ = std::move(prev_taint_tracker);
            current_fn_summary_ = std::move(prev_fn_summary);
            current_fn_param_indices_ = std::move(prev_param_indices);
            current_fn_param_flow_ = std::move(prev_param_flow);
            current_unreachable_stmts_ = std::move(prev_unreachable_stmts);
            held_locks_ = std::move(prev_held_locks);
            scoped_guards_ = std::move(prev_scoped_guards);
            local_vars_ = std::move(prev_local_vars);
            freed_vars_ = std::move(prev_freed_vars);
            free_arg_refs_ = std::move(prev_free_arg_refs);
            current_fn_return_type_ = prev_fn_return_type;
        }
        return ok;
    }

    bool RuntimeDependencyVisitor::TraverseLambdaExpr(clang::LambdaExpr *LE) {
        if (!LE)
            return true;
        const clang::SourceLocation loc = LE->getBeginLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc)) {
            return clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseLambdaExpr(LE);
        }

        auto prev_pending_vars = std::move(pending_lambda_var_origins_);
        pending_lambda_var_origins_.clear();
        auto prev_captured_fields = captured_field_origins_;

        if (const clang::CXXRecordDecl *lambda_class = LE->getLambdaClass()) {
            llvm::DenseMap<const clang::ValueDecl *, clang::FieldDecl *> capture_fields;
            clang::FieldDecl *this_capture = nullptr;
            lambda_class->getCaptureFields(capture_fields, this_capture);

            for (const auto &kv : capture_fields) {
                const auto *captured_var = llvm::dyn_cast_or_null<clang::VarDecl>(kv.first);
                const clang::FieldDecl *capture_field = kv.second;
                if (!captured_var)
                    continue;

                auto it = local_ptr_origins_.find(captured_var);
                if (it == local_ptr_origins_.end() && captured_var->hasInit()) {
                    if (const auto *DRE =
                            llvm::dyn_cast<clang::DeclRefExpr>(captured_var->getInit()->IgnoreParenCasts())) {
                        if (const auto *init_var = llvm::dyn_cast_or_null<clang::VarDecl>(DRE->getDecl())) {
                            it = local_ptr_origins_.find(init_var);
                        }
                    }
                }
                if (it != local_ptr_origins_.end()) {
                    pending_lambda_var_origins_[captured_var] = it->second;
                    if (capture_field) {
                        captured_field_origins_[capture_field] = it->second;
                    }
                }
            }
        }

        const bool ok = clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseLambdaExpr(LE);
        pending_lambda_var_origins_ = std::move(prev_pending_vars);
        captured_field_origins_ = std::move(prev_captured_fields);
        return ok;
    }

    bool RuntimeDependencyVisitor::TraverseForStmt(clang::ForStmt *S) {
        if (!S)
            return true;
        const bool in_user = S->getBeginLoc().isValid() && !sm_.isInSystemHeader(S->getBeginLoc());
        if (in_user)
            ++loop_depth_;
        const bool ok = clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseForStmt(S);
        if (in_user)
            --loop_depth_;
        return ok;
    }

    bool RuntimeDependencyVisitor::TraverseWhileStmt(clang::WhileStmt *S) {
        if (!S)
            return true;
        const bool in_user = S->getBeginLoc().isValid() && !sm_.isInSystemHeader(S->getBeginLoc());
        if (in_user)
            ++loop_depth_;
        const bool ok = clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseWhileStmt(S);
        if (in_user)
            --loop_depth_;
        return ok;
    }

    bool RuntimeDependencyVisitor::TraverseDoStmt(clang::DoStmt *S) {
        if (!S)
            return true;
        const bool in_user = S->getBeginLoc().isValid() && !sm_.isInSystemHeader(S->getBeginLoc());
        if (in_user)
            ++loop_depth_;
        const bool ok = clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseDoStmt(S);
        if (in_user)
            --loop_depth_;
        return ok;
    }

    bool RuntimeDependencyVisitor::TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        if (!S)
            return true;
        const bool in_user = S->getBeginLoc().isValid() && !sm_.isInSystemHeader(S->getBeginLoc());
        if (in_user)
            ++loop_depth_;
        const bool ok = clang::RecursiveASTVisitor<RuntimeDependencyVisitor>::TraverseCXXForRangeStmt(S);
        if (in_user)
            --loop_depth_;
        return ok;
    }

    bool RuntimeDependencyVisitor::VisitCallExpr(clang::CallExpr *CE) {
        if (!CE)
            return true;
        const clang::SourceLocation call_loc = CE->getBeginLoc();
        if (call_loc.isInvalid() || sm_.isInSystemHeader(call_loc))
            return true;

        if (const clang::Expr *callee = CE->getCallee()) {
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(callee->IgnoreParenImpCasts())) {
                call_callee_refs_.insert(DRE);
            }
        }

        const clang::FunctionDecl *FD = CE->getDirectCallee();
        if (!FD) {
            inspectIndirectCall(CE, call_loc);
            return true;
        }

        if (const auto *MCE = llvm::dyn_cast<clang::CXXMemberCallExpr>(CE)) {
            emitVirtualOverrideCalls(MCE, call_loc);
            const std::string mname = FD->getNameAsString();
            if ((mname == "lock" || mname == "unlock") && MCE->getNumArgs() == 0 &&
                !isRaiiLockGuardType(MCE->getObjectType())) {
                const std::string lock_name = extractLockExprName(MCE->getImplicitObjectArgument());
                if (!lock_name.empty()) {
                    if (mname == "lock") {
                        handleLockAcquisition(lock_name, call_loc);
                    } else {
                        handleLockRelease(lock_name);
                    }
                }
            }
        } else {
            const std::string fn_name = FD->getNameAsString();
            if ((fn_name == "pthread_mutex_lock" || fn_name == "pthread_mutex_unlock") && CE->getNumArgs() >= 1) {
                const std::string lock_name = extractLockExprName(CE->getArg(0));
                if (!lock_name.empty()) {
                    if (fn_name == "pthread_mutex_lock") {
                        handleLockAcquisition(lock_name, call_loc);
                    } else {
                        handleLockRelease(lock_name);
                    }
                }
            }
        }

        {
            const std::string fn_name = FD->getNameAsString();
            if ((fn_name == "free" || fn_name == "munmap") && CE->getNumArgs() >= 1) {
                if (const auto *arg_dre = llvm::dyn_cast<clang::DeclRefExpr>(CE->getArg(0)->IgnoreParenCasts())) {
                    free_arg_refs_.insert(arg_dre);
                }
                if (const clang::VarDecl *arg_vd = extractVarDeclFromExpr(CE->getArg(0))) {
                    if (freed_vars_.count(arg_vd) > 0) {
                        emitLifetimeRecord("double_free", "double_free", "double_free", arg_vd->getNameAsString(), 85,
                                           call_loc);
                    } else {
                        freed_vars_.insert(arg_vd);
                    }
                }
            } else {
                for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
                    if (const clang::VarDecl *arg_vd = extractVarDeclFromExpr(CE->getArg(i))) {
                        if (freed_vars_.count(arg_vd) > 0) {
                            emitUseAfterFree(arg_vd, CE->getArg(i)->getBeginLoc());
                        }
                    }
                }
            }
        }

        propagateMemCopyTaint(FD, CE);
        applyInterproceduralCallSummary(FD, CE);
        trackStringAssemblyCall(CE);

        ExtractedCallTelemetry tel;
        collectCallArgumentTelemetry(CE, tel);

        inspectFunction(FD, call_loc, "call", CE, nullptr, &tel);

        if (!tel.arg_entropies.empty() || !tel.arg_bitmasks.empty()) {
            tel.caller_function = current_caller_;
            tel.symbol = FD->getNameAsString();
            tel.is_indirect = false;
            tel.is_auto_init_entrypoint = current_is_auto_init_;
            tel.entrypoint_kind = current_entrypoint_kind_;
            fillPresumedLocation(call_loc, tel.source_file, tel.line, tel.column);
            extracted_telemetry_.push_back(std::move(tel));
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitDeclRefExpr(clang::DeclRefExpr *DRE) {
        if (!DRE || call_callee_refs_.count(DRE))
            return true;
        const clang::SourceLocation ref_loc = DRE->getBeginLoc();
        if (ref_loc.isInvalid() || sm_.isInSystemHeader(ref_loc))
            return true;

        const clang::ValueDecl *VD = DRE->getDecl();
        if (const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(VD)) {
            inspectFunction(FD, ref_loc, "pointer reference");
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitVarDecl(clang::VarDecl *VD) {
        if (!VD)
            return true;
        const clang::SourceLocation loc = VD->getLocation();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        if (isLocalNonStaticVar(VD)) {
            local_vars_.insert(VD);
            if (isRaiiLockGuardType(VD->getType()) && VD->hasInit()) {
                const clang::Expr *init_expr = VD->getInit()->IgnoreParenImpCasts();
                if (const auto *EWC = llvm::dyn_cast<clang::ExprWithCleanups>(init_expr)) {
                    init_expr = EWC->getSubExpr()->IgnoreParenImpCasts();
                }
                if (const auto *CCE = llvm::dyn_cast<clang::CXXConstructExpr>(init_expr)) {
                    for (unsigned i = 0; i < CCE->getNumArgs(); ++i) {
                        const std::string lock_name = extractLockExprName(CCE->getArg(i));
                        if (!lock_name.empty()) {
                            scoped_guards_.insert(lock_name);
                        }
                    }
                }
            }
        }

        if (!VD->hasInit())
            return true;

        if (VD->hasLocalStorage()) {
            if (VD->getType()->isPointerType()) {
                trackPointerOriginFromExpr(VD, VD->getInit(), loc);
            }
            updateTaintFromAssignment(VD, VD->getInit());
            if (current_fn_decoded_var_strings_.find(VD) == current_fn_decoded_var_strings_.end()) {
                std::string assembled;
                if (extractAssembledStringLiteral(VD->getInit(), assembled) && !assembled.empty()) {
                    current_fn_decoded_var_strings_[VD] = std::move(assembled);
                }
            }
        }

        const clang::Expr *init = VD->getInit()->IgnoreParenImpCasts();
        if (const auto *SL = llvm::dyn_cast<clang::StringLiteral>(init)) {
            const llvm::StringRef bytes = SL->getBytes();
            const std::string_view sv(bytes.data(), bytes.size());
            ByteBlobEntropyRecord rec;
            rec.caller_function = current_caller_;
            rec.var_name = VD->getNameAsString();
            rec.byte_length = sv.size();
            rec.shannon_entropy = EntropyAnalyzer::computeShannonEntropy(sv);
            rec.is_high_entropy = EntropyAnalyzer::isHighEntropyString(sv);
            rec.is_string_literal = true;
            fillPresumedLocation(loc, rec.source_file, rec.line, rec.column);
            if (rec.is_high_entropy) {
                taint_tracker_.addTaint(TaintTracker::toKey(VD), TaintKind::HighEntropyBlob, rec.var_name);
            }
            if (collector_ && rec.is_high_entropy) {
                CallPatternRecord pat;
                pat.caller_function = rec.caller_function;
                pat.symbol = rec.var_name;
                pat.mangled_symbol = rec.var_name;
                pat.library = "data-blob";
                pat.category = "ObfuscatedPayload";
                pat.kind = "high_entropy_string";
                pat.return_type = VD->getType().getAsString();
                pat.all_args_constant = true;
                pat.source_file = rec.source_file;
                pat.line = rec.line;
                pat.column = rec.column;

                BehaviorFeatures features;
                features.target_os = HeaderClassifier::platformToTargetOS(platform_);
                features.call_kind = "data_blob";
                features.return_type = pat.return_type;
                features.arg_entropies.push_back(rec.shannon_entropy);
                features.max_arg_entropy = rec.shannon_entropy;
                features.has_high_entropy_literal = true;
                features.inside_loop = (loop_depth_ > 0);
                features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
                features.has_crypto_or_hash_constant = current_fn_has_crypto_hash_;
                features.crypto_hash_tags = current_fn_crypto_hash_tags_;
                features.is_auto_init_entrypoint = current_is_auto_init_;
                features.entrypoint_kind = current_entrypoint_kind_;
                features.caller_function = current_caller_;
                classifyAndPopulateRecord(pat, features);
                collector_->add(std::move(pat));
            }
            byte_blob_entropies_.push_back(std::move(rec));
        } else if (const auto *ILE = llvm::dyn_cast<clang::InitListExpr>(init)) {
            std::vector<uint8_t> bytes;
            if (extractBytesFromInitList(ILE, bytes)) {
                ByteBlobEntropyRecord rec;
                rec.caller_function = current_caller_;
                rec.var_name = VD->getNameAsString();
                rec.byte_length = bytes.size();
                rec.shannon_entropy = EntropyAnalyzer::computeByteEntropy(bytes.data(), bytes.size());
                rec.is_high_entropy = EntropyAnalyzer::isLikelyEncryptedOrPacked(bytes.data(), bytes.size());
                rec.is_string_literal = false;
                fillPresumedLocation(loc, rec.source_file, rec.line, rec.column);
                if (rec.is_high_entropy) {
                    taint_tracker_.addTaint(TaintTracker::toKey(VD), TaintKind::HighEntropyBlob, rec.var_name);
                }
                if (collector_ && rec.is_high_entropy) {
                    CallPatternRecord pat;
                    pat.caller_function = rec.caller_function;
                    pat.symbol = rec.var_name;
                    pat.mangled_symbol = rec.var_name;
                    pat.library = "data-blob";
                    pat.category = "ObfuscatedPayload";
                    pat.kind = "high_entropy_bytes";
                    pat.return_type = VD->getType().getAsString();
                    pat.all_args_constant = true;
                    pat.source_file = rec.source_file;
                    pat.line = rec.line;
                    pat.column = rec.column;

                    BehaviorFeatures features;
                    features.target_os = HeaderClassifier::platformToTargetOS(platform_);
                    features.call_kind = "data_blob";
                    features.return_type = pat.return_type;
                    features.arg_entropies.push_back(rec.shannon_entropy);
                    features.max_arg_entropy = rec.shannon_entropy;
                    features.has_high_entropy_literal = true;
                    features.inside_loop = (loop_depth_ > 0);
                    features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
                    features.has_crypto_or_hash_constant = current_fn_has_crypto_hash_;
                    features.crypto_hash_tags = current_fn_crypto_hash_tags_;
                    features.is_auto_init_entrypoint = current_is_auto_init_;
                    features.entrypoint_kind = current_entrypoint_kind_;
                    features.caller_function = current_caller_;
                    classifyAndPopulateRecord(pat, features);
                    collector_->add(std::move(pat));
                }
                byte_blob_entropies_.push_back(std::move(rec));
            }
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitBinaryOperator(clang::BinaryOperator *BO) {
        if (!BO)
            return true;
        const clang::SourceLocation loc = BO->getOperatorLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        if (BO->getOpcode() == clang::BO_Assign) {
            const clang::Expr *lhs = BO->getLHS()->IgnoreParenImpCasts();
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(lhs)) {
                if (const auto *VD = llvm::dyn_cast_or_null<clang::VarDecl>(DRE->getDecl())) {
                    freed_vars_.erase(VD);
                    if (VD->hasLocalStorage()) {
                        if (VD->getType()->isPointerType()) {
                            trackPointerOriginFromExpr(VD, BO->getRHS(), loc);
                        }
                        updateTaintFromAssignment(VD, BO->getRHS());
                    }
                }
            } else if (llvm::isa<clang::MemberExpr>(lhs)) {
                const clang::Expr *rhs = BO->getRHS()->IgnoreParenCasts();
                if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(rhs)) {
                    if (UO->getOpcode() == clang::UO_AddrOf) {
                        if (const clang::VarDecl *VD = extractVarDeclFromExpr(UO->getSubExpr())) {
                            if (isLocalNonStaticVar(VD)) {
                                emitLifetimeRecord("lifetime_stack_escape", "stack_escape", "stack_escape",
                                                   VD->getNameAsString(), 75, loc);
                            }
                        }
                    }
                } else if (const auto *RDRE = llvm::dyn_cast<clang::DeclRefExpr>(rhs)) {
                    if (const auto *VD = llvm::dyn_cast_or_null<clang::VarDecl>(RDRE->getDecl())) {
                        if (isLocalNonStaticVar(VD) && VD->getType()->isArrayType()) {
                            emitLifetimeRecord("lifetime_stack_escape", "stack_escape", "stack_escape",
                                               VD->getNameAsString(), 75, loc);
                        }
                    }
                }
                const std::string lhs_key_str = extractExprTaintKey(lhs);
                if (!lhs_key_str.empty()) {
                    if (const uintptr_t dst_key = resolveTaintKey(lhs)) {
                        updateTaintFromAssignment(dst_key, lhs_key_str, BO->getRHS());
                    }
                }
            } else if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(lhs)) {
                if (UO->getOpcode() == clang::UO_Deref) {
                    if (const auto *base_vd = extractVarDeclFromExpr(UO->getSubExpr())) {
                        if (const auto *PVD = llvm::dyn_cast<clang::ParmVarDecl>(base_vd)) {
                            const auto p_it = current_fn_param_indices_.find(PVD);
                            if (p_it != current_fn_param_indices_.end()) {
                                const uint32_t rhs_mask = getExprParamFlowMask(BO->getRHS());
                                recordParamToParamFlow(rhs_mask, p_it->second);
                            }
                        }
                    }
                }
            } else {
                const std::string lhs_key_str = extractExprTaintKey(lhs);
                if (!lhs_key_str.empty()) {
                    if (const uintptr_t dst_key = resolveTaintKey(lhs)) {
                        updateTaintFromAssignment(dst_key, lhs_key_str, BO->getRHS());
                    }
                }
            }
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitUnaryOperator(clang::UnaryOperator *UO) {
        if (!UO)
            return true;
        const clang::SourceLocation loc = UO->getOperatorLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;
        if (UO->getOpcode() == clang::UO_Deref) {
            if (const clang::VarDecl *VD = extractVarDeclFromExpr(UO->getSubExpr())) {
                if (freed_vars_.count(VD) > 0) {
                    emitUseAfterFree(VD, loc);
                }
            }
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitMemberExpr(clang::MemberExpr *ME) {
        if (!ME || !ME->isArrow())
            return true;
        const clang::SourceLocation loc = ME->getMemberLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;
        if (const clang::VarDecl *VD = extractVarDeclFromExpr(ME->getBase())) {
            if (freed_vars_.count(VD) > 0) {
                emitUseAfterFree(VD, loc);
            }
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitArraySubscriptExpr(clang::ArraySubscriptExpr *ASE) {
        if (!ASE)
            return true;
        const clang::SourceLocation loc = ASE->getBeginLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;
        if (const clang::VarDecl *VD = extractVarDeclFromExpr(ASE->getBase())) {
            if (freed_vars_.count(VD) > 0) {
                emitUseAfterFree(VD, loc);
            }
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitReturnStmt(clang::ReturnStmt *RS) {
        if (!RS)
            return true;
        const clang::SourceLocation loc = RS->getReturnLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        for (const std::string &lock_name : held_locks_) {
            if (scoped_guards_.count(lock_name) == 0 && collector_) {
                CallPatternRecord pat;
                pat.caller_function = current_caller_;
                pat.symbol = lock_name;
                pat.mangled_symbol = lock_name;
                pat.library = "concurrency";
                pat.category = "LockLeak";
                pat.kind = "lock_unclosed";
                pat.behavior_category = "Concurrency";
                pat.risk_score = 60;
                pat.behavior_tags.push_back("lock_unclosed");
                setLifetimeFieldIfPresent(pat, "lock_unclosed");
                setLockFieldsIfPresent(pat, lock_name, "");
                pat.is_auto_init_entrypoint = current_is_auto_init_;
                pat.entrypoint_kind = current_entrypoint_kind_;
                fillPresumedLocation(loc, pat.source_file, pat.line, pat.column);
                collector_->add(std::move(pat));
            }
        }

        if (!RS->getRetValue())
            return true;

        if (const clang::VarDecl *dangling_vd = findDanglingLocalVar(RS->getRetValue(), current_fn_return_type_)) {
            emitLifetimeRecord("lifetime_dangling", "dangling_view", "dangling_view", dangling_vd->getNameAsString(),
                               75, loc, current_fn_return_type_.getAsString());
        }

        const clang::Expr *ret_val = RS->getRetValue()->IgnoreParenCasts();
        if (const auto *call = llvm::dyn_cast<clang::CallExpr>(ret_val)) {
            std::string sym;
            const BehaviorCategory cat = classifyCallExprCategory(call, &sym);
            if (cat == BehaviorCategory::MemoryAllocation) {
                current_fn_summary_.return_taint_mask |= static_cast<uint32_t>(TaintKind::MemoryAlloc);
                if (current_fn_summary_.origin_symbol.empty()) {
                    current_fn_summary_.origin_symbol = sym;
                }
            } else if (cat == BehaviorCategory::DynamicResolution) {
                current_fn_summary_.return_taint_mask |= static_cast<uint32_t>(TaintKind::DynamicResolve);
                if (current_fn_summary_.origin_symbol.empty()) {
                    current_fn_summary_.origin_symbol = sym;
                }
            } else if (const clang::FunctionDecl *callee = call->getDirectCallee()) {
                const FunctionTaintSummary *callee_sum = summary_table_.findSummary(callee->getQualifiedNameAsString());
                if (!callee_sum) {
                    callee_sum = summary_table_.findSummary(callee->getNameAsString());
                }
                if (callee_sum) {
                    current_fn_summary_.return_taint_mask |= callee_sum->return_taint_mask;
                    if (current_fn_summary_.origin_symbol.empty() && !callee_sum->origin_symbol.empty()) {
                        current_fn_summary_.origin_symbol = callee_sum->origin_symbol;
                    }
                    for (const uint32_t p_idx : callee_sum->param_to_return) {
                        if (p_idx < call->getNumArgs()) {
                            const uint32_t arg_mask = getExprParamFlowMask(call->getArg(p_idx));
                            for (uint32_t bit = 0; bit < 32; ++bit) {
                                if ((arg_mask & (1u << bit)) != 0 &&
                                    std::find(current_fn_summary_.param_to_return.begin(),
                                              current_fn_summary_.param_to_return.end(),
                                              bit) == current_fn_summary_.param_to_return.end()) {
                                    current_fn_summary_.param_to_return.push_back(bit);
                                }
                            }
                        }
                    }
                }
            }
            return true;
        }

        if (const uintptr_t key = resolveTaintKey(ret_val)) {
            const TaintState &state = taint_tracker_.getTaint(key);
            if (!state.empty()) {
                current_fn_summary_.return_taint_mask |= state.mask;
                if (current_fn_summary_.origin_symbol.empty()) {
                    current_fn_summary_.origin_symbol = state.origin_symbol;
                }
            }
        }

        const uint32_t param_mask = getExprParamFlowMask(ret_val);
        for (uint32_t bit = 0; bit < 32; ++bit) {
            if ((param_mask & (1u << bit)) != 0 &&
                std::find(current_fn_summary_.param_to_return.begin(), current_fn_summary_.param_to_return.end(),
                          bit) == current_fn_summary_.param_to_return.end()) {
                current_fn_summary_.param_to_return.push_back(bit);
            }
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitCXXMethodDecl(clang::CXXMethodDecl *) {
        return true;
    }

    bool RuntimeDependencyVisitor::VisitCastExpr(clang::CastExpr *CE) {
        if (!CE || llvm::isa<clang::ImplicitCastExpr>(CE))
            return true;
        const clang::SourceLocation loc = CE->getBeginLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        const clang::QualType target_type = CE->getType();
        if (target_type->isFunctionPointerType() || target_type->isMemberFunctionPointerType()) {
            const clang::Expr *sub = CE->getSubExpr();
            if (sub && sub->IgnoreParenImpCasts()->getType()->isNullPtrType()) {
                return true;
            }
            FunctionPointerCastRecord rec;
            rec.caller_function = current_caller_;
            rec.cast_kind = classifyExplicitCastKind(CE);
            if (sub) {
                rec.source_type = sub->getType().getAsString();
            }
            rec.target_type = target_type.getAsString();
            rec.from_integer = (CE->getCastKind() == clang::CK_IntegralToPointer);
            fillPresumedLocation(loc, rec.source_file, rec.line, rec.column);
            if (collector_) {
                CallPatternRecord pat;
                pat.caller_function = rec.caller_function;
                pat.symbol = rec.cast_kind;
                pat.mangled_symbol = rec.target_type;
                pat.library = "cast";
                pat.category = "FunctionPointerCast";
                pat.kind = "fn_ptr_cast";
                pat.return_type = rec.target_type;
                if (!rec.source_type.empty()) {
                    pat.param_types.push_back(rec.source_type);
                }
                pat.source_file = rec.source_file;
                pat.line = rec.line;
                pat.column = rec.column;

                BehaviorFeatures features;
                features.target_os = HeaderClassifier::platformToTargetOS(platform_);
                features.call_kind = "fn_ptr_cast";
                features.return_type = pat.return_type;
                features.param_types = pat.param_types;
                features.inside_loop = (loop_depth_ > 0);
                features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
                features.has_crypto_or_hash_constant = current_fn_has_crypto_hash_;
                features.crypto_hash_tags = current_fn_crypto_hash_tags_;
                features.is_auto_init_entrypoint = current_is_auto_init_;
                features.entrypoint_kind = current_entrypoint_kind_;
                features.caller_function = current_caller_;
                classifyAndPopulateRecord(pat, features);
                collector_->add(std::move(pat));
            }
            fp_casts_.push_back(std::move(rec));
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitGCCAsmStmt(clang::GCCAsmStmt *GAS) {
        if (!GAS)
            return true;
        const clang::SourceLocation loc = GAS->getAsmLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        std::string asm_str = GAS->generateAsmString(ci_.getASTContext());
        if (asm_str.empty() && GAS->getAsmStringExpr()) {
            if (const auto *SL = llvm::dyn_cast<clang::StringLiteral>(GAS->getAsmStringExpr()->IgnoreParenImpCasts())) {
                asm_str = SL->getString().str();
            }
        }

        std::string lower_asm = asm_str;
        std::transform(lower_asm.begin(), lower_asm.end(), lower_asm.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

        InlineAsmRecord rec;
        rec.caller_function = current_caller_;
        rec.asm_template = std::move(asm_str);
        rec.is_volatile = GAS->isVolatile();
        fillPresumedLocation(loc, rec.source_file, rec.line, rec.column);

        static constexpr std::array<std::string_view, 5> kMnemonicPatterns = {"syscall", "svc", "sysenter", "rdtsc",
                                                                              "cpuid"};
        for (const std::string_view pat : kMnemonicPatterns) {
            if (containsAsmMnemonic(lower_asm, pat)) {
                rec.matched_instructions.emplace_back(pat);
            }
        }
        if (containsInt80(lower_asm)) {
            rec.matched_instructions.emplace_back("int 0x80");
        }
        if (lower_asm.find("fs:") != std::string::npos) {
            rec.matched_instructions.emplace_back("fs:");
        }
        if (lower_asm.find("gs:") != std::string::npos) {
            rec.matched_instructions.emplace_back("gs:");
        }

        if (collector_) {
            CallPatternRecord pat;
            pat.caller_function = rec.caller_function;
            pat.symbol = rec.matched_instructions.empty() ? "inline_asm" : rec.matched_instructions.front();
            pat.mangled_symbol = pat.symbol;
            pat.library = "inline-asm";
            pat.category = "InlineAsm";
            pat.kind = "inline_asm";
            pat.return_type = "void";
            pat.source_file = rec.source_file;
            pat.line = rec.line;
            pat.column = rec.column;

            BehaviorFeatures features;
            features.target_os = HeaderClassifier::platformToTargetOS(platform_);
            features.call_kind = "inline_asm";
            features.asm_text = rec.asm_template;
            features.inside_loop = (loop_depth_ > 0);
            features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
            features.has_crypto_or_hash_constant = current_fn_has_crypto_hash_;
            features.crypto_hash_tags = current_fn_crypto_hash_tags_;
            features.is_auto_init_entrypoint = current_is_auto_init_;
            features.entrypoint_kind = current_entrypoint_kind_;
            features.caller_function = current_caller_;
            classifyAndPopulateRecord(pat, features);
            collector_->add(std::move(pat));
        }

        inline_asm_records_.push_back(std::move(rec));
        return true;
    }

    bool RuntimeDependencyVisitor::VisitCXXNewExpr(clang::CXXNewExpr *NE) {
        if (!NE)
            return true;
        const clang::SourceLocation loc = NE->getBeginLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        if (const clang::FunctionDecl *op_new = NE->getOperatorNew()) {
            if (!op_new->isReservedGlobalPlacementOperator()) {
                inspectFunction(op_new, loc, "operator new");
            }
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitCXXDeleteExpr(clang::CXXDeleteExpr *DE) {
        if (!DE)
            return true;
        const clang::SourceLocation loc = DE->getBeginLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        if (const clang::FunctionDecl *op_del = DE->getOperatorDelete()) {
            inspectFunction(op_del, loc, "operator delete");
        }
        return true;
    }

    bool RuntimeDependencyVisitor::VisitCXXThrowExpr(clang::CXXThrowExpr *TE) {
        if (!TE)
            return true;
        const clang::SourceLocation loc = TE->getBeginLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        reportExternal("__cxa_throw", "C++ throw", "C++ABI", "libstdc++/libc++/vcruntime", "compiler/eh_abi", false,
                       loc);
        return true;
    }

    bool RuntimeDependencyVisitor::VisitCXXTypeidExpr(clang::CXXTypeidExpr *TE) {
        if (!TE)
            return true;
        const clang::SourceLocation loc = TE->getBeginLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        reportExternal("typeid", "C++ RTTI", "C++ABI", "libstdc++/libc++/vcruntime", "compiler/rtti", false, loc);
        return true;
    }

    bool RuntimeDependencyVisitor::VisitCXXConstructExpr(clang::CXXConstructExpr *CE) {
        if (!CE)
            return true;
        const clang::SourceLocation loc = CE->getBeginLoc();
        if (loc.isInvalid() || sm_.isInSystemHeader(loc))
            return true;

        if (const clang::CXXConstructorDecl *CD = CE->getConstructor()) {
            if (!CD->isTrivial()) {
                inspectFunction(CD, loc, "constructor", nullptr, CE);
            }
        }
        return true;
    }

    bool RuntimeDependencyVisitor::findSystemHeaderDecl(const clang::FunctionDecl *FD, std::string &out_header) const {
        auto checkLoc = [&](clang::SourceLocation loc) -> bool {
            if (loc.isValid() && sm_.isInSystemHeader(loc)) {
                out_header = sm_.getFilename(loc).str();
                return true;
            }
            return false;
        };

        if (checkLoc(FD->getLocation()))
            return true;
        for (const clang::FunctionDecl *redecl : FD->redecls()) {
            if (checkLoc(redecl->getLocation()))
                return true;
        }
        if (const clang::FunctionDecl *pattern = FD->getTemplateInstantiationPattern()) {
            if (checkLoc(pattern->getLocation()))
                return true;
        }
        return false;
    }

    void RuntimeDependencyVisitor::reportExternal(std::string_view name, const char *usage_type,
                                                  std::string_view category, std::string_view library,
                                                  std::string_view header, bool replaceable,
                                                  clang::SourceLocation loc) {
        diags_.Report(loc, diag_id_) << std::string(name) << usage_type << getPlatformName(platform_)
                                     << std::string(library) << std::string(category) << std::string(header)
                                     << (replaceable ? "candidate for freestanding inline replacement"
                                                     : "host OS / runtime dependency");
    }

    std::string RuntimeDependencyVisitor::mangleDeclName(const clang::FunctionDecl *FD) const {
        if (!mangle_ctx_ || !FD || !mangle_ctx_->shouldMangleDeclName(FD)) {
            return {};
        }
        std::string mangled;
        llvm::raw_string_ostream os(mangled);
        if (const auto *CD = llvm::dyn_cast<clang::CXXConstructorDecl>(FD)) {
            mangle_ctx_->mangleName(clang::GlobalDecl(CD, clang::Ctor_Complete), os);
        } else if (const auto *DD = llvm::dyn_cast<clang::CXXDestructorDecl>(FD)) {
            mangle_ctx_->mangleName(clang::GlobalDecl(DD, clang::Dtor_Complete), os);
        } else {
            mangle_ctx_->mangleName(clang::GlobalDecl(FD), os);
        }
        os.flush();
        return mangled;
    }

    std::string RuntimeDependencyVisitor::classifyArgShape(const clang::Expr *arg, bool &is_const_out) const {
        if (!arg) {
            is_const_out = false;
            return "unknown";
        }
        const clang::Expr *clean = arg->IgnoreParenImpCasts();
        const std::string type_str = clean->getType().getAsString();

        if (llvm::isa<clang::StringLiteral>(clean) || llvm::isa<clang::IntegerLiteral>(clean) ||
            llvm::isa<clang::FloatingLiteral>(clean) || llvm::isa<clang::CharacterLiteral>(clean) ||
            llvm::isa<clang::CXXBoolLiteralExpr>(clean)) {
            is_const_out = true;
            return "lit:" + type_str;
        }
        if (llvm::isa<clang::CXXNullPtrLiteralExpr>(clean)) {
            is_const_out = true;
            return "null:" + type_str;
        }
        if (clean->isEvaluatable(ci_.getASTContext())) {
            is_const_out = true;
            return "const:" + type_str;
        }
        if (llvm::isa<clang::DeclRefExpr>(clean)) {
            is_const_out = false;
            return "var:" + type_str;
        }
        is_const_out = false;
        return "expr:" + type_str;
    }

    bool RuntimeDependencyVisitor::extractAssembledStringLiteral(const clang::Expr *expr, std::string &out,
                                                                 unsigned depth) const {
        if (!expr || depth > 16)
            return false;
        constexpr size_t kMaxAssembledLen = 1024;

        const clang::Expr *clean = expr;
        while (clean) {
            const clang::Expr *next = clean->IgnoreParenCasts();
            if (const auto *EWC = llvm::dyn_cast<clang::ExprWithCleanups>(next)) {
                next = EWC->getSubExpr();
            } else if (const auto *MTE = llvm::dyn_cast<clang::MaterializeTemporaryExpr>(next)) {
                next = MTE->getSubExpr();
            } else if (const auto *BTE = llvm::dyn_cast<clang::CXXBindTemporaryExpr>(next)) {
                next = BTE->getSubExpr();
            } else if (const auto *CE_expr = llvm::dyn_cast<clang::ConstantExpr>(next)) {
                next = CE_expr->getSubExpr();
            } else if (next == clean) {
                break;
            }
            clean = next;
        }
        if (!clean)
            return false;

        if (const auto *SL = llvm::dyn_cast<clang::StringLiteral>(clean)) {
            if (SL->isOrdinary() || SL->isUTF8()) {
                const llvm::StringRef sr = SL->getString();
                out.assign(sr.data(), std::min(sr.size(), kMaxAssembledLen));
                return true;
            }
            return false;
        }

        if (const auto *MCE = llvm::dyn_cast<clang::CXXMemberCallExpr>(clean)) {
            if (const clang::CXXMethodDecl *MD = MCE->getMethodDecl()) {
                const std::string mname = MD->getNameAsString();
                if ((mname == "c_str" || mname == "data") && MCE->getNumArgs() == 0) {
                    return extractAssembledStringLiteral(MCE->getImplicitObjectArgument(), out, depth + 1);
                }
            }
        }

        if (const auto *CCE = llvm::dyn_cast<clang::CXXConstructExpr>(clean)) {
            if (CCE->getNumArgs() >= 1) {
                bool rest_default = true;
                for (unsigned i = 1; i < CCE->getNumArgs(); ++i) {
                    if (!llvm::isa<clang::CXXDefaultArgExpr>(CCE->getArg(i))) {
                        rest_default = false;
                        break;
                    }
                }
                if (rest_default) {
                    return extractAssembledStringLiteral(CCE->getArg(0), out, depth + 1);
                }
            }
            return false;
        }

        if (const auto *OCE = llvm::dyn_cast<clang::CXXOperatorCallExpr>(clean)) {
            if (OCE->getOperator() == clang::OO_Plus && OCE->getNumArgs() == 2) {
                std::string lhs;
                std::string rhs;
                if (extractAssembledStringLiteral(OCE->getArg(0), lhs, depth + 1) &&
                    extractAssembledStringLiteral(OCE->getArg(1), rhs, depth + 1)) {
                    out = std::move(lhs);
                    if (out.size() < kMaxAssembledLen) {
                        const size_t avail = kMaxAssembledLen - out.size();
                        out.append(rhs, 0, std::min(rhs.size(), avail));
                    }
                    return true;
                }
            }
            return false;
        }

        if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(clean)) {
            if (BO->getOpcode() == clang::BO_Add) {
                std::string lhs;
                std::string rhs;
                if (extractAssembledStringLiteral(BO->getLHS(), lhs, depth + 1) &&
                    extractAssembledStringLiteral(BO->getRHS(), rhs, depth + 1)) {
                    out = std::move(lhs);
                    if (out.size() < kMaxAssembledLen) {
                        const size_t avail = kMaxAssembledLen - out.size();
                        out.append(rhs, 0, std::min(rhs.size(), avail));
                    }
                    return true;
                }
            }
            return false;
        }

        if (const clang::VarDecl *vd = extractVarDeclFromExpr(clean)) {
            const auto it = current_fn_decoded_var_strings_.find(vd);
            if (it != current_fn_decoded_var_strings_.end()) {
                out = it->second;
                return true;
            }
        }

        return false;
    }

    void RuntimeDependencyVisitor::trackStringAssemblyCall(const clang::CallExpr *CE) {
        if (!CE)
            return;
        constexpr size_t kMaxAssembledLen = 1024;

        if (const auto *OCE = llvm::dyn_cast<clang::CXXOperatorCallExpr>(CE)) {
            const auto op = OCE->getOperator();
            if ((op == clang::OO_PlusEqual || op == clang::OO_Equal) && OCE->getNumArgs() == 2) {
                const clang::VarDecl *vd = extractVarDeclFromExpr(OCE->getArg(0));
                if (vd && vd->hasLocalStorage()) {
                    std::string rhs;
                    if (extractAssembledStringLiteral(OCE->getArg(1), rhs)) {
                        if (op == clang::OO_Equal) {
                            current_fn_decoded_var_strings_[vd] = std::move(rhs);
                        } else {
                            std::string &cur = current_fn_decoded_var_strings_[vd];
                            if (cur.size() < kMaxAssembledLen) {
                                const size_t avail = kMaxAssembledLen - cur.size();
                                cur.append(rhs, 0, std::min(rhs.size(), avail));
                            }
                        }
                    }
                }
            }
            return;
        }

        if (const auto *MCE = llvm::dyn_cast<clang::CXXMemberCallExpr>(CE)) {
            if (const clang::CXXMethodDecl *MD = MCE->getMethodDecl()) {
                const std::string mname = MD->getNameAsString();
                if ((mname == "append" || mname == "assign") && MCE->getNumArgs() >= 1) {
                    bool rest_default = true;
                    for (unsigned i = 1; i < MCE->getNumArgs(); ++i) {
                        if (!llvm::isa<clang::CXXDefaultArgExpr>(MCE->getArg(i))) {
                            rest_default = false;
                            break;
                        }
                    }
                    if (rest_default) {
                        const clang::VarDecl *vd = extractVarDeclFromExpr(MCE->getImplicitObjectArgument());
                        if (vd && vd->hasLocalStorage()) {
                            std::string rhs;
                            if (extractAssembledStringLiteral(MCE->getArg(0), rhs)) {
                                if (mname == "assign") {
                                    current_fn_decoded_var_strings_[vd] = std::move(rhs);
                                } else {
                                    std::string &cur = current_fn_decoded_var_strings_[vd];
                                    if (cur.size() < kMaxAssembledLen) {
                                        const size_t avail = kMaxAssembledLen - cur.size();
                                        cur.append(rhs, 0, std::min(rhs.size(), avail));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return;
        }

        const clang::FunctionDecl *FD = CE->getDirectCallee();
        if (!FD)
            return;
        const std::string callee_name = FD->getNameAsString();
        unsigned fmt_idx = 0;
        unsigned first_arg_idx = 0;
        if (callee_name == "snprintf") {
            if (CE->getNumArgs() < 3)
                return;
            fmt_idx = 2;
            first_arg_idx = 3;
        } else if (callee_name == "sprintf") {
            if (CE->getNumArgs() < 2)
                return;
            fmt_idx = 1;
            first_arg_idx = 2;
        } else if (callee_name == "__builtin___snprintf_chk") {
            if (CE->getNumArgs() < 5)
                return;
            fmt_idx = 4;
            first_arg_idx = 5;
        } else if (callee_name == "__builtin___sprintf_chk") {
            if (CE->getNumArgs() < 4)
                return;
            fmt_idx = 3;
            first_arg_idx = 4;
        } else {
            return;
        }

        const clang::VarDecl *dst_vd = extractVarDeclFromExpr(CE->getArg(0));
        if (!dst_vd || !dst_vd->hasLocalStorage())
            return;

        std::string fmt;
        if (!extractAssembledStringLiteral(CE->getArg(fmt_idx), fmt))
            return;

        std::string assembled;
        unsigned arg_idx = first_arg_idx;
        for (size_t i = 0; i < fmt.size(); ++i) {
            if (fmt[i] != '%') {
                if (assembled.size() < kMaxAssembledLen) {
                    assembled.push_back(fmt[i]);
                }
                continue;
            }
            if (i + 1 >= fmt.size())
                return;
            if (fmt[i + 1] == '%') {
                if (assembled.size() < kMaxAssembledLen) {
                    assembled.push_back('%');
                }
                ++i;
                continue;
            }
            if (fmt[i + 1] == 's') {
                if (arg_idx >= CE->getNumArgs())
                    return;
                std::string arg_str;
                if (!extractAssembledStringLiteral(CE->getArg(arg_idx), arg_str))
                    return;
                ++arg_idx;
                if (assembled.size() < kMaxAssembledLen) {
                    const size_t avail = kMaxAssembledLen - assembled.size();
                    assembled.append(arg_str, 0, std::min(arg_str.size(), avail));
                }
                ++i;
                continue;
            }
            return;
        }
        current_fn_decoded_var_strings_[dst_vd] = std::move(assembled);
    }

    void RuntimeDependencyVisitor::collectArgLiterals(const clang::CallExpr *CE, std::vector<std::string> &out) const {
        if (!CE)
            return;
        constexpr size_t kMaxLiteralLen = 512;
        constexpr size_t kMaxLiteralsPerCall = 16;

        auto addUnique = [&](std::string_view text) {
            if (text.empty() || out.size() >= kMaxLiteralsPerCall)
                return;
            std::string clipped(text.substr(0, std::min(text.size(), kMaxLiteralLen)));
            if (std::find(out.begin(), out.end(), clipped) == out.end()) {
                out.push_back(std::move(clipped));
            }
        };

        for (const clang::Expr *arg : CE->arguments()) {
            if (!arg)
                continue;
            std::string assembled;
            if (extractAssembledStringLiteral(arg, assembled)) {
                addUnique(assembled);
            }
        }
    }

    void RuntimeDependencyVisitor::emitVirtualOverrideCalls(const clang::CXXMemberCallExpr *MCE,
                                                            clang::SourceLocation call_loc) {
        if (!MCE || !collector_)
            return;
        const clang::CXXMethodDecl *MD = MCE->getMethodDecl();
        if (!MD || !MD->isVirtual())
            return;

        const clang::CXXMethodDecl *canon_base = MD->getCanonicalDecl();
        const auto it = virtual_overrides_.find(canon_base);
        if (it == virtual_overrides_.end())
            return;

        for (const clang::CXXMethodDecl *override_md : it->second) {
            if (!override_md)
                continue;
            if (override_md == canon_base && MD->hasBody())
                continue;

            CallPatternRecord rec;
            rec.caller_function = current_caller_;
            rec.symbol = override_md->getQualifiedNameAsString();
            const std::string mangled = mangleDeclName(override_md);
            rec.mangled_symbol = mangled.empty() ? rec.symbol : mangled;
            rec.library = "intra-tu";
            rec.category = "IntraTU";
            rec.kind = "virtual_override_call";
            rec.return_type = override_md->getReturnType().getAsString();
            rec.is_variadic = override_md->isVariadic();
            for (const clang::ParmVarDecl *param : override_md->parameters()) {
                rec.param_types.push_back(param->getType().getAsString());
            }
            collectArgLiterals(MCE, rec.arg_literals);
            rec.behavior_category = "Benign";
            rec.risk_score = 0;
            rec.is_intra_tu_call = true;
            rec.is_auto_init_entrypoint = current_is_auto_init_;
            rec.entrypoint_kind = current_entrypoint_kind_;
            fillPresumedLocation(call_loc, rec.source_file, rec.line, rec.column);
            collector_->add(std::move(rec));
        }
    }

    void RuntimeDependencyVisitor::collectBehaviorArgFeatures(const clang::CallExpr *CE,
                                                              const ExtractedCallTelemetry *arg_telemetry,
                                                              BehaviorFeatures &features) const {
        if (arg_telemetry) {
            features.max_arg_entropy = arg_telemetry->max_arg_entropy;
            for (const auto &ae : arg_telemetry->arg_entropies) {
                features.arg_entropies.push_back(ae.shannon_entropy);
                if (ae.is_high_entropy) {
                    features.has_high_entropy_literal = true;
                }
            }
            for (const auto &bm : arg_telemetry->arg_bitmasks) {
                features.numeric_constants.push_back(bm.value);
            }
        }
        if (CE) {
            for (const clang::Expr *arg : CE->arguments()) {
                if (!arg)
                    continue;
                if (const auto *SL = llvm::dyn_cast<clang::StringLiteral>(arg->IgnoreParenImpCasts())) {
                    if (SL->isOrdinary() || SL->isUTF8()) {
                        features.string_literals.push_back(SL->getString().str());
                    }
                }
            }
        }
        if (current_fn_has_stack_string_) {
            features.has_stack_string = true;
            features.reconstructed_stack_strings = current_fn_stack_strings_;
            for (const auto &s : current_fn_stack_strings_) {
                if (std::find(features.string_literals.begin(), features.string_literals.end(), s) ==
                    features.string_literals.end()) {
                    features.string_literals.push_back(s);
                }
            }
        }
        if (current_fn_has_cff_) {
            features.has_cff_dispatcher = true;
        }
    }

    void RuntimeDependencyVisitor::classifyAndPopulateRecord(CallPatternRecord &rec,
                                                             const BehaviorFeatures &features) const {
        BehaviorAssessment assessment = BehaviorClassifier::classify(features);
        rec.behavior_category = getBehaviorCategoryName(assessment.primary_category);
        rec.behavior_tags = std::move(assessment.tags);
        rec.risk_score = assessment.risk_score;
        rec.arg_entropy = features.max_arg_entropy;
        rec.has_high_entropy_literal = features.has_high_entropy_literal;
        rec.is_indirect_call =
            (features.call_kind == "indirect" || features.call_kind == "fn_ptr_cast" || features.resolved_from_symbol);
        rec.is_inline_asm = (features.call_kind == "inline_asm");
        rec.behavior_rationale = std::move(assessment.rationale);
        rec.is_auto_init_entrypoint = features.is_auto_init_entrypoint;
        rec.entrypoint_kind = features.entrypoint_kind;
    }

    void RuntimeDependencyVisitor::inspectFunction(const clang::FunctionDecl *FD, clang::SourceLocation call_loc,
                                                   const char *usage_type, const clang::CallExpr *call_expr,
                                                   const clang::CXXConstructExpr *ctor_expr,
                                                   const ExtractedCallTelemetry *arg_telemetry) {
        std::string header_filename;
        const bool in_system = findSystemHeaderDecl(FD, header_filename);
        const bool is_builtin = (FD->getBuiltinID() != 0);

        // Internal project function defined in user code (not a system header, not a builtin)
        if (!in_system && !is_builtin && FD->hasBody()) {
            if (collector_ && call_expr) {
                CallPatternRecord rec;
                rec.caller_function = current_caller_;
                rec.symbol = FD->getNameAsString();
                const std::string mangled = mangleDeclName(FD);
                rec.mangled_symbol = mangled.empty() ? rec.symbol : mangled;
                rec.library = "intra-tu";
                rec.category = "IntraTU";
                rec.kind = "intra_tu_call";
                rec.return_type = FD->getReturnType().getAsString();
                rec.is_variadic = FD->isVariadic();
                for (const clang::ParmVarDecl *param : FD->parameters()) {
                    rec.param_types.push_back(param->getType().getAsString());
                }
                collectArgLiterals(call_expr, rec.arg_literals);
                rec.behavior_category = "Benign";
                rec.risk_score = 0;
                const FunctionTaintSummary *callee_sum = summary_table_.findSummary(FD->getQualifiedNameAsString());
                if (!callee_sum) {
                    callee_sum = summary_table_.findSummary(FD->getNameAsString());
                }
                if (callee_sum) {
                    for (const uint32_t sink_idx : callee_sum->param_sinks) {
                        if (sink_idx < call_expr->getNumArgs()) {
                            if (const uintptr_t arg_key = resolveTaintKey(call_expr->getArg(sink_idx))) {
                                if (taint_tracker_.isTainted(arg_key)) {
                                    rec.behavior_tags.push_back("tainted_buffer_exec_flow");
                                    rec.risk_score = 35;
                                    break;
                                }
                            }
                        }
                    }
                }
                rec.is_intra_tu_call = true;
                rec.is_auto_init_entrypoint = current_is_auto_init_;
                rec.entrypoint_kind = current_entrypoint_kind_;
                fillPresumedLocation(call_loc, rec.source_file, rec.line, rec.column);
                collector_->add(std::move(rec));
            }
            return;
        }

        if (header_filename.empty() && FD->getLocation().isValid()) {
            header_filename = sm_.getFilename(FD->getLocation()).str();
        }

        const std::string name = FD->getNameAsString();
        const std::string mangled = mangleDeclName(FD);

        // 1. Dynamic library export resolution (unmangled first, then mangled C++ ABI name)
        auto &registry = DynamicSymbolRegistry::instance();
        std::string resolved_lib_name;
        auto dyn_match = registry.findLibraryForSymbol(name);
        if (dyn_match.empty() && !mangled.empty()) {
            dyn_match = registry.findLibraryForSymbol(mangled);
        }
        if (!dyn_match.empty()) {
            resolved_lib_name = std::string(dyn_match);
        }

        // 2. Physical header path metadata (zero hardcoded library names)
        HeaderPathInfo header_info{};
        if (!header_filename.empty()) {
            header_info = classifyHeaderPath(header_filename, platform_);
        }

        // 3. Remote / manifest resolver fallback if still unresolved
        if (resolved_lib_name.empty()) {
            auto remote_match = RemoteSymbolResolver::instance().lookup(name);
            if (!remote_match.empty()) {
                resolved_lib_name = std::string(remote_match);
            }
        }

        const bool is_external_dependency = in_system || is_builtin || !FD->hasBody() || !resolved_lib_name.empty();

        if (!is_external_dependency) {
            return;
        }

        if (resolved_lib_name.empty()) {
            if (is_builtin) {
                resolved_lib_name = "compiler-builtin";
            } else if (FD->hasBody() && !header_info.module_hint.empty()) {
                resolved_lib_name = "header-inline (" + header_info.module_hint + ")";
            } else if (!header_filename.empty()) {
                resolved_lib_name = header_filename;
            } else {
                resolved_lib_name = "unresolved external symbol";
            }
        }

        const std::string category =
            is_builtin ? "CompilerBuiltin"
                       : (!header_info.module_hint.empty() ? header_info.module_hint : "ExternalSymbol");

        if (collector_) {
            CallPatternRecord rec;
            rec.caller_function = current_caller_;
            rec.symbol = name;
            rec.mangled_symbol = mangled.empty() ? name : mangled;
            rec.library = resolved_lib_name;
            rec.category = category;
            rec.kind = usage_type ? usage_type : "call";
            rec.return_type = FD->getReturnType().getAsString();
            rec.is_variadic = FD->isVariadic();
            for (const clang::ParmVarDecl *param : FD->parameters()) {
                rec.param_types.push_back(param->getType().getAsString());
            }

            bool all_const = true;
            if (call_expr) {
                for (const clang::Expr *arg : call_expr->arguments()) {
                    bool arg_const = false;
                    rec.arg_shapes.push_back(classifyArgShape(arg, arg_const));
                    all_const = all_const && arg_const;
                }
                collectArgLiterals(call_expr, rec.arg_literals);
            } else if (ctor_expr) {
                for (const clang::Expr *arg : ctor_expr->arguments()) {
                    bool arg_const = false;
                    rec.arg_shapes.push_back(classifyArgShape(arg, arg_const));
                    all_const = all_const && arg_const;
                }
            } else {
                all_const = false;
            }
            rec.all_args_constant = all_const && !rec.arg_shapes.empty();

            fillPresumedLocation(call_loc, rec.source_file, rec.line, rec.column);

            BehaviorFeatures features;
            features.target_os = HeaderClassifier::platformToTargetOS(platform_);
            if (rec.kind == "operator new") {
                features.call_kind = "new";
            } else if (rec.kind == "operator delete") {
                features.call_kind = "delete";
            } else if (rec.kind == "constructor") {
                features.call_kind = "construct";
            } else {
                features.call_kind = "direct";
            }
            features.return_type = rec.return_type;
            features.param_types = rec.param_types;
            features.arg_shapes = rec.arg_shapes;
            features.is_variadic = rec.is_variadic;
            features.is_system_header = in_system;
            features.inside_loop = (loop_depth_ > 0);
            features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
            features.has_crypto_or_hash_constant = current_fn_has_crypto_hash_;
            features.crypto_hash_tags = current_fn_crypto_hash_tags_;
            features.is_auto_init_entrypoint = current_is_auto_init_;
            features.entrypoint_kind = current_entrypoint_kind_;
            features.caller_function = current_caller_;
            collectBehaviorArgFeatures(call_expr, arg_telemetry, features);
            const BehaviorAssessment pre = BehaviorClassifier::classify(features);
            applyTaintExecCheck(call_expr, pre.primary_category, name, features);
            classifyAndPopulateRecord(rec, features);

            collector_->add(std::move(rec));
        }

        reportExternal(name, usage_type, category, resolved_lib_name,
                       header_filename.empty() ? std::string_view("built-in/extern")
                                               : std::string_view(header_filename),
                       is_builtin, call_loc);
    }

    void RuntimeDependencyVisitor::fillPresumedLocation(clang::SourceLocation loc, std::string &file, unsigned &line,
                                                        unsigned &column) const {
        const clang::PresumedLoc ploc = sm_.getPresumedLoc(loc);
        if (ploc.isValid()) {
            file = ploc.getFilename() ? ploc.getFilename() : "";
            line = ploc.getLine();
            column = ploc.getColumn();
        }
    }

    bool RuntimeDependencyVisitor::extractResolverInfo(const clang::CallExpr *call, LocalPtrOrigin &out) const {
        if (!call)
            return false;
        if (const clang::FunctionDecl *callee_fd = call->getDirectCallee()) {
            out.resolver_symbol = callee_fd->getNameAsString();
        } else if (const clang::Expr *callee_expr = call->getCallee()) {
            const clang::Expr *stripped = callee_expr->IgnoreParenCasts();
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(stripped)) {
                out.resolver_symbol = DRE->getNameInfo().getAsString();
            } else if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(stripped)) {
                out.resolver_symbol = ME->getMemberDecl() ? ME->getMemberDecl()->getNameAsString() : "<member>";
            }
        }
        if (out.resolver_symbol.empty()) {
            return false;
        }

        for (const clang::Expr *arg : call->arguments()) {
            if (!arg)
                continue;
            if (const auto *SL = llvm::dyn_cast<clang::StringLiteral>(arg->IgnoreParenImpCasts())) {
                out.target_hint = SL->getString().str();
                break;
            }
        }
        const clang::QualType ret_ty = call->getType();
        const bool opaque_ret =
            ret_ty->isVoidPointerType() || ret_ty.getAsString() == "FARPROC" || ret_ty.getAsString() == "PROC";
        if (!opaque_ret && out.target_hint.empty()) {
            return false;
        }
        return true;
    }

    void RuntimeDependencyVisitor::trackPointerOriginFromExpr(const clang::VarDecl *target_var, const clang::Expr *rhs,
                                                              clang::SourceLocation loc) {
        if (!target_var || !rhs)
            return;
        const clang::Expr *stripped = rhs->IgnoreParenCasts();

        if (const auto *call = llvm::dyn_cast<clang::CallExpr>(stripped)) {
            LocalPtrOrigin origin;
            if (extractResolverInfo(call, origin)) {
                const clang::PresumedLoc ploc = sm_.getPresumedLoc(loc);
                origin.resolved_line = ploc.isValid() ? ploc.getLine() : 0;
                local_ptr_origins_[target_var] = std::move(origin);
            }
            return;
        }

        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(stripped)) {
            if (const auto *src_var = llvm::dyn_cast_or_null<clang::VarDecl>(DRE->getDecl())) {
                const auto it = local_ptr_origins_.find(src_var);
                if (it != local_ptr_origins_.end()) {
                    local_ptr_origins_[target_var] = it->second;
                }
            }
            return;
        }

        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(stripped)) {
            if (const auto *field = llvm::dyn_cast_or_null<clang::FieldDecl>(ME->getMemberDecl())) {
                const auto it = captured_field_origins_.find(field);
                if (it != captured_field_origins_.end()) {
                    local_ptr_origins_[target_var] = it->second;
                }
            }
        }
    }

    BehaviorCategory RuntimeDependencyVisitor::classifyCallExprCategory(const clang::CallExpr *CE,
                                                                        std::string *out_symbol) const {
        if (!CE)
            return BehaviorCategory::Benign;
        const clang::FunctionDecl *FD = CE->getDirectCallee();
        if (!FD)
            return BehaviorCategory::Benign;

        const std::string sym = FD->getNameAsString();
        if (out_symbol) {
            *out_symbol = sym;
        }

        BehaviorFeatures features;
        features.target_os = HeaderClassifier::platformToTargetOS(platform_);
        features.call_kind = "direct";
        features.return_type = FD->getReturnType().getAsString();
        features.is_variadic = FD->isVariadic();
        features.is_system_header = FD->getLocation().isValid() && sm_.isInSystemHeader(FD->getLocation());
        features.inside_loop = (loop_depth_ > 0);
        features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
        features.caller_function = current_caller_;
        for (const clang::ParmVarDecl *param : FD->parameters()) {
            features.param_types.push_back(param->getType().getAsString());
        }
        for (const clang::Expr *arg : CE->arguments()) {
            bool is_const = false;
            features.arg_shapes.push_back(classifyArgShape(arg, is_const));
        }

        ExtractedCallTelemetry tel;
        collectCallArgumentTelemetry(CE, tel);
        collectBehaviorArgFeatures(CE, &tel, features);
        return BehaviorClassifier::classify(features).primary_category;
    }

    uintptr_t RuntimeDependencyVisitor::resolveTaintKey(const clang::Expr *expr) const {
        const clang::Expr *clean = stripTaintExpr(expr);
        if (!clean)
            return 0;
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(clean)) {
            if (const auto *VD = llvm::dyn_cast_or_null<clang::VarDecl>(DRE->getDecl())) {
                return TaintTracker::toKey(VD);
            }
            return 0;
        }
        const std::string key = extractExprTaintKey(clean);
        if (key.empty())
            return 0;
        auto [it, inserted] = synthetic_taint_keys_.emplace(key, 0);
        if (inserted) {
            it->second = (next_synthetic_taint_key_ << 1) | 1ULL;
            ++next_synthetic_taint_key_;
        }
        return it->second;
    }

    uint32_t RuntimeDependencyVisitor::getExprParamFlowMask(const clang::Expr *expr) const {
        if (!expr)
            return 0;
        const clang::Expr *clean = expr->IgnoreParenCasts();
        if (const uintptr_t key = resolveTaintKey(clean)) {
            const auto it = current_fn_param_flow_.find(key);
            return (it != current_fn_param_flow_.end()) ? it->second : 0;
        }
        if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(clean)) {
            return getExprParamFlowMask(BO->getLHS()) | getExprParamFlowMask(BO->getRHS());
        }
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(clean)) {
            return getExprParamFlowMask(UO->getSubExpr());
        }
        return 0;
    }

    void RuntimeDependencyVisitor::recordParamSinkMask(uint32_t param_mask) {
        for (uint32_t bit = 0; bit < 32; ++bit) {
            if ((param_mask & (1u << bit)) != 0 &&
                std::find(current_fn_summary_.param_sinks.begin(), current_fn_summary_.param_sinks.end(), bit) ==
                    current_fn_summary_.param_sinks.end()) {
                current_fn_summary_.param_sinks.push_back(bit);
            }
        }
    }

    void RuntimeDependencyVisitor::recordParamToParamFlow(uint32_t src_param_mask, uint32_t dst_param_idx) {
        for (uint32_t bit = 0; bit < 32; ++bit) {
            if ((src_param_mask & (1u << bit)) != 0) {
                const std::pair<uint32_t, uint32_t> edge(bit, dst_param_idx);
                if (std::find(current_fn_summary_.param_to_param.begin(), current_fn_summary_.param_to_param.end(),
                              edge) == current_fn_summary_.param_to_param.end()) {
                    current_fn_summary_.param_to_param.push_back(edge);
                }
            }
        }
    }

    void RuntimeDependencyVisitor::applyInterproceduralCallSummary(const clang::FunctionDecl *FD,
                                                                   const clang::CallExpr *CE, CallPatternRecord *) {
        if (!FD || !CE)
            return;
        const FunctionTaintSummary *summary = summary_table_.findSummary(FD->getQualifiedNameAsString());
        if (!summary) {
            summary = summary_table_.findSummary(FD->getNameAsString());
        }
        if (!summary)
            return;

        for (const auto &[src_idx, dst_idx] : summary->param_to_param) {
            if (src_idx < CE->getNumArgs() && dst_idx < CE->getNumArgs()) {
                const uintptr_t src_key = resolveTaintKey(CE->getArg(src_idx));
                const uintptr_t dst_key = resolveTaintKey(CE->getArg(dst_idx));
                if (src_key != 0 && dst_key != 0) {
                    taint_tracker_.assignAlias(dst_key, src_key, FD->getNameAsString());
                    const uint32_t src_mask = getExprParamFlowMask(CE->getArg(src_idx));
                    if (src_mask != 0) {
                        current_fn_param_flow_[dst_key] |= src_mask;
                    }
                }
            }
        }

        for (const uint32_t sink_idx : summary->param_sinks) {
            if (sink_idx < CE->getNumArgs()) {
                if (const uintptr_t arg_key = resolveTaintKey(CE->getArg(sink_idx))) {
                    if (taint_tracker_.isTainted(arg_key)) {
                        taint_tracker_.addTaint(arg_key, TaintKind::ExecProtect, FD->getNameAsString());
                    }
                    const uint32_t arg_mask = getExprParamFlowMask(CE->getArg(sink_idx));
                    if (arg_mask != 0) {
                        recordParamSinkMask(arg_mask);
                    }
                }
            }
        }
    }

    void RuntimeDependencyVisitor::updateTaintFromAssignment(const clang::VarDecl *target_var, const clang::Expr *rhs) {
        if (!target_var)
            return;
        updateTaintFromAssignment(TaintTracker::toKey(target_var), target_var->getNameAsString(), rhs);
    }

    void RuntimeDependencyVisitor::updateTaintFromAssignment(uintptr_t dst_key, std::string_view dst_name,
                                                             const clang::Expr *rhs) {
        if (dst_key == 0 || !rhs)
            return;
        const clang::Expr *stripped = rhs->IgnoreParenCasts();

        if (const auto *call = llvm::dyn_cast<clang::CallExpr>(stripped)) {
            std::string sym;
            const BehaviorCategory cat = classifyCallExprCategory(call, &sym);
            if (cat == BehaviorCategory::MemoryAllocation) {
                taint_tracker_.addTaint(dst_key, TaintKind::MemoryAlloc, sym);
            } else if (cat == BehaviorCategory::DynamicResolution) {
                taint_tracker_.addTaint(dst_key, TaintKind::DynamicResolve, sym);
            }

            if (const clang::FunctionDecl *callee = call->getDirectCallee()) {
                const FunctionTaintSummary *summary = summary_table_.findSummary(callee->getQualifiedNameAsString());
                if (!summary) {
                    summary = summary_table_.findSummary(callee->getNameAsString());
                }
                if (summary) {
                    const std::string &origin =
                        summary->origin_symbol.empty() ? callee->getNameAsString() : summary->origin_symbol;
                    static constexpr TaintKind kAllKinds[] = {
                        TaintKind::MemoryAlloc, TaintKind::DynamicResolve, TaintKind::HighEntropyBlob,
                        TaintKind::StackString, TaintKind::ExecProtect,
                    };
                    for (const TaintKind k : kAllKinds) {
                        if ((summary->return_taint_mask & static_cast<uint32_t>(k)) != 0) {
                            taint_tracker_.addTaint(dst_key, k, origin);
                        }
                    }
                    for (const uint32_t p_idx : summary->param_to_return) {
                        if (p_idx < call->getNumArgs()) {
                            if (const uintptr_t arg_key = resolveTaintKey(call->getArg(p_idx))) {
                                taint_tracker_.assignAlias(dst_key, arg_key, callee->getNameAsString());
                            }
                            const uint32_t arg_mask = getExprParamFlowMask(call->getArg(p_idx));
                            if (arg_mask != 0) {
                                current_fn_param_flow_[dst_key] |= arg_mask;
                            }
                        }
                    }
                }
            }
            return;
        }

        if (const uintptr_t src_key = resolveTaintKey(stripped)) {
            taint_tracker_.assignAlias(dst_key, src_key, dst_name);
            const auto p_it = current_fn_param_flow_.find(src_key);
            if (p_it != current_fn_param_flow_.end()) {
                current_fn_param_flow_[dst_key] |= p_it->second;
            }
            return;
        }

        if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(stripped)) {
            const uintptr_t lhs_key = resolveTaintKey(BO->getLHS());
            const uintptr_t rhs_key = resolveTaintKey(BO->getRHS());
            taint_tracker_.propagateBinary(dst_key, lhs_key, rhs_key, dst_name);
            const uint32_t combined_mask = getExprParamFlowMask(BO->getLHS()) | getExprParamFlowMask(BO->getRHS());
            if (combined_mask != 0) {
                current_fn_param_flow_[dst_key] |= combined_mask;
            }
        }
    }

    void RuntimeDependencyVisitor::propagateMemCopyTaint(const clang::FunctionDecl *FD, const clang::CallExpr *CE) {
        if (!FD || !CE || CE->getNumArgs() < 2 || CE->getNumArgs() > 3)
            return;
        if (FD->getNumParams() < 2 || FD->getNumParams() > 3)
            return;

        const clang::QualType p0 = FD->getParamDecl(0)->getType();
        const clang::QualType p1 = FD->getParamDecl(1)->getType();
        if (!p0->isPointerType() || !p1->isPointerType())
            return;
        if (p0->getPointeeType().isConstQualified())
            return;
        if (FD->getNumParams() == 3 && !FD->getParamDecl(2)->getType()->isIntegerType())
            return;

        const std::string name = FD->getNameAsString();
        const bool known_copy_name = name == "memcpy" || name == "memmove" || name == "wmemcpy" || name == "wmemmove" ||
                                     name == "strcpy" || name == "strncpy" || name == "RtlCopyMemory" ||
                                     name == "RtlMoveMemory" || name == "CopyMemory" || name == "__builtin_memcpy" ||
                                     name == "__builtin_memmove";
        const bool structural_void_copy =
            p0->isVoidPointerType() && p1->isVoidPointerType() && p1->getPointeeType().isConstQualified();

        if (!known_copy_name && !structural_void_copy)
            return;

        const uintptr_t dst_key = resolveTaintKey(CE->getArg(0));
        const uintptr_t src_key = resolveTaintKey(CE->getArg(1));
        if (dst_key != 0 && src_key != 0) {
            taint_tracker_.propagateBinary(dst_key, src_key, 0, name);
            const uint32_t src_mask = getExprParamFlowMask(CE->getArg(1));
            if (src_mask != 0) {
                current_fn_param_flow_[dst_key] |= src_mask;
                if (const clang::VarDecl *dst_var = extractVarDeclFromExpr(CE->getArg(0))) {
                    if (const auto *dst_pvd = llvm::dyn_cast<clang::ParmVarDecl>(dst_var)) {
                        const auto p_it = current_fn_param_indices_.find(dst_pvd);
                        if (p_it != current_fn_param_indices_.end()) {
                            recordParamToParamFlow(src_mask, p_it->second);
                        }
                    }
                }
            }
        }
    }

    void RuntimeDependencyVisitor::applyTaintExecCheck(const clang::CallExpr *CE, BehaviorCategory cat,
                                                       std::string_view sym, BehaviorFeatures &features) {
        if (!CE)
            return;
        if (cat != BehaviorCategory::MemoryProtection && cat != BehaviorCategory::IndirectCall &&
            cat != BehaviorCategory::ProcessThreadOp) {
            return;
        }

        auto checkKey = [&](uintptr_t key) {
            if (key == 0)
                return;
            if (taint_tracker_.hasTaintedExecFlow(key) || taint_tracker_.hasTaint(key, TaintKind::MemoryAlloc) ||
                taint_tracker_.hasTaint(key, TaintKind::HighEntropyBlob)) {
                features.has_tainted_exec_flow = true;
            }
            if (cat == BehaviorCategory::MemoryProtection) {
                taint_tracker_.addTaint(key, TaintKind::ExecProtect, sym);
            }
            const auto p_it = current_fn_param_flow_.find(key);
            if (p_it != current_fn_param_flow_.end()) {
                recordParamSinkMask(p_it->second);
            }
        };

        if (cat == BehaviorCategory::IndirectCall) {
            checkKey(resolveTaintKey(CE->getCallee()));
        }
        for (const clang::Expr *arg : CE->arguments()) {
            checkKey(resolveTaintKey(arg));
        }
    }

    bool RuntimeDependencyVisitor::extractBytesFromInitList(const clang::InitListExpr *ILE,
                                                            std::vector<uint8_t> &out_bytes) const {
        if (!ILE || ILE->getNumInits() == 0)
            return false;
        const clang::ASTContext &ctx = ci_.getASTContext();
        out_bytes.clear();
        out_bytes.reserve(ILE->getNumInits());

        for (const clang::Expr *elem : ILE->inits()) {
            if (!elem)
                continue;
            const clang::Expr *clean = elem->IgnoreParenImpCasts();
            if (clean->isValueDependent() || clean->isTypeDependent() || !clean->getType()->isIntegerType()) {
                out_bytes.clear();
                return false;
            }
            clang::Expr::EvalResult eval_res;
            if (!clean->EvaluateAsInt(eval_res, ctx)) {
                out_bytes.clear();
                return false;
            }
            const uint64_t val = eval_res.Val.getInt().getZExtValue();
            if (val > 0xFF) {
                out_bytes.clear();
                return false;
            }
            out_bytes.push_back(static_cast<uint8_t>(val));
        }
        return !out_bytes.empty();
    }

    void RuntimeDependencyVisitor::collectCallArgumentTelemetry(const clang::CallExpr *CE,
                                                                ExtractedCallTelemetry &out) const {
        if (!CE)
            return;
        const clang::ASTContext &ctx = ci_.getASTContext();

        unsigned idx = 0;
        for (const clang::Expr *arg : CE->arguments()) {
            if (!arg) {
                ++idx;
                continue;
            }
            const clang::Expr *clean = arg->IgnoreParenImpCasts();

            if (const auto *SL = llvm::dyn_cast<clang::StringLiteral>(clean)) {
                const llvm::StringRef bytes = SL->getBytes();
                const std::string_view sv(bytes.data(), bytes.size());
                ArgEntropyInfo info;
                info.arg_index = idx;
                info.byte_length = sv.size();
                info.shannon_entropy = EntropyAnalyzer::computeShannonEntropy(sv);
                info.is_high_entropy = EntropyAnalyzer::isHighEntropyString(sv);
                info.is_byte_array = false;
                out.max_arg_entropy = std::max(out.max_arg_entropy, info.shannon_entropy);
                out.arg_entropies.push_back(info);
            } else {
                const clang::InitListExpr *ILE = llvm::dyn_cast<clang::InitListExpr>(clean);
                if (!ILE) {
                    if (const auto *CLE = llvm::dyn_cast<clang::CompoundLiteralExpr>(clean)) {
                        ILE = llvm::dyn_cast_or_null<clang::InitListExpr>(
                            CLE->getInitializer() ? CLE->getInitializer()->IgnoreParenImpCasts() : nullptr);
                    }
                }
                if (ILE) {
                    std::vector<uint8_t> bytes;
                    if (extractBytesFromInitList(ILE, bytes)) {
                        ArgEntropyInfo info;
                        info.arg_index = idx;
                        info.byte_length = bytes.size();
                        info.shannon_entropy = EntropyAnalyzer::computeByteEntropy(bytes.data(), bytes.size());
                        info.is_high_entropy = EntropyAnalyzer::isLikelyEncryptedOrPacked(bytes.data(), bytes.size());
                        info.is_byte_array = true;
                        out.max_arg_entropy = std::max(out.max_arg_entropy, info.shannon_entropy);
                        out.arg_entropies.push_back(info);
                    }
                }
            }

            if (isInspectableBitmaskExpr(clean)) {
                clang::Expr::EvalResult eval_res;
                if (clean->EvaluateAsInt(eval_res, ctx)) {
                    ArgBitmaskInfo binfo;
                    binfo.arg_index = idx;
                    binfo.value = eval_res.Val.getInt().getZExtValue();
                    collectOrComponents(clean, ctx, binfo.or_components, binfo.is_or_expression);
                    out.arg_bitmasks.push_back(std::move(binfo));
                }
            }

            ++idx;
        }
    }

    void RuntimeDependencyVisitor::inspectIndirectCall(const clang::CallExpr *CE, clang::SourceLocation call_loc) {
        if (!CE)
            return;
        ExtractedCallTelemetry tel;
        tel.caller_function = current_caller_;
        tel.is_indirect = true;
        tel.is_auto_init_entrypoint = current_is_auto_init_;
        tel.entrypoint_kind = current_entrypoint_kind_;
        fillPresumedLocation(call_loc, tel.source_file, tel.line, tel.column);

        const clang::Expr *callee = CE->getCallee();
        const clang::Expr *walk = callee;
        while (walk) {
            walk = walk->IgnoreParens();
            if (const auto *cast = llvm::dyn_cast<clang::CastExpr>(walk)) {
                if (!llvm::isa<clang::ImplicitCastExpr>(cast) &&
                    (cast->getType()->isFunctionPointerType() || cast->getType()->isMemberFunctionPointerType())) {
                    tel.has_fn_ptr_cast = true;
                    tel.cast_kind = classifyExplicitCastKind(cast);
                    break;
                }
                walk = cast->getSubExpr();
            } else {
                break;
            }
        }

        const clang::Expr *stripped = callee ? callee->IgnoreParenCasts() : nullptr;
        if (const auto *DRE = llvm::dyn_cast_or_null<clang::DeclRefExpr>(stripped)) {
            if (const auto *VD = llvm::dyn_cast_or_null<clang::VarDecl>(DRE->getDecl())) {
                tel.symbol = VD->getNameAsString();
                const auto it = local_ptr_origins_.find(VD);
                if (it != local_ptr_origins_.end()) {
                    tel.indirect_kind = "local_var_resolved";
                    tel.resolver_symbol = it->second.resolver_symbol;
                    tel.resolved_target_hint = it->second.target_hint;
                } else {
                    tel.indirect_kind = VD->hasLocalStorage() ? "local_var" : "global_var";
                }
            } else {
                tel.symbol = DRE->getNameInfo().getAsString();
                tel.indirect_kind = "decl_ref";
            }
        } else if (const auto *ME = llvm::dyn_cast_or_null<clang::MemberExpr>(stripped)) {
            tel.symbol = ME->getMemberDecl() ? ME->getMemberDecl()->getNameAsString() : "<member>";
            if (const auto *field = llvm::dyn_cast_or_null<clang::FieldDecl>(ME->getMemberDecl())) {
                const auto it = captured_field_origins_.find(field);
                if (it != captured_field_origins_.end()) {
                    tel.indirect_kind = "lambda_capture_resolved";
                    tel.resolver_symbol = it->second.resolver_symbol;
                    tel.resolved_target_hint = it->second.target_hint;
                } else {
                    tel.indirect_kind = "member_expr";
                }
            } else {
                tel.indirect_kind = "member_expr";
            }
        } else if (const auto *inner_call = llvm::dyn_cast_or_null<clang::CallExpr>(stripped)) {
            tel.indirect_kind = "call_result";
            LocalPtrOrigin origin;
            if (extractResolverInfo(inner_call, origin)) {
                tel.resolver_symbol = origin.resolver_symbol;
                tel.resolved_target_hint = origin.target_hint;
                tel.symbol = origin.resolver_symbol;
            } else {
                tel.symbol = "<call_result>";
            }
        } else if (llvm::isa_and_nonnull<clang::IntegerLiteral>(stripped)) {
            tel.indirect_kind = "hardcoded_addr";
            tel.symbol = "<int_addr>";
        } else if (llvm::isa_and_nonnull<clang::ArraySubscriptExpr>(stripped)) {
            tel.indirect_kind = "subscript";
            tel.symbol = "<table_entry>";
        } else {
            tel.indirect_kind = "expr";
            tel.symbol = callee ? callee->getType().getAsString() : "<indirect>";
        }

        collectCallArgumentTelemetry(CE, tel);

        if (collector_) {
            CallPatternRecord pat;
            pat.caller_function = current_caller_;
            pat.symbol = tel.symbol;
            pat.mangled_symbol = tel.symbol;
            pat.library = tel.resolver_symbol.empty() ? "indirect-call" : ("dynamic:" + tel.resolver_symbol);
            pat.category = "IndirectCall";
            pat.kind = "indirect";
            pat.return_type = CE->getType().getAsString();
            bool all_const = true;
            for (const clang::Expr *arg : CE->arguments()) {
                bool arg_const = false;
                pat.arg_shapes.push_back(classifyArgShape(arg, arg_const));
                all_const = all_const && arg_const;
            }
            collectArgLiterals(CE, pat.arg_literals);
            pat.all_args_constant = all_const && !pat.arg_shapes.empty();
            pat.source_file = tel.source_file;
            pat.line = tel.line;
            pat.column = tel.column;
            if (!tel.resolver_symbol.empty()) {
                pat.resolved_from_symbol = tel.resolved_target_hint.empty()
                                               ? tel.resolver_symbol
                                               : (tel.resolver_symbol + ":" + tel.resolved_target_hint);
            }

            BehaviorFeatures features;
            features.target_os = HeaderClassifier::platformToTargetOS(platform_);
            features.call_kind = "indirect";
            features.return_type = pat.return_type;
            features.arg_shapes = pat.arg_shapes;
            features.resolved_from_symbol = !pat.resolved_from_symbol.empty();
            features.inside_loop = (loop_depth_ > 0);
            features.has_bitwise_xor_loop = current_fn_has_xor_loop_;
            features.has_crypto_or_hash_constant = current_fn_has_crypto_hash_;
            features.crypto_hash_tags = current_fn_crypto_hash_tags_;
            features.is_auto_init_entrypoint = current_is_auto_init_;
            features.entrypoint_kind = current_entrypoint_kind_;
            features.caller_function = current_caller_;
            collectBehaviorArgFeatures(CE, &tel, features);
            applyTaintExecCheck(CE, BehaviorCategory::IndirectCall, tel.symbol, features);
            classifyAndPopulateRecord(pat, features);

            collector_->add(std::move(pat));
        }

        extracted_telemetry_.push_back(std::move(tel));
    }

    void RuntimeDependencyVisitor::handleLockAcquisition(const std::string &lock_name, clang::SourceLocation loc) {
        if (!held_locks_.empty()) {
            const std::string &prev = held_locks_.back();
            if (prev != lock_name && collector_) {
                CallPatternRecord pat;
                pat.caller_function = current_caller_;
                pat.symbol = lock_name;
                pat.mangled_symbol = lock_name;
                pat.library = "concurrency";
                pat.category = "LockOrder";
                pat.kind = "lock_acquire";
                pat.behavior_category = "Concurrency";
                pat.behavior_tags.push_back("lock_acquire");
                setLockFieldsIfPresent(pat, lock_name, prev);
                pat.is_auto_init_entrypoint = current_is_auto_init_;
                pat.entrypoint_kind = current_entrypoint_kind_;
                fillPresumedLocation(loc, pat.source_file, pat.line, pat.column);
                collector_->add(std::move(pat));
            }
        }
        held_locks_.push_back(lock_name);
    }

    void RuntimeDependencyVisitor::handleLockRelease(const std::string &lock_name) {
        for (auto it = held_locks_.rbegin(); it != held_locks_.rend(); ++it) {
            if (*it == lock_name) {
                held_locks_.erase(std::next(it).base());
                break;
            }
        }
    }

    void RuntimeDependencyVisitor::emitLifetimeRecord(std::string_view kind, std::string_view lifetime_kind,
                                                      std::string_view tag, std::string_view symbol,
                                                      uint32_t risk_score, clang::SourceLocation loc,
                                                      std::string_view ret_type) {
        if (!collector_)
            return;
        CallPatternRecord pat;
        pat.caller_function = current_caller_;
        pat.symbol = std::string(symbol);
        pat.mangled_symbol = pat.symbol;
        pat.library = "lifetime";
        pat.category = "MemorySafety";
        pat.kind = std::string(kind);
        pat.return_type = std::string(ret_type);
        pat.behavior_category = "MemorySafety";
        pat.risk_score = risk_score;
        pat.behavior_tags.emplace_back(tag);
        setLifetimeFieldIfPresent(pat, lifetime_kind);
        pat.is_auto_init_entrypoint = current_is_auto_init_;
        pat.entrypoint_kind = current_entrypoint_kind_;
        fillPresumedLocation(loc, pat.source_file, pat.line, pat.column);
        collector_->add(std::move(pat));
    }

    void RuntimeDependencyVisitor::emitUseAfterFree(const clang::VarDecl *VD, clang::SourceLocation loc) {
        if (!VD)
            return;
        emitLifetimeRecord("use_after_free", "use_after_free", "use_after_free", VD->getNameAsString(), 85, loc);
    }

#endif // CLANG_PLUGIN_AVAILABLE

} // namespace traceql
