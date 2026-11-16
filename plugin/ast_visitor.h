#pragma once

#include "tools/traceql/analysis/behavior_classifier.h"
#include "../safety/taint_tracker.h"
#include "tools/traceql/patterns/call_pattern.h"
#include "tools/traceql/platform/header_classifier.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if __has_include("clang/Frontend/FrontendPluginRegistry.h")
#define CLANG_PLUGIN_AVAILABLE 1
#include "clang/AST/AST.h"
#include "clang/AST/Mangle.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include <memory>
#else
#define CLANG_PLUGIN_AVAILABLE 0
#endif

namespace traceql {

    /// @brief Shannon entropy metrics for a single call argument (string literal or byte array).
    struct ArgEntropyInfo {
        unsigned arg_index{0};
        size_t byte_length{0};
        double shannon_entropy{0.0};
        bool is_high_entropy{false};
        bool is_byte_array{false};
    };

    /// @brief Extracted integer constant or bitwise-OR bitmask from a call argument.
    struct ArgBitmaskInfo {
        unsigned arg_index{0};
        uint64_t value{0};
        bool is_or_expression{false};
        std::vector<uint64_t> or_components;
    };

    /// @brief Extended per-call telemetry for indirect calls, dynamic resolution, entropy, and bitmasks.
    struct ExtractedCallTelemetry {
        std::string caller_function;
        std::string symbol;
        bool is_indirect{false};
        std::string indirect_kind;
        std::string resolver_symbol;
        std::string resolved_target_hint;
        bool has_fn_ptr_cast{false};
        std::string cast_kind;
        std::vector<ArgEntropyInfo> arg_entropies;
        double max_arg_entropy{0.0};
        std::vector<ArgBitmaskInfo> arg_bitmasks;
        std::string source_file;
        unsigned line{0};
        unsigned column{0};
        bool is_auto_init_entrypoint{false};
        std::string entrypoint_kind;
    };

    /// @brief Telemetry for GCC inline assembly statements and matched privileged/evasion instructions.
    struct InlineAsmRecord {
        std::string caller_function;
        std::string asm_template;
        std::vector<std::string> matched_instructions;
        bool is_volatile{false};
        std::string source_file;
        unsigned line{0};
        unsigned column{0};
    };

    /// @brief Telemetry for explicit casts (reinterpret_cast / C-style) to function-pointer types.
    struct FunctionPointerCastRecord {
        std::string caller_function;
        std::string cast_kind;
        std::string source_type;
        std::string target_type;
        bool from_integer{false};
        std::string source_file;
        unsigned line{0};
        unsigned column{0};
    };

    /// @brief Shannon entropy telemetry for initialized local/global string or byte-array variables.
    struct ByteBlobEntropyRecord {
        std::string caller_function;
        std::string var_name;
        size_t byte_length{0};
        double shannon_entropy{0.0};
        bool is_high_entropy{false};
        bool is_string_literal{false};
        std::string source_file;
        unsigned line{0};
        unsigned column{0};
    };

#if CLANG_PLUGIN_AVAILABLE

    /// @brief AST visitor that detects all external runtime, OS, ABI, and third-party
    /// library dependencies directly from Clang AST nodes without any static symbol table.
    class RuntimeDependencyVisitor : public clang::RecursiveASTVisitor<RuntimeDependencyVisitor> {
      public:
        RuntimeDependencyVisitor(clang::CompilerInstance &ci, unsigned diag_id, TargetPlatform platform,
                                 CallPatternCollector *collector = nullptr);

        bool TraverseTranslationUnitDecl(clang::TranslationUnitDecl *TUD);
        bool TraverseFunctionDecl(clang::FunctionDecl *FD);
        bool TraverseCXXMethodDecl(clang::CXXMethodDecl *MD);
        bool TraverseStmt(clang::Stmt *S);
        bool TraverseLambdaExpr(clang::LambdaExpr *LE);
        bool TraverseForStmt(clang::ForStmt *S);
        bool TraverseWhileStmt(clang::WhileStmt *S);
        bool TraverseDoStmt(clang::DoStmt *S);
        bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S);
        bool VisitCallExpr(clang::CallExpr *CE);
        bool VisitDeclRefExpr(clang::DeclRefExpr *DRE);
        bool VisitVarDecl(clang::VarDecl *VD);
        bool VisitBinaryOperator(clang::BinaryOperator *BO);
        bool VisitUnaryOperator(clang::UnaryOperator *UO);
        bool VisitMemberExpr(clang::MemberExpr *ME);
        bool VisitArraySubscriptExpr(clang::ArraySubscriptExpr *ASE);
        bool VisitReturnStmt(clang::ReturnStmt *RS);
        bool VisitCXXMethodDecl(clang::CXXMethodDecl *MD);
        bool VisitCastExpr(clang::CastExpr *CE);
        bool VisitGCCAsmStmt(clang::GCCAsmStmt *GAS);
        bool VisitCXXNewExpr(clang::CXXNewExpr *NE);
        bool VisitCXXDeleteExpr(clang::CXXDeleteExpr *DE);
        bool VisitCXXThrowExpr(clang::CXXThrowExpr *TE);
        bool VisitCXXTypeidExpr(clang::CXXTypeidExpr *TE);
        bool VisitCXXConstructExpr(clang::CXXConstructExpr *CE);

        [[nodiscard]] const std::vector<ExtractedCallTelemetry> &extracted_telemetry() const noexcept {
            return extracted_telemetry_;
        }

        [[nodiscard]] const std::vector<InlineAsmRecord> &inline_asm_records() const noexcept {
            return inline_asm_records_;
        }

        [[nodiscard]] const std::vector<FunctionPointerCastRecord> &fp_casts() const noexcept {
            return fp_casts_;
        }

        [[nodiscard]] const std::vector<ByteBlobEntropyRecord> &byte_blob_entropies() const noexcept {
            return byte_blob_entropies_;
        }

        [[nodiscard]] const FunctionSummaryTable &summaryTable() const noexcept {
            return summary_table_;
        }

      private:
        struct LocalPtrOrigin {
            std::string resolver_symbol;
            std::string target_hint;
            unsigned resolved_line{0};
        };

        template <typename TraverseFn>
        bool traverseFunctionWithContext(clang::FunctionDecl *FD, TraverseFn &&traverse_fn);
        bool findSystemHeaderDecl(const clang::FunctionDecl *FD, std::string &out_header) const;

        void reportExternal(std::string_view name, const char *usage_type, std::string_view category,
                            std::string_view library, std::string_view header, bool replaceable,
                            clang::SourceLocation loc);

        void inspectFunction(const clang::FunctionDecl *FD, clang::SourceLocation call_loc, const char *usage_type,
                             const clang::CallExpr *call_expr = nullptr,
                             const clang::CXXConstructExpr *ctor_expr = nullptr,
                             const ExtractedCallTelemetry *arg_telemetry = nullptr);

        void inspectIndirectCall(const clang::CallExpr *CE, clang::SourceLocation call_loc);
        void collectCallArgumentTelemetry(const clang::CallExpr *CE, ExtractedCallTelemetry &out) const;
        void collectArgLiterals(const clang::CallExpr *CE, std::vector<std::string> &out) const;
        bool extractAssembledStringLiteral(const clang::Expr *expr, std::string &out, unsigned depth = 0) const;
        void trackStringAssemblyCall(const clang::CallExpr *CE);
        void emitVirtualOverrideCalls(const clang::CXXMemberCallExpr *MCE, clang::SourceLocation call_loc);
        void collectBehaviorArgFeatures(const clang::CallExpr *CE, const ExtractedCallTelemetry *arg_telemetry,
                                        BehaviorFeatures &features) const;
        void classifyAndPopulateRecord(CallPatternRecord &rec, const BehaviorFeatures &features) const;
        void trackPointerOriginFromExpr(const clang::VarDecl *target_var, const clang::Expr *rhs,
                                        clang::SourceLocation loc);
        BehaviorCategory classifyCallExprCategory(const clang::CallExpr *CE, std::string *out_symbol = nullptr) const;
        void updateTaintFromAssignment(const clang::VarDecl *target_var, const clang::Expr *rhs);
        void updateTaintFromAssignment(uintptr_t dst_key, std::string_view dst_name, const clang::Expr *rhs);
        void propagateMemCopyTaint(const clang::FunctionDecl *FD, const clang::CallExpr *CE);
        void applyTaintExecCheck(const clang::CallExpr *CE, BehaviorCategory cat, std::string_view sym,
                                 BehaviorFeatures &features);
        void applyInterproceduralCallSummary(const clang::FunctionDecl *FD, const clang::CallExpr *CE,
                                             CallPatternRecord *intra_rec = nullptr);
        uintptr_t resolveTaintKey(const clang::Expr *expr) const;
        uint32_t getExprParamFlowMask(const clang::Expr *expr) const;
        void recordParamSinkMask(uint32_t param_mask);
        void recordParamToParamFlow(uint32_t src_param_mask, uint32_t dst_param_idx);
        bool extractResolverInfo(const clang::CallExpr *call, LocalPtrOrigin &out) const;
        bool extractBytesFromInitList(const clang::InitListExpr *ILE, std::vector<uint8_t> &out_bytes) const;
        void fillPresumedLocation(clang::SourceLocation loc, std::string &file, unsigned &line, unsigned &column) const;

        void handleLockAcquisition(const std::string &lock_name, clang::SourceLocation loc);
        void handleLockRelease(const std::string &lock_name);
        void emitLifetimeRecord(std::string_view kind, std::string_view lifetime_kind, std::string_view tag,
                                std::string_view symbol, uint32_t risk_score, clang::SourceLocation loc,
                                std::string_view ret_type = {});
        void emitUseAfterFree(const clang::VarDecl *VD, clang::SourceLocation loc);

        std::string mangleDeclName(const clang::FunctionDecl *FD) const;
        std::string classifyArgShape(const clang::Expr *arg, bool &is_const_out) const;

        clang::CompilerInstance &ci_;
        clang::SourceManager &sm_;
        clang::DiagnosticsEngine &diags_;
        unsigned diag_id_{0};
        TargetPlatform platform_{TargetPlatform::Auto};
        CallPatternCollector *collector_{nullptr};
        std::string current_caller_;
        unsigned loop_depth_{0};
        bool current_fn_has_xor_loop_{false};
        bool current_is_auto_init_{false};
        std::string current_entrypoint_kind_;
        bool current_fn_has_crypto_hash_{false};
        std::vector<std::string> current_fn_crypto_hash_tags_;
        bool current_fn_has_stack_string_{false};
        std::vector<std::string> current_fn_stack_strings_;
        llvm::DenseMap<const clang::VarDecl *, std::string> current_fn_decoded_var_strings_;
        bool current_fn_has_cff_{false};
        TaintTracker taint_tracker_;
        mutable std::unordered_map<std::string, uintptr_t> synthetic_taint_keys_;
        mutable uintptr_t next_synthetic_taint_key_{1};
        FunctionSummaryTable summary_table_;
        FunctionTaintSummary current_fn_summary_;
        llvm::DenseMap<const clang::ParmVarDecl *, uint32_t> current_fn_param_indices_;
        llvm::DenseMap<uintptr_t, uint32_t> current_fn_param_flow_;
        llvm::SmallPtrSet<const clang::Stmt *, 32> current_unreachable_stmts_;
        llvm::DenseMap<const clang::CXXMethodDecl *, std::vector<const clang::CXXMethodDecl *>> virtual_overrides_;
        std::unique_ptr<clang::MangleContext> mangle_ctx_;
        llvm::SmallPtrSet<const clang::DeclRefExpr *, 16> call_callee_refs_;
        llvm::DenseMap<const clang::VarDecl *, LocalPtrOrigin> local_ptr_origins_;
        llvm::DenseMap<const clang::FieldDecl *, LocalPtrOrigin> captured_field_origins_;
        llvm::DenseMap<const clang::VarDecl *, LocalPtrOrigin> pending_lambda_var_origins_;
        std::vector<ExtractedCallTelemetry> extracted_telemetry_;
        std::vector<InlineAsmRecord> inline_asm_records_;
        std::vector<FunctionPointerCastRecord> fp_casts_;
        std::vector<ByteBlobEntropyRecord> byte_blob_entropies_;
        std::vector<std::string> held_locks_;
        std::unordered_set<std::string> scoped_guards_;
        std::unordered_set<const clang::VarDecl *> local_vars_;
        std::unordered_set<const clang::VarDecl *> freed_vars_;
        llvm::SmallPtrSet<const clang::DeclRefExpr *, 16> free_arg_refs_;
        clang::QualType current_fn_return_type_;
    };

#endif // CLANG_PLUGIN_AVAILABLE

} // namespace traceql
