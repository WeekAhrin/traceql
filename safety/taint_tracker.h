#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace traceql {

    /// @brief Bitmaskable taint categories tracked intra-procedurally across variables and buffers.
    enum class TaintKind : uint8_t {
        MemoryAlloc = 1 << 0,
        DynamicResolve = 1 << 1,
        HighEntropyBlob = 1 << 2,
        StackString = 1 << 3,
        ExecProtect = 1 << 4
    };

    /// @brief Combines two TaintKind flags into a bitmask.
    [[nodiscard]] constexpr uint32_t operator|(TaintKind lhs, TaintKind rhs) noexcept {
        return static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs);
    }

    /// @brief Combines a raw taint mask with a TaintKind flag.
    [[nodiscard]] constexpr uint32_t operator|(uint32_t lhs, TaintKind rhs) noexcept {
        return lhs | static_cast<uint32_t>(rhs);
    }

    /// @brief Intersects a raw taint mask with a TaintKind flag.
    [[nodiscard]] constexpr uint32_t operator&(uint32_t lhs, TaintKind rhs) noexcept {
        return lhs & static_cast<uint32_t>(rhs);
    }

    /// @brief Returns a human-readable static label for a single TaintKind flag.
    [[nodiscard]] const char *getTaintKindName(TaintKind kind) noexcept;

    /// @brief Accumulated taint state for a single AST variable or expression key.
    struct TaintState {
        uint32_t mask = 0;
        std::string origin_symbol;
        std::vector<std::string> chain;

        [[nodiscard]] bool empty() const noexcept {
            return mask == 0;
        }
        [[nodiscard]] bool has(TaintKind kind) const noexcept {
            return (mask & static_cast<uint32_t>(kind)) != 0;
        }
    };

    /// @brief Intra-procedural pointer/buffer taint tracker keyed by opaque uintptr_t AST keys.
    ///        Maintains zero dependencies on LLVM or Clang headers.
    class TaintTracker {
      public:
        /// @brief Converts an opaque AST pointer (e.g. clang::ValueDecl*) to a uintptr_t key.
        [[nodiscard]] static uintptr_t toKey(const void *ptr) noexcept {
            return reinterpret_cast<uintptr_t>(ptr);
        }

        /// @brief Clears all tracked variable taint states (called at function boundaries).
        void clear();

        /// @brief Adds a taint flag and optional provenance detail to @p var.
        void addTaint(uintptr_t var, TaintKind kind, std::string_view detail = {});

        /// @brief Propagates taint from @p src to @p dst (pointer alias, assignment, or memcpy).
        void assignAlias(uintptr_t dst, uintptr_t src, std::string_view detail = {});

        /// @brief Propagates taint from two operand keys @p lhs and @p rhs into @p dst.
        void propagateBinary(uintptr_t dst, uintptr_t lhs, uintptr_t rhs, std::string_view detail = {});

        /// @brief Returns the taint state for @p var, or an empty TaintState if untainted.
        [[nodiscard]] const TaintState &getTaint(uintptr_t var) const noexcept;

        /// @brief Returns true if @p var carries the specified @p kind taint flag.
        [[nodiscard]] bool hasTaint(uintptr_t var, TaintKind kind) const noexcept;

        /// @brief Returns true if @p var has any non-zero taint mask.
        [[nodiscard]] bool isTainted(uintptr_t var) const noexcept;

        /// @brief Returns true if @p var combines executable protection taint with a payload/alloc/resolve source.
        [[nodiscard]] bool hasTaintedExecFlow(uintptr_t var) const noexcept;

        /// @brief Returns the number of currently tracked tainted variables.
        [[nodiscard]] size_t trackedCount() const noexcept {
            return states_.size();
        }

        /// @brief 1-CFA context-sensitive taint tracking scoped by `callsite_id`.
        void markTaintedInContext(uintptr_t var_key, uint64_t callsite_id, TaintKind kind,
                                  std::string_view detail = {});
        void propagateInContext(uintptr_t dst_key, uintptr_t src_key, uint64_t callsite_id);
        [[nodiscard]] bool hasTaintInContext(uintptr_t var_key, uint64_t callsite_id) const noexcept;
        [[nodiscard]] uint32_t taintMaskInContext(uintptr_t var_key, uint64_t callsite_id) const noexcept;

      private:
        static void appendChainUnique(std::vector<std::string> &chain, std::string_view entry);
        static uintptr_t contextKey(uintptr_t var_key, uint64_t callsite_id) noexcept;

        std::unordered_map<uintptr_t, TaintState> states_;
        std::unordered_map<uintptr_t, TaintState> context_states_;
    };

    /// @brief Inter-procedural taint summary for a single function in a translation unit.
    struct FunctionTaintSummary {
        uint32_t return_taint_mask{0};
        std::vector<uint32_t> param_sinks;
        std::vector<std::pair<uint32_t, uint32_t>> param_to_param;
        std::vector<uint32_t> param_to_return;
        std::string origin_symbol;
    };

    /// @brief Table mapping function names/symbols to their inter-procedural taint summaries.
    class FunctionSummaryTable {
      public:
        void recordSummary(std::string func_name, FunctionTaintSummary summary);
        [[nodiscard]] const FunctionTaintSummary *findSummary(std::string_view func_name) const;
        [[nodiscard]] const std::unordered_map<std::string, FunctionTaintSummary> &entries() const noexcept;
        [[nodiscard]] size_t size() const noexcept;
        void clear();

      private:
        std::unordered_map<std::string, FunctionTaintSummary> summaries_;
    };

} // namespace traceql
