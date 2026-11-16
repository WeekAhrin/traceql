#include "safety/taint_tracker.h"

#include <algorithm>

namespace traceql {

    const char *getTaintKindName(TaintKind kind) noexcept {
        switch (kind) {
        case TaintKind::MemoryAlloc:
            return "MemoryAlloc";
        case TaintKind::DynamicResolve:
            return "DynamicResolve";
        case TaintKind::HighEntropyBlob:
            return "HighEntropyBlob";
        case TaintKind::StackString:
            return "StackString";
        case TaintKind::ExecProtect:
            return "ExecProtect";
        }
        return "Unknown";
    }

    void TaintTracker::clear() {
        states_.clear();
    }

    void TaintTracker::appendChainUnique(std::vector<std::string> &chain, std::string_view entry) {
        if (entry.empty()) {
            return;
        }
        if (std::find(chain.begin(), chain.end(), entry) == chain.end()) {
            chain.emplace_back(entry);
        }
    }

    void TaintTracker::addTaint(uintptr_t var, TaintKind kind, std::string_view detail) {
        if (var == 0) {
            return;
        }
        TaintState &state = states_[var];
        state.mask |= static_cast<uint32_t>(kind);
        if (state.origin_symbol.empty()) {
            state.origin_symbol = detail.empty() ? std::string(getTaintKindName(kind)) : std::string(detail);
        }
        appendChainUnique(state.chain, detail.empty() ? std::string_view(getTaintKindName(kind)) : detail);
    }

    void TaintTracker::assignAlias(uintptr_t dst, uintptr_t src, std::string_view detail) {
        if (dst == 0 || src == 0 || dst == src) {
            return;
        }
        const auto it = states_.find(src);
        if (it == states_.end() || it->second.mask == 0) {
            return;
        }

        const TaintState src_copy = it->second;
        TaintState &dst_state = states_[dst];
        dst_state.mask |= src_copy.mask;
        if (dst_state.origin_symbol.empty()) {
            dst_state.origin_symbol = src_copy.origin_symbol;
        }
        for (const auto &step : src_copy.chain) {
            appendChainUnique(dst_state.chain, step);
        }
        appendChainUnique(dst_state.chain, detail);
    }

    void TaintTracker::propagateBinary(uintptr_t dst, uintptr_t lhs, uintptr_t rhs, std::string_view detail) {
        if (dst == 0) {
            return;
        }
        if (lhs != 0) {
            assignAlias(dst, lhs, detail);
        }
        if (rhs != 0) {
            assignAlias(dst, rhs, detail);
        }
    }

    const TaintState &TaintTracker::getTaint(uintptr_t var) const noexcept {
        static const TaintState kEmptyState{};
        if (var == 0) {
            return kEmptyState;
        }
        const auto it = states_.find(var);
        if (it == states_.end()) {
            return kEmptyState;
        }
        return it->second;
    }

    bool TaintTracker::hasTaint(uintptr_t var, TaintKind kind) const noexcept {
        return getTaint(var).has(kind);
    }

    bool TaintTracker::isTainted(uintptr_t var) const noexcept {
        return getTaint(var).mask != 0;
    }

    bool TaintTracker::hasTaintedExecFlow(uintptr_t var) const noexcept {
        const TaintState &state = getTaint(var);
        if ((state.mask & static_cast<uint32_t>(TaintKind::ExecProtect)) == 0) {
            return false;
        }
        constexpr uint32_t kSourceMask =
            static_cast<uint32_t>(TaintKind::MemoryAlloc) | static_cast<uint32_t>(TaintKind::DynamicResolve) |
            static_cast<uint32_t>(TaintKind::HighEntropyBlob) | static_cast<uint32_t>(TaintKind::StackString);
        return (state.mask & kSourceMask) != 0;
    }

    uintptr_t TaintTracker::contextKey(uintptr_t var_key, uint64_t callsite_id) noexcept {
        // SplitMix-style mix of variable key and callsite ID.
        uint64_t x = static_cast<uint64_t>(var_key) ^ (callsite_id * 0x9e3779b97f4a7c15ULL);
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        return static_cast<uintptr_t>(x ^ (x >> 31));
    }

    void TaintTracker::markTaintedInContext(uintptr_t var_key, uint64_t callsite_id, TaintKind kind,
                                            std::string_view detail) {
        if (var_key == 0) {
            return;
        }
        auto &state = context_states_[contextKey(var_key, callsite_id)];
        state.mask |= static_cast<uint32_t>(kind);
        if (!detail.empty()) {
            appendChainUnique(state.chain, detail);
        }
    }

    void TaintTracker::propagateInContext(uintptr_t dst_key, uintptr_t src_key, uint64_t callsite_id) {
        if (dst_key == 0 || src_key == 0 || dst_key == src_key) {
            return;
        }
        const auto it = context_states_.find(contextKey(src_key, callsite_id));
        if (it == context_states_.end() || it->second.mask == 0) {
            return;
        }
        auto &dst_state = context_states_[contextKey(dst_key, callsite_id)];
        dst_state.mask |= it->second.mask;
        for (const auto &entry : it->second.chain) {
            appendChainUnique(dst_state.chain, entry);
        }
    }

    bool TaintTracker::hasTaintInContext(uintptr_t var_key, uint64_t callsite_id) const noexcept {
        return taintMaskInContext(var_key, callsite_id) != 0;
    }

    uint32_t TaintTracker::taintMaskInContext(uintptr_t var_key, uint64_t callsite_id) const noexcept {
        if (var_key == 0) {
            return 0;
        }
        const auto it = context_states_.find(contextKey(var_key, callsite_id));
        return it == context_states_.end() ? 0U : it->second.mask;
    }

    void FunctionSummaryTable::recordSummary(std::string func_name, FunctionTaintSummary summary) {
        if (func_name.empty()) {
            return;
        }
        summaries_[std::move(func_name)] = std::move(summary);
    }

    const FunctionTaintSummary *FunctionSummaryTable::findSummary(std::string_view func_name) const {
        if (func_name.empty()) {
            return nullptr;
        }
        const auto it = summaries_.find(std::string(func_name));
        if (it == summaries_.end()) {
            return nullptr;
        }
        return &it->second;
    }

    const std::unordered_map<std::string, FunctionTaintSummary> &FunctionSummaryTable::entries() const noexcept {
        return summaries_;
    }

    size_t FunctionSummaryTable::size() const noexcept {
        return summaries_.size();
    }

    void FunctionSummaryTable::clear() {
        summaries_.clear();
    }

} // namespace traceql
