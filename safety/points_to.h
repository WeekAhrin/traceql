#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace traceql {

    /// @brief Andersen-style inclusion-based points-to / alias graph for pointer & indirect-target resolution.
    class PointsToGraph {
      public:
        /// @brief Records `ptr = &target` (`target` in `pts(ptr)`).
        void addAddrOf(uintptr_t ptr, uintptr_t target);

        /// @brief Records `dst = src` (`pts(src) <= pts(dst)`).
        void addCopy(uintptr_t dst, uintptr_t src);

        /// @brief Records `*dst_ptr = src` (for all `t` in `pts(dst_ptr)`: `pts(src) <= pts(t)`).
        void addStore(uintptr_t dst_ptr, uintptr_t src);

        /// @brief Records `dst = *src_ptr` (for all `t` in `pts(src_ptr)`: `pts(t) <= pts(dst)`).
        void addLoad(uintptr_t dst, uintptr_t src_ptr);

        /// @brief Runs worklist fixpoint iteration until all points-to sets stabilize.
        void solve();

        /// @brief Returns the solved points-to set for `ptr`.
        [[nodiscard]] const std::vector<uintptr_t> &pointsTo(uintptr_t ptr) const;

        void clear();

      private:
        struct ComplexEdge {
            uintptr_t a{0};
            uintptr_t b{0};
        };

        std::unordered_map<uintptr_t, std::vector<uintptr_t>> pts_;
        std::unordered_map<uintptr_t, std::vector<uintptr_t>> copy_edges_;
        std::vector<ComplexEdge> store_edges_;
        std::vector<ComplexEdge> load_edges_;

        bool insertPointee(uintptr_t ptr, uintptr_t target);
        static const std::vector<uintptr_t> kEmpty;
    };

} // namespace traceql
