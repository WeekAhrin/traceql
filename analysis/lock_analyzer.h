#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace traceql {

    /// @brief Directed lock-acquisition ordering edge: @p first_lock held while acquiring @p second_lock.
    struct LockOrderEdge {
        std::string first_lock;
        std::string second_lock;
        std::string caller;
        std::string file;
        uint32_t line{0};
    };

    /// @brief Canonical lock-order inversion finding where both A -> B and B -> A edges exist.
    struct LockInversionFinding {
        std::string lock_a;
        std::string lock_b;
        std::string caller_ab;
        std::string caller_ba;
        std::string file_ab;
        std::string file_ba;
    };

    /// @brief Collects lock-order edges across functions/TUs and detects AB/BA lock-order inversions.
    class LockAnalyzer {
      public:
        /// @brief Records a directed lock-order edge (ignores empty lock names or self-edges).
        void recordEdge(LockOrderEdge edge);

        /// @brief Detects canonical (A < B) lock-order inversion pairs where both A -> B and B -> A exist.
        [[nodiscard]] std::vector<LockInversionFinding> detectInversions() const;

        /// @brief Clears all recorded lock-order edges.
        void clear();

        /// @brief Returns all recorded lock-order edges.
        [[nodiscard]] const std::vector<LockOrderEdge> &edges() const noexcept {
            return edges_;
        }

      private:
        std::vector<LockOrderEdge> edges_;
    };

} // namespace traceql
