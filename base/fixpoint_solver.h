#pragma once

#include "../safety/taint_tracker.h"

#include <string>
#include <vector>

namespace traceql {

    struct CallEdge {
        std::string caller;
        std::string callee;
    };

    /// @brief Tarjan SCC + worklist fixpoint solver for inter-procedural FunctionSummaryTable propagation.
    class TarjanFixpointSolver {
      public:
        /// @brief Computes strongly connected components in reverse topological order (callees before callers).
        [[nodiscard]] std::vector<std::vector<std::string>> computeSccs(const std::vector<CallEdge> &edges) const;

        /// @brief Propagates `return_taint_mask` and `param_sinks` across `edges` until fixpoint,
        ///        handling mutual recursion cycles inside each SCC.
        void solveSummaries(const std::vector<CallEdge> &edges, FunctionSummaryTable &table) const;
    };

} // namespace traceql
