#pragma once

#include "analysis/dataset_loader.h"
#include "safety/taint_tracker.h"
#include "patterns/behavior_rule_emitter.h"
#include "patterns/call_pattern.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace traceql {

    /// @brief Aggregates per-TU pattern JSON reports and performs cross-TU call-chain analysis.
    class ProjectAggregator {
      public:
        /// @brief Parses a `--emit-patterns=<tu.json>` file and appends its call records.
        bool loadPatternJsonFile(const std::string &path);

        /// @brief Parses a `--emit-patterns=<tu.json>` JSON payload directly from memory.
        bool loadPatternJsonContent(std::string_view json_content);

        /// @brief Recursively loads all `.json` pattern files in `dir_path`.
        /// @return Number of files successfully loaded.
        size_t loadPatternJsonDirectory(const std::string &dir_path);

        /// @brief Clears all loaded call records.
        void clear() noexcept;

        /// @brief Returns the raw loaded call records before cross-TU merging.
        [[nodiscard]] const std::vector<CallPatternRecord> &rawRecords() const noexcept {
            return records_;
        }

        /// @brief Returns the aggregated cross-TU function taint summary table.
        [[nodiscard]] const FunctionSummaryTable &summaryTable() const noexcept {
            return summary_table_;
        }

        /// @brief Builds a merged CallPatternCollector with cross-TU calls marked as
        ///        `is_intra_tu_call = true` whenever a call's `symbol` matches any
        ///        `caller_function` defined in any loaded TU.
        [[nodiscard]] CallPatternCollector buildMergedCollector() const;

        /// @brief Serializes the merged collector (including cross-TU sequences) to JSON.
        [[nodiscard]] std::string toMergedPatternsJson() const;

        /// @brief Serializes the merged call graph, tainted flows, and lock-order edges
        ///        to a Mermaid flowchart (`flowchart LR`).
        [[nodiscard]] std::string toMermaidFlowchart() const;

        /// @brief Serializes the merged call graph, tainted flows, and lock-order edges
        ///        to a Graphviz DOT digraph.
        [[nodiscard]] std::string toGraphvizDot() const;

        /// @brief Runs BehaviorRuleEmitter::analyzeFindings on the merged cross-TU calls and sequences.
        [[nodiscard]] std::vector<BehaviorFinding> analyzeProjectFindings(std::string_view target_os = "auto",
                                                                          uint32_t risk_threshold = 40,
                                                                          double entropy_threshold = 6.8,
                                                                          const DatasetLoader *dataset = nullptr) const;

      private:
        [[nodiscard]] CallPatternCollector buildMergedCollectorImpl(const DatasetLoader *dataset) const;

        std::vector<CallPatternRecord> records_;
        FunctionSummaryTable summary_table_;
        std::vector<std::string> summary_names_;
    };

} // namespace traceql
