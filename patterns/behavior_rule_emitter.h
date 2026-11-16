#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace traceql {

    class DatasetLoader;

    /// @brief Single call-site behavioral observation fed into the behavior rule emitter.
    struct BehaviorCallObservation {
        std::string caller;
        std::string symbol;
        std::string library;
        std::string kind;
        std::string pattern;
        std::string behavior_category;
        std::vector<std::string> behavior_tags;
        std::vector<std::string> arg_literals;
        uint32_t risk_score{0};
        double arg_entropy{0.0};
        bool has_high_entropy_literal{false};
        bool is_indirect_call{false};
        bool is_inline_asm{false};
        std::string resolved_from_symbol;
        std::string file;
        uint32_t line{0};
        uint32_t column{0};
        bool is_auto_init_entrypoint{false};
        std::string entrypoint_kind;
        bool tainted_exec_flow{false};
        std::string lock_name;
        std::string lock_held_prev;
        std::string lifetime_kind;
    };

    /// @brief Per-caller behavioral call-chain observation fed into the behavior rule emitter.
    struct BehaviorSequenceObservation {
        std::string caller;
        std::vector<std::string> chain;
        std::vector<std::string> behavior_chain_tags;
        double sequence_entropy{0.0};
        double max_arg_entropy{0.0};
        uint32_t caller_risk_score{0};
        bool is_auto_init_entrypoint{false};
        std::string entrypoint_kind;
    };

    /// @brief Normalized behavioral risk finding mapped to MITRE ATT&CK and Sigma/JSON output.
    struct BehaviorFinding {
        std::string rule_id;
        std::string title;
        std::string severity; ///< "low" | "medium" | "high" | "critical"
        std::string target_os;
        std::string caller;
        std::string file;
        uint32_t line{0};
        uint32_t column{0};
        std::vector<std::string> indicators;
        std::vector<std::string> mitre_techniques;
        uint32_t risk_score{0};
        double entropy{0.0};
        std::string description;
    };

    /// @brief Output serialization format for BehaviorRuleEmitter::writeRulesFile.
    enum class BehaviorRuleFormat : uint8_t { Json = 0, SigmaYaml, Sarif };

    /// @brief Emits table-free behavioral risk findings, JSON rule bundles, and Sigma YAML rules.
    class BehaviorRuleEmitter {
      public:
        /// @brief Analyzes call-site and sequence observations using behavioral categories, tags,
        ///        call chains, entropy thresholds, and indirect/syscall/dynamic-resolution indicators.
        [[nodiscard]] static std::vector<BehaviorFinding>
        analyzeFindings(const std::vector<BehaviorCallObservation> &calls,
                        const std::vector<BehaviorSequenceObservation> &sequences, std::string_view target_os = "auto",
                        uint32_t risk_threshold = 40, double entropy_threshold = 6.8,
                        const DatasetLoader *dataset = nullptr);

        /// @brief Serializes findings into a behavioral JSON rules/telemetry document.
        [[nodiscard]] static std::string toJsonRules(const std::vector<BehaviorFinding> &findings,
                                                     std::string_view target_os = "auto");

        /// @brief Serializes findings into multi-document Sigma v2.x YAML detection rules.
        [[nodiscard]] static std::string toSigmaYaml(const std::vector<BehaviorFinding> &findings,
                                                     std::string_view target_os = "auto");

        /// @brief Serializes findings into a SARIF 2.1.0 JSON log document.
        [[nodiscard]] static std::string toSarif(const std::vector<BehaviorFinding> &findings,
                                                 std::string_view target_os = "auto");

        /// @brief Writes serialized JSON, Sigma YAML, or SARIF 2.1.0 rules to disk.
        static bool writeRulesFile(const std::string &output_path, const std::vector<BehaviorFinding> &findings,
                                   std::string_view target_os, BehaviorRuleFormat format);

        /// @brief Writes serialized JSON or Sigma YAML rules to disk (backwards-compatible overload).
        static bool writeRulesFile(const std::string &output_path, const std::vector<BehaviorFinding> &findings,
                                   std::string_view target_os = "auto", bool as_yaml = false);
    };

} // namespace traceql
