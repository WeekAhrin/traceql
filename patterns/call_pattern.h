#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace traceql {

    /// @brief Structured AST call-site pattern for behavioral / anti-cheat telemetry & rule generation.
    struct CallPatternRecord {
        std::string caller_function;
        std::string symbol;
        std::string mangled_symbol;
        std::string library;
        std::string category;
        std::string kind; ///< "call", "operator new", "constructor", etc.
        std::string return_type;
        std::vector<std::string> param_types;
        bool is_variadic{false};
        std::vector<std::string> arg_shapes; ///< e.g. "lit:const char*", "const:double", "var:int"
        std::vector<std::string> arg_literals;
        std::string source_file;
        unsigned line{0};
        unsigned column{0};
        bool all_args_constant{false};

        // Behavioral classification & entropy telemetry
        std::string behavior_category = "Benign";
        std::vector<std::string> behavior_tags;
        uint32_t risk_score = 0;
        double arg_entropy = 0.0;
        bool has_high_entropy_literal = false;
        bool is_indirect_call = false;
        bool is_inline_asm = false;
        std::string resolved_from_symbol;
        std::string behavior_rationale;
        bool is_auto_init_entrypoint{false};
        std::string entrypoint_kind;
        bool is_intra_tu_call{false};
        bool tainted_exec_flow{false};
        std::string lock_name;
        std::string lock_held_prev;
        std::string lifetime_kind;

        /// @brief Formats normalized signature pattern, e.g. "int printf(const char*, ...)".
        [[nodiscard]] std::string formatSignature() const;

        /// @brief Formats canonical pattern key, e.g. "[libm.so.6] double sin(double) @ (const:double)".
        [[nodiscard]] std::string formatCanonicalPattern() const;
    };

    /// @brief Per-function behavioral call sequence for runtime / security auditing.
    struct FunctionCallSequence {
        std::string caller_function;
        std::vector<std::string> call_patterns;
        double sequence_entropy = 0.0;
        double max_arg_entropy = 0.0;
        uint32_t caller_risk_score = 0;
        std::vector<std::string> detected_chains;
        bool is_auto_init_entrypoint{false};
        std::string entrypoint_kind;
        std::vector<std::string> transitive_callees;
    };

    /// @brief Collects AST call patterns and builds per-function behavioral call-chain sequences.
    class CallPatternCollector {
      public:
        void add(CallPatternRecord record);
        void clear() noexcept;

        [[nodiscard]] const std::vector<CallPatternRecord> &records() const noexcept {
            return records_;
        }

        [[nodiscard]] std::vector<FunctionCallSequence> buildSequences() const;
        [[nodiscard]] std::string toJson() const;
        bool writeJsonFile(const std::string &path) const;

      private:
        std::vector<CallPatternRecord> records_;
    };

} // namespace traceql
