#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../base/aho_corasick.h"

namespace traceql {

    /// @brief A single API / symbol indicator loaded from an external dataset (e.g. MalAPI JSON,
    ///        LOLBAS JSON, Elastic TOML rules, or Sigma YAML).
    struct DatasetApiEntry {
        std::string symbol;
        std::string category;
        std::string severity = "medium";
        uint32_t risk_score = 60;
        std::string rule_id;
        std::string title;
        std::string description;
        std::vector<std::string> mitre_techniques;
        std::string source_file;
    };

    /// @brief A behavioral rule (single-API or multi-API sequence) loaded from an external feed.
    struct DatasetRule {
        std::string rule_id;
        std::string title;
        std::string severity = "medium";
        uint32_t risk_score = 65;
        std::string target_os = "auto";
        std::string description;
        std::vector<std::string> apis;
        std::vector<std::string> sequence;
        std::unordered_map<std::string, std::vector<std::string>> selections;
        std::unordered_map<std::string, std::vector<std::string>> selection_all_of;
        std::string condition_expr;
        std::vector<std::string> mitre_techniques;
        std::string source_file;
    };

    /// @brief Loads external JSON (MalAPI / LOLBAS / custom), Elastic TOML, and Sigma YAML
    ///        datasets at runtime so detection rules stay externally updatable without hardcoding.
    class DatasetLoader {
      public:
        /// @brief Loads a single .json, .yml, .yaml, or .toml dataset file. Returns entries/rules added.
        size_t loadFile(const std::string &file_path);

        /// @brief Recursively scans a directory for .json, .yml, .yaml, and .toml dataset files.
        size_t loadDirectory(const std::string &dir_path);

        /// @brief Looks up an exact symbol (case-sensitive, with optional namespace/prefix stripping).
        [[nodiscard]] std::vector<DatasetApiEntry> matchSymbol(std::string_view symbol) const;

        /// @brief Evaluates ordered call symbols against loaded sequence rules.
        [[nodiscard]] std::vector<DatasetRule> matchSequence(const std::vector<std::string> &call_symbols) const;

        /// @brief Evaluates observed function indicators (symbols, stack strings, literals)
        ///        against loaded rules using Sigma condition ASTs (or any-match fallback).
        [[nodiscard]] std::vector<DatasetRule> matchIndicators(const std::vector<std::string> &indicators) const;

        [[nodiscard]] size_t apiCount() const noexcept {
            return api_index_.size();
        }
        [[nodiscard]] size_t ruleCount() const noexcept {
            return rules_.size();
        }
        [[nodiscard]] const std::vector<DatasetRule> &rules() const noexcept {
            return rules_;
        }
        [[nodiscard]] size_t loadedFileCount() const noexcept {
            return loaded_files_.size();
        }
        [[nodiscard]] const std::vector<std::string> &loadedFiles() const noexcept {
            return loaded_files_;
        }

        void clear();

      private:
        size_t loadFileInternal(const std::string &file_path, bool build_ac);
        void indexRuleForAhoCorasick(uint32_t rule_idx);
        size_t parseJsonDataset(const std::string &content, const std::string &source_file);
        size_t parseSigmaYaml(const std::string &content, const std::string &source_file);
        size_t parseElasticToml(const std::string &content, const std::string &source_file);
        void indexApiEntry(DatasetApiEntry entry);

        std::unordered_map<std::string, std::vector<DatasetApiEntry>> api_index_;
        std::vector<DatasetRule> rules_;
        std::vector<std::string> loaded_files_;
        AhoCorasick ac_automaton_;
        std::vector<uint32_t> fallback_rule_ids_;
    };

} // namespace traceql
