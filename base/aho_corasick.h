#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace traceql {

    /// @brief Case-insensitive ASCII Aho-Corasick multi-pattern matcher compiled to a DFA
    ///        for O(L) single-pass scanning across thousands of indicator patterns.
    class AhoCorasick {
      public:
        AhoCorasick() = default;

        /// @brief Adds a pattern associated with @p rule_id. Ignored if @p pattern is empty.
        ///        Must call build() before matchAll().
        void addPattern(std::string_view pattern, uint32_t rule_id);

        /// @brief Compiles failure links, dictionary suffix links, and DFA goto transitions.
        void build();

        /// @brief Scans @p text in O(text.size()) and appends deduplicated matching rule IDs
        ///        to @p out_rule_ids.
        void matchAll(std::string_view text, std::vector<uint32_t> &out_rule_ids) const;

        /// @brief Resets the automaton and releases all nodes.
        void clear();

        [[nodiscard]] size_t patternCount() const noexcept {
            return pattern_count_;
        }

      private:
        static constexpr uint32_t kInvalidNode = UINT32_MAX;

        struct Node {
            std::array<uint32_t, 256> next;
            uint32_t fail = 0;
            uint32_t dict_link = kInvalidNode;
            std::vector<uint32_t> outputs;

            Node() {
                next.fill(kInvalidNode);
            }
        };

        std::vector<Node> nodes_;
        size_t pattern_count_ = 0;
        bool built_ = false;
    };

} // namespace traceql
