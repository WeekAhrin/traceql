#include "../base/aho_corasick.h"

#include <algorithm>

namespace traceql {

    namespace {

        constexpr uint8_t toLowerAscii(unsigned char ch) noexcept {
            return (ch >= 'A' && ch <= 'Z') ? static_cast<uint8_t>(ch + ('a' - 'A')) : ch;
        }

    } // namespace

    void AhoCorasick::addPattern(std::string_view pattern, uint32_t rule_id) {
        if (pattern.empty()) {
            return;
        }
        if (nodes_.empty()) {
            nodes_.emplace_back();
        }
        built_ = false;

        uint32_t cur = 0;
        for (const char raw_ch : pattern) {
            const uint8_t ch = toLowerAscii(static_cast<unsigned char>(raw_ch));
            uint32_t nxt = nodes_[cur].next[ch];
            if (nxt == kInvalidNode) {
                nxt = static_cast<uint32_t>(nodes_.size());
                nodes_[cur].next[ch] = nxt;
                nodes_.emplace_back();
            }
            cur = nxt;
        }

        auto &outs = nodes_[cur].outputs;
        if (std::find(outs.begin(), outs.end(), rule_id) == outs.end()) {
            outs.push_back(rule_id);
        }
        ++pattern_count_;
    }

    void AhoCorasick::build() {
        if (nodes_.empty()) {
            built_ = true;
            return;
        }

        std::vector<uint32_t> queue;
        queue.reserve(nodes_.size());

        nodes_[0].fail = 0;
        nodes_[0].dict_link = kInvalidNode;

        for (size_t c = 0; c < 256; ++c) {
            const uint32_t child = nodes_[0].next[c];
            if (child != kInvalidNode) {
                nodes_[child].fail = 0;
                nodes_[child].dict_link = kInvalidNode;
                queue.push_back(child);
            } else {
                nodes_[0].next[c] = 0;
            }
        }

        size_t head = 0;
        while (head < queue.size()) {
            const uint32_t u = queue[head++];
            const uint32_t f = nodes_[u].fail;
            nodes_[u].dict_link = !nodes_[f].outputs.empty() ? f : nodes_[f].dict_link;

            for (size_t c = 0; c < 256; ++c) {
                const uint32_t v = nodes_[u].next[c];
                if (v != kInvalidNode) {
                    nodes_[v].fail = nodes_[f].next[c];
                    queue.push_back(v);
                } else {
                    nodes_[u].next[c] = nodes_[f].next[c];
                }
            }
        }

        built_ = true;
    }

    void AhoCorasick::matchAll(std::string_view text, std::vector<uint32_t> &out_rule_ids) const {
        if (!built_ || nodes_.empty() || text.empty()) {
            return;
        }

        const size_t initial_size = out_rule_ids.size();
        uint32_t state = 0;

        for (const char raw_ch : text) {
            const uint8_t ch = toLowerAscii(static_cast<unsigned char>(raw_ch));
            state = nodes_[state].next[ch];

            uint32_t out_node = !nodes_[state].outputs.empty() ? state : nodes_[state].dict_link;
            while (out_node != kInvalidNode) {
                const auto &outs = nodes_[out_node].outputs;
                out_rule_ids.insert(out_rule_ids.end(), outs.begin(), outs.end());
                out_node = nodes_[out_node].dict_link;
            }
        }

        if (out_rule_ids.size() > initial_size + 1) {
            auto begin_it = out_rule_ids.begin() + static_cast<std::ptrdiff_t>(initial_size);
            std::sort(begin_it, out_rule_ids.end());
            out_rule_ids.erase(std::unique(begin_it, out_rule_ids.end()), out_rule_ids.end());
        }
    }

    void AhoCorasick::clear() {
        nodes_.clear();
        pattern_count_ = 0;
        built_ = false;
    }

} // namespace traceql
