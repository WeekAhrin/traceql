#include "../optimize/entropy_analyzer.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <unordered_map>

namespace traceql {

    double EntropyAnalyzer::computeShannonEntropy(std::string_view data) {
        if (data.empty()) {
            return 0.0;
        }
        return computeByteEntropy(reinterpret_cast<const uint8_t *>(data.data()), data.size());
    }

    double EntropyAnalyzer::computeByteEntropy(const uint8_t *data, size_t size) {
        if (data == nullptr || size == 0) {
            return 0.0;
        }

        std::array<size_t, 256> counts{};
        for (size_t i = 0; i < size; ++i) {
            ++counts[data[i]];
        }

        double entropy = 0.0;
        const double inv_size = 1.0 / static_cast<double>(size);
        for (const size_t count : counts) {
            if (count == 0) {
                continue;
            }
            const double p = static_cast<double>(count) * inv_size;
            entropy -= p * std::log2(p);
        }

        return entropy <= 0.0 ? 0.0 : entropy;
    }

    double EntropyAnalyzer::computeNonPrintableRatio(const uint8_t *data, size_t size) {
        if (data == nullptr || size == 0) {
            return 0.0;
        }

        size_t non_printable = 0;
        for (size_t i = 0; i < size; ++i) {
            const uint8_t b = data[i];
            const bool printable = (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r';
            if (!printable) {
                ++non_printable;
            }
        }
        return static_cast<double>(non_printable) / static_cast<double>(size);
    }

    double EntropyAnalyzer::computeSequenceEntropy(const std::vector<std::string> &tokens) {
        if (tokens.empty()) {
            return 0.0;
        }

        std::unordered_map<std::string_view, size_t> counts;
        counts.reserve(tokens.size());
        for (const auto &token : tokens) {
            ++counts[token];
        }

        double entropy = 0.0;
        const double inv_size = 1.0 / static_cast<double>(tokens.size());
        for (const auto &[token, count] : counts) {
            (void)token;
            const double p = static_cast<double>(count) * inv_size;
            entropy -= p * std::log2(p);
        }

        return entropy <= 0.0 ? 0.0 : entropy;
    }

    bool EntropyAnalyzer::isHighEntropyString(std::string_view s, double threshold, size_t min_len) {
        if (s.size() < min_len) {
            return false;
        }
        const auto *bytes = reinterpret_cast<const uint8_t *>(s.data());
        const double ent = computeByteEntropy(bytes, s.size());
        if (ent < threshold) {
            return false;
        }
        // Pure printable ASCII (e.g. URLs, shaders, UI text) maxes around ~6.0-6.5 bits/byte;
        // require either non-printable binary bytes or very high entropy (>= 7.0).
        const double non_print = computeNonPrintableRatio(bytes, s.size());
        return non_print >= 0.15 || ent >= 7.0;
    }

    bool EntropyAnalyzer::isHighEntropyBytes(const uint8_t *data, size_t size, double threshold, size_t min_len) {
        if (data == nullptr || size < min_len) {
            return false;
        }
        return computeByteEntropy(data, size) >= threshold;
    }

    bool EntropyAnalyzer::isLikelyEncryptedOrPacked(const uint8_t *data, size_t size, double threshold,
                                                    size_t min_len) {
        if (data == nullptr || size < min_len) {
            return false;
        }
        const double ent = computeByteEntropy(data, size);
        if (ent < threshold) {
            return false;
        }
        const double non_print = computeNonPrintableRatio(data, size);
        return non_print >= 0.15 || ent >= 7.2;
    }

    EntropyReport EntropyAnalyzer::summarize(const std::vector<double> &literal_entropies,
                                             const std::vector<std::string> &sequence_tokens, double threshold) {
        EntropyReport report;
        report.sequence_entropy = computeSequenceEntropy(sequence_tokens);

        if (literal_entropies.empty()) {
            return report;
        }

        double sum = 0.0;
        for (const double entropy : literal_entropies) {
            report.max_literal_entropy = std::max(report.max_literal_entropy, entropy);
            sum += entropy;
            if (entropy >= threshold) {
                ++report.high_entropy_blob_count;
            }
        }
        report.mean_literal_entropy = sum / static_cast<double>(literal_entropies.size());

        return report;
    }

} // namespace traceql
