#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace traceql {

    /// @brief Summary of Shannon entropy metrics across literal blobs and call sequences.
    struct EntropyReport {
        double max_literal_entropy = 0.0;
        double mean_literal_entropy = 0.0;
        double sequence_entropy = 0.0;
        size_t high_entropy_blob_count = 0;
    };

    /// @brief Computes Shannon entropy and byte-distribution metrics over byte buffers,
    ///        string literals, and token sequences for detecting packed/encrypted payloads
    ///        while avoiding false positives on normal ASCII/UTF-8 text and UI assets.
    class EntropyAnalyzer {
      public:
        using EntropyReport = traceql::EntropyReport;

        static constexpr double kDefaultBinaryEntropyThreshold = 6.8;
        static constexpr double kDefaultAsciiEntropyThreshold = 7.0;
        static constexpr size_t kDefaultMinBlobLength = 32;

        /// @brief Computes Shannon entropy of a UTF-8/byte string in bits per byte [0.0, 8.0].
        [[nodiscard]] static double computeShannonEntropy(std::string_view data);

        /// @brief Computes Shannon entropy of a raw byte buffer in bits per byte [0.0, 8.0].
        [[nodiscard]] static double computeByteEntropy(const uint8_t *data, size_t size);

        /// @brief Returns the fraction [0.0, 1.0] of bytes outside printable ASCII (excluding \\t, \\n, \\r).
        [[nodiscard]] static double computeNonPrintableRatio(const uint8_t *data, size_t size);

        /// @brief Computes Shannon entropy of a sequence of call or category tokens in bits per token.
        [[nodiscard]] static double computeSequenceEntropy(const std::vector<std::string> &tokens);

        /// @brief Returns true if @p s meets @p min_len and exceeds the packed/encrypted entropy threshold.
        ///        Normal printable ASCII text (typically 3.5-5.5 bits/byte) returns false.
        [[nodiscard]] static bool isHighEntropyString(std::string_view s,
                                                      double threshold = kDefaultAsciiEntropyThreshold,
                                                      size_t min_len = kDefaultMinBlobLength);

        /// @brief Returns true if @p data meets @p min_len and its entropy is at least @p threshold.
        [[nodiscard]] static bool isHighEntropyBytes(const uint8_t *data, size_t size,
                                                     double threshold = kDefaultBinaryEntropyThreshold,
                                                     size_t min_len = kDefaultMinBlobLength);

        /// @brief Context-aware check for packed/encrypted binary payloads: requires @p min_len,
        ///        entropy >= @p threshold, and either >= 15% non-printable bytes or entropy >= 7.2.
        [[nodiscard]] static bool isLikelyEncryptedOrPacked(const uint8_t *data, size_t size,
                                                            double threshold = kDefaultBinaryEntropyThreshold,
                                                            size_t min_len = kDefaultMinBlobLength);

        /// @brief Aggregates per-literal entropies and sequence entropy into an EntropyReport.
        [[nodiscard]] static EntropyReport summarize(const std::vector<double> &literal_entropies,
                                                     const std::vector<std::string> &sequence_tokens,
                                                     double threshold = kDefaultBinaryEntropyThreshold);
    };

} // namespace traceql
