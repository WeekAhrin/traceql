#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace traceql {

    /// @brief Classification result for an LLVM IR inline assembly block.
    struct IrAsmFinding {
        bool matched{false};
        std::string mnemonic;
        std::string category;
        std::string tag;
        uint32_t risk_score{0};
    };

    /// @brief Classifies an inline assembly string for direct syscalls or anti-analysis instructions.
    /// @details Case-insensitive and instruction/word-boundary aware so benign identifiers or
    ///          comments do not trigger false positives.
    [[nodiscard]] IrAsmFinding classifyInlineAsm(std::string_view asm_text);

    /// @brief Returns true if a recovered IR string is printable ASCII (>= 6 chars) and not
    ///        C++ RTTI/mangled metadata, repetitive padding, or a trivial format string.
    [[nodiscard]] bool isUsefulRecoveredIrString(std::string_view text) noexcept;

    /// @brief Strips trailing NUL bytes from raw IR constant bytes and validates that the
    ///        remaining sequence is a useful printable ASCII string. Returns empty on rejection.
    [[nodiscard]] std::string sanitizeRecoveredIrBytes(std::string_view raw_bytes);

} // namespace traceql
