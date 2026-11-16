#include "tools/traceql/ir/ir_asm_classifier.h"

#include <array>
#include <cctype>
#include <string>
#include <string_view>

namespace traceql {

    namespace {

        constexpr bool isIdentChar(unsigned char ch) noexcept {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_';
        }

        constexpr bool isHexOrIdentChar(unsigned char ch) noexcept {
            return isIdentChar(ch);
        }

        constexpr bool isHorizontalSpace(unsigned char ch) noexcept {
            return ch == ' ' || ch == '\t';
        }

        /// @brief Strips C/C++ line comments (`//...`) and block comments (`/*...*/`) and lowercases ASCII.
        ///        Preserves `#` because ARM `svc #0` uses `#` for immediate operands.
        std::string normalizeAsmText(std::string_view asm_text) {
            std::string out;
            out.reserve(asm_text.size());

            size_t i = 0;
            const size_t n = asm_text.size();
            while (i < n) {
                if (i + 1 < n && asm_text[i] == '/' && asm_text[i + 1] == '/') {
                    i += 2;
                    while (i < n && asm_text[i] != '\n') {
                        ++i;
                    }
                    out.push_back(' ');
                    continue;
                }
                if (i + 1 < n && asm_text[i] == '/' && asm_text[i + 1] == '*') {
                    i += 2;
                    while (i + 1 < n && !(asm_text[i] == '*' && asm_text[i + 1] == '/')) {
                        ++i;
                    }
                    if (i + 1 < n) {
                        i += 2;
                    } else {
                        i = n;
                    }
                    out.push_back(' ');
                    continue;
                }

                const unsigned char ch = static_cast<unsigned char>(asm_text[i]);
                out.push_back(static_cast<char>(std::tolower(ch)));
                ++i;
            }
            return out;
        }

        bool hasWordBoundaryBefore(std::string_view text, size_t pos) noexcept {
            if (pos == 0) {
                return true;
            }
            return !isIdentChar(static_cast<unsigned char>(text[pos - 1]));
        }

        bool hasWordBoundaryAfter(std::string_view text, size_t end_pos) noexcept {
            if (end_pos >= text.size()) {
                return true;
            }
            return !isIdentChar(static_cast<unsigned char>(text[end_pos]));
        }

        bool containsWholeWord(std::string_view text, std::string_view word) noexcept {
            size_t pos = 0;
            while ((pos = text.find(word, pos)) != std::string_view::npos) {
                const size_t end_pos = pos + word.size();
                if (hasWordBoundaryBefore(text, pos) && hasWordBoundaryAfter(text, end_pos)) {
                    return true;
                }
                pos += 1;
            }
            return false;
        }

        bool matchInt0x80(std::string_view text) noexcept {
            size_t pos = 0;
            while ((pos = text.find("int", pos)) != std::string_view::npos) {
                if (hasWordBoundaryBefore(text, pos)) {
                    size_t cur = pos + 3;
                    if (cur < text.size() && isHorizontalSpace(static_cast<unsigned char>(text[cur]))) {
                        while (cur < text.size() && isHorizontalSpace(static_cast<unsigned char>(text[cur]))) {
                            ++cur;
                        }
                        if (cur < text.size() && text[cur] == '$') {
                            ++cur;
                        }
                        if (cur + 4 <= text.size() && text.substr(cur, 4) == "0x80") {
                            if (cur + 4 >= text.size() ||
                                !isHexOrIdentChar(static_cast<unsigned char>(text[cur + 4]))) {
                                return true;
                            }
                        }
                    }
                }
                pos += 1;
            }
            return false;
        }

        bool matchSvc0(std::string_view text) noexcept {
            size_t pos = 0;
            while ((pos = text.find("svc", pos)) != std::string_view::npos) {
                if (hasWordBoundaryBefore(text, pos)) {
                    size_t cur = pos + 3;
                    if (cur < text.size() && isHorizontalSpace(static_cast<unsigned char>(text[cur]))) {
                        while (cur < text.size() && isHorizontalSpace(static_cast<unsigned char>(text[cur]))) {
                            ++cur;
                        }
                        if (cur < text.size() && text[cur] == '#') {
                            ++cur;
                        }
                        if (cur < text.size() && text[cur] == '0') {
                            if (cur + 1 >= text.size() ||
                                !isHexOrIdentChar(static_cast<unsigned char>(text[cur + 1]))) {
                                return true;
                            }
                        }
                    }
                }
                pos += 1;
            }
            return false;
        }

    } // namespace

    IrAsmFinding classifyInlineAsm(std::string_view asm_text) {
        if (asm_text.empty()) {
            return {};
        }

        const std::string normalized = normalizeAsmText(asm_text);

        // 1. Direct syscalls (highest severity)
        if (containsWholeWord(normalized, "syscall")) {
            return {true, "syscall", "ProcessExecution", "ir-inline-asm-syscall", 85};
        }
        if (containsWholeWord(normalized, "sysenter")) {
            return {true, "sysenter", "ProcessExecution", "ir-inline-asm-syscall", 85};
        }
        if (matchInt0x80(normalized)) {
            return {true, "int_0x80", "ProcessExecution", "ir-inline-asm-syscall", 85};
        }
        if (matchSvc0(normalized)) {
            return {true, "svc_0", "ProcessExecution", "ir-inline-asm-syscall", 85};
        }

        // 2. Hardware / VM / timing anti-analysis
        static constexpr std::array<std::string_view, 5> kAntiAnalysisMnemonics = {"rdtscp", "rdtsc", "cpuid",
                                                                                   "vmmcall", "vmcall"};
        for (const std::string_view mnemonic : kAntiAnalysisMnemonics) {
            if (containsWholeWord(normalized, mnemonic)) {
                return {true, std::string(mnemonic), "AntiAnalysis", "ir-inline-asm-anti-analysis", 60};
            }
        }

        return {};
    }

    bool isUsefulRecoveredIrString(std::string_view text) noexcept {
        constexpr size_t kMinLen = 6;
        constexpr size_t kMaxLen = 512;
        if (text.size() < kMinLen || text.size() > kMaxLen) {
            return false;
        }

        if (text.starts_with("_ZTS") || text.starts_with("_ZTI") || text.starts_with("_ZTV") ||
            text.starts_with("_ZN") || text.starts_with("_ZZ")) {
            return false;
        }

        const char first = text[0];
        bool all_same = true;
        size_t alnum_count = 0;

        for (const char c : text) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc < 0x20 || uc > 0x7e) {
                return false;
            }
            if (c != first) {
                all_same = false;
            }
            if ((uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') || (uc >= '0' && uc <= '9')) {
                ++alnum_count;
            }
        }

        if (all_same || alnum_count < 3) {
            return false;
        }

        // Reject trivial printf-style format strings (e.g. "%s: %d (%p)").
        if (text.find('%') != std::string_view::npos) {
            size_t non_fmt_alnum = 0;
            for (size_t i = 0; i < text.size(); ++i) {
                if (text[i] == '%' && i + 1 < text.size()) {
                    size_t j = i + 1;
                    while (j < text.size() &&
                           (text[j] == '-' || text[j] == '+' || text[j] == ' ' || text[j] == '#' || text[j] == '0' ||
                            text[j] == '.' || text[j] == '*' || (text[j] >= '0' && text[j] <= '9'))) {
                        ++j;
                    }
                    while (j < text.size() && (text[j] == 'h' || text[j] == 'l' || text[j] == 'L' || text[j] == 'z' ||
                                               text[j] == 'j' || text[j] == 't')) {
                        ++j;
                    }
                    if (j < text.size() && std::isalpha(static_cast<unsigned char>(text[j]))) {
                        i = j;
                        continue;
                    }
                }
                const unsigned char uc = static_cast<unsigned char>(text[i]);
                if ((uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') || (uc >= '0' && uc <= '9')) {
                    ++non_fmt_alnum;
                }
            }
            if (non_fmt_alnum < 3) {
                return false;
            }
        }

        return true;
    }

    std::string sanitizeRecoveredIrBytes(std::string_view raw_bytes) {
        while (!raw_bytes.empty() && raw_bytes.back() == '\0') {
            raw_bytes.remove_suffix(1);
        }
        if (!isUsefulRecoveredIrString(raw_bytes)) {
            return {};
        }
        return std::string(raw_bytes);
    }

} // namespace traceql
