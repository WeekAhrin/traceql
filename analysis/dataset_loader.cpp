#include "tools/traceql/analysis/dataset_loader.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <regex>
#include <sstream>
#include <yaml-cpp/yaml.h>

namespace traceql {

    namespace {

        std::string trim(std::string_view sv) {
            size_t start = 0;
            while (start < sv.size() && std::isspace(static_cast<unsigned char>(sv[start]))) {
                ++start;
            }
            size_t end = sv.size();
            while (end > start && std::isspace(static_cast<unsigned char>(sv[end - 1]))) {
                --end;
            }
            return std::string(sv.substr(start, end - start));
        }

        std::string toLower(std::string_view sv) {
            std::string out(sv);
            for (char &ch : out) {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }
            return out;
        }

        std::string stripQuotes(std::string_view sv) {
            std::string s = trim(sv);
            if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
                return s.substr(1, s.size() - 2);
            }
            return s;
        }

        uint32_t severityToRisk(std::string_view sev) {
            const std::string low = toLower(sev);
            if (low == "critical")
                return 90;
            if (low == "high")
                return 75;
            if (low == "medium")
                return 55;
            if (low == "low")
                return 35;
            if (low == "informational" || low == "info")
                return 15;
            return 55;
        }

        uint32_t categoryToDefaultRisk(std::string_view cat) {
            const std::string low = toLower(cat);
            if (low.find("inject") != std::string::npos || low.find("syscall") != std::string::npos ||
                low.find("evasion") != std::string::npos || low.find("hook") != std::string::npos) {
                return 80;
            }
            if (low.find("memory") != std::string::npos || low.find("dynamic") != std::string::npos ||
                low.find("anti") != std::string::npos || low.find("spy") != std::string::npos) {
                return 68;
            }
            if (low.find("enum") != std::string::npos || low.find("internet") != std::string::npos ||
                low.find("helper") != std::string::npos) {
                return 50;
            }
            return 60;
        }

        std::string normalizeSymbolKey(std::string_view sym) {
            if (sym.size() > 2 && sym[0] == ':' && sym[1] == ':' && sym.find("::", 2) == std::string_view::npos) {
                return std::string(sym.substr(2));
            }
            return std::string(sym);
        }

        void appendUnique(std::vector<std::string> &out, std::string value) {
            if (value.empty())
                return;
            if (std::find(out.begin(), out.end(), value) == out.end()) {
                out.push_back(std::move(value));
            }
        }

        std::vector<std::string> parseTomlStringList(std::string_view text) {
            std::vector<std::string> items;
            size_t i = 0;
            while (i < text.size()) {
                const char q = text[i];
                if (q == '"' || q == '\'') {
                    const size_t start = ++i;
                    while (i < text.size()) {
                        if (q == '"' && text[i] == '\\' && i + 1 < text.size()) {
                            i += 2;
                            continue;
                        }
                        if (text[i] == q)
                            break;
                        ++i;
                    }
                    if (i > start) {
                        items.emplace_back(text.substr(start, i - start));
                    }
                    if (i < text.size())
                        ++i;
                } else {
                    ++i;
                }
            }
            return items;
        }

        bool isIdentifierChar(char ch) {
            const unsigned char uch = static_cast<unsigned char>(ch);
            return std::isalnum(uch) != 0 || ch == '_';
        }

        bool containsWholeWord(std::string_view haystack, std::string_view word) {
            if (word.empty() || haystack.size() < word.size())
                return false;
            size_t pos = 0;
            while ((pos = haystack.find(word, pos)) != std::string_view::npos) {
                const bool left_ok = (pos == 0) || !isIdentifierChar(haystack[pos - 1]);
                const size_t end = pos + word.size();
                const bool right_ok = (end == haystack.size()) || !isIdentifierChar(haystack[end]);
                if (left_ok && right_ok) {
                    return true;
                }
                pos += word.size();
            }
            return false;
        }

        std::string stripEqlNegationsAndComments(std::string_view query) {
            std::string out;
            out.reserve(query.size());
            size_t i = 0;
            while (i < query.size()) {
                // Skip /* ... */ comments
                if (i + 1 < query.size() && query[i] == '/' && query[i + 1] == '*') {
                    i += 2;
                    while (i + 1 < query.size() && !(query[i] == '*' && query[i + 1] == '/')) {
                        ++i;
                    }
                    i = (i + 1 < query.size()) ? (i + 2) : query.size();
                    out.push_back(' ');
                    continue;
                }
                // Preserve triple-quoted strings intact
                if ((query.substr(i, 3) == "\"\"\"" || query.substr(i, 3) == "'''")) {
                    const std::string_view delim = query.substr(i, 3);
                    const size_t start = i;
                    i += 3;
                    while (i + 3 <= query.size() && query.substr(i, 3) != delim) {
                        ++i;
                    }
                    i = (i + 3 <= query.size()) ? (i + 3) : query.size();
                    out.append(query.substr(start, i - start));
                    continue;
                }
                // Preserve single/double-quoted strings intact
                if (query[i] == '"' || query[i] == '\'') {
                    const char q = query[i];
                    const size_t start = i++;
                    while (i < query.size() && query[i] != q) {
                        if (q == '"' && query[i] == '\\' && i + 1 < query.size()) {
                            i += 2;
                        } else {
                            ++i;
                        }
                    }
                    if (i < query.size())
                        ++i;
                    out.append(query.substr(start, i - start));
                    continue;
                }
                // Skip `not (...)` exclusion blocks
                if (i + 3 <= query.size() && (query[i] == 'n' || query[i] == 'N') &&
                    (query[i + 1] == 'o' || query[i + 1] == 'O') && (query[i + 2] == 't' || query[i + 2] == 'T') &&
                    (i == 0 || !isIdentifierChar(query[i - 1])) &&
                    (i + 3 == query.size() || !isIdentifierChar(query[i + 3]))) {
                    size_t j = i + 3;
                    while (j < query.size() && std::isspace(static_cast<unsigned char>(query[j]))) {
                        ++j;
                    }
                    if (j < query.size() && query[j] == '(') {
                        int depth = 0;
                        while (j < query.size()) {
                            if (query[j] == '"' || query[j] == '\'') {
                                const char q = query[j++];
                                while (j < query.size() && query[j] != q) {
                                    if (q == '"' && query[j] == '\\' && j + 1 < query.size()) {
                                        j += 2;
                                    } else {
                                        ++j;
                                    }
                                }
                                if (j < query.size())
                                    ++j;
                                continue;
                            }
                            if (query[j] == '(') {
                                ++depth;
                            } else if (query[j] == ')') {
                                --depth;
                                if (depth == 0) {
                                    ++j;
                                    break;
                                }
                            }
                            ++j;
                        }
                        out.push_back(' ');
                        i = j;
                        continue;
                    }
                }
                out.push_back(query[i++]);
            }
            return out;
        }

        constexpr std::string_view kRegexPrefix = "\x01RE:";

        std::string cleanElasticPattern(std::string val, bool allow_paths_and_wildcards) {
            val = trim(val);
            if (val.empty())
                return {};
            if (!allow_paths_and_wildcards) {
                if (val.find('*') != std::string::npos || val.find('?') != std::string::npos ||
                    val.find('/') != std::string::npos || val.find('\\') != std::string::npos) {
                    return {};
                }
                return val;
            }
            if (val.rfind("?:\\", 0) == 0 || val.rfind("?:/", 0) == 0) {
                val.replace(0, 2, "*");
            }
            return val;
        }

        size_t coreTokenLength(std::string_view sv) {
            size_t start = 0;
            size_t end = sv.size();
            while (start < end &&
                   (sv[start] == '*' || sv[start] == '?' || std::isspace(static_cast<unsigned char>(sv[start])))) {
                ++start;
            }
            while (end > start && (sv[end - 1] == '*' || sv[end - 1] == '?' ||
                                   std::isspace(static_cast<unsigned char>(sv[end - 1])))) {
                --end;
            }
            return end - start;
        }

        void extractFieldQuotedValues(std::string_view query, std::string_view field_name,
                                      std::vector<std::string> &out, const std::vector<std::string_view> &ignore_list,
                                      bool allow_paths_and_wildcards = false, size_t min_core_len = 1) {
            size_t pos = 0;
            while ((pos = query.find(field_name, pos)) != std::string_view::npos) {
                const size_t after_field = pos + field_name.size();
                if (pos > 0 && isIdentifierChar(query[pos - 1])) {
                    pos = after_field;
                    continue;
                }
                if (after_field < query.size() && isIdentifierChar(query[after_field])) {
                    pos = after_field;
                    continue;
                }
                size_t cur = after_field;
                while (cur < query.size() && std::isspace(static_cast<unsigned char>(query[cur]))) {
                    ++cur;
                }
                // Match operators: ==, :, in, like~, like, regex~, regex
                bool is_regex_op = false;
                if (cur + 1 < query.size() && query[cur] == '=' && query[cur + 1] == '=') {
                    cur += 2;
                } else if (cur < query.size() && query[cur] == ':') {
                    cur += 1;
                } else if (cur + 2 <= query.size() && query.substr(cur, 2) == "in" &&
                           (cur + 2 == query.size() || !isIdentifierChar(query[cur + 2]))) {
                    cur += 2;
                } else if (allow_paths_and_wildcards && cur + 5 <= query.size() && query.substr(cur, 5) == "like~" &&
                           (cur + 5 == query.size() || !isIdentifierChar(query[cur + 5]))) {
                    cur += 5;
                } else if (allow_paths_and_wildcards && cur + 4 <= query.size() && query.substr(cur, 4) == "like" &&
                           (cur + 4 == query.size() || !isIdentifierChar(query[cur + 4]))) {
                    cur += 4;
                } else if (allow_paths_and_wildcards && cur + 6 <= query.size() && query.substr(cur, 6) == "regex~" &&
                           (cur + 6 == query.size() || !isIdentifierChar(query[cur + 6]))) {
                    cur += 6;
                    is_regex_op = true;
                } else if (allow_paths_and_wildcards && cur + 5 <= query.size() && query.substr(cur, 5) == "regex" &&
                           (cur + 5 == query.size() || !isIdentifierChar(query[cur + 5]))) {
                    cur += 5;
                    is_regex_op = true;
                } else {
                    pos = after_field;
                    continue;
                }

                while (cur < query.size() && std::isspace(static_cast<unsigned char>(query[cur]))) {
                    ++cur;
                }

                auto acceptCandidate = [&](std::string val) {
                    if (is_regex_op) {
                        if (val.size() >= min_core_len) {
                            appendUnique(out, std::string(kRegexPrefix) + val);
                        }
                        return;
                    }
                    val = cleanElasticPattern(std::move(val), allow_paths_and_wildcards);
                    if (val.empty() || coreTokenLength(val) < min_core_len) {
                        return;
                    }
                    const std::string low = toLower(val);
                    for (std::string_view ign : ignore_list) {
                        if (low == ign)
                            return;
                    }
                    appendUnique(out, std::move(val));
                };

                if (cur < query.size() && query[cur] == '(') {
                    const size_t close = query.find(')', cur + 1);
                    if (close != std::string_view::npos) {
                        for (auto &item : parseTomlStringList(query.substr(cur + 1, close - cur - 1))) {
                            acceptCandidate(std::move(item));
                        }
                        cur = close + 1;
                    }
                } else if (cur + 3 <= query.size() &&
                           (query.substr(cur, 3) == "\"\"\"" || query.substr(cur, 3) == "'''")) {
                    const std::string_view delim = query.substr(cur, 3);
                    cur += 3;
                    const size_t close = query.find(delim, cur);
                    if (close != std::string_view::npos) {
                        acceptCandidate(std::string(query.substr(cur, close - cur)));
                        cur = close + 3;
                    }
                } else if (cur < query.size() && (query[cur] == '"' || query[cur] == '\'')) {
                    const char q = query[cur];
                    const size_t start = ++cur;
                    while (cur < query.size() && query[cur] != q) {
                        if (q == '"' && query[cur] == '\\' && cur + 1 < query.size()) {
                            cur += 2;
                        } else {
                            ++cur;
                        }
                    }
                    if (cur > start) {
                        acceptCandidate(std::string(query.substr(start, cur - start)));
                    }
                }
                pos = std::max(cur, after_field);
            }
        }

        std::vector<std::string_view> splitEqlTopLevelAnd(std::string_view query) {
            std::vector<std::string_view> chunks;
            int paren_depth = 0;
            int bracket_depth = 0;
            char quote = 0;
            size_t chunk_start = 0;

            for (size_t i = 0; i < query.size(); ++i) {
                const char ch = query[i];
                if (quote != 0) {
                    if (quote == '"' && ch == '\\' && i + 1 < query.size()) {
                        ++i;
                        continue;
                    }
                    if (ch == quote) {
                        quote = 0;
                    }
                    continue;
                }
                if (ch == '"' || ch == '\'') {
                    quote = ch;
                    continue;
                }
                if (ch == '(') {
                    ++paren_depth;
                    continue;
                }
                if (ch == ')' && paren_depth > 0) {
                    --paren_depth;
                    continue;
                }
                if (ch == '[') {
                    ++bracket_depth;
                    continue;
                }
                if (ch == ']' && bracket_depth > 0) {
                    --bracket_depth;
                    continue;
                }
                if (paren_depth == 0 && bracket_depth == 0 && i + 3 <= query.size()) {
                    const bool left_ok = (i == 0) || !isIdentifierChar(query[i - 1]);
                    const bool right_ok = (i + 3 == query.size()) || !isIdentifierChar(query[i + 3]);
                    if (left_ok && right_ok && (query[i] == 'a' || query[i] == 'A') &&
                        (query[i + 1] == 'n' || query[i + 1] == 'N') && (query[i + 2] == 'd' || query[i + 2] == 'D')) {
                        const std::string_view part = query.substr(chunk_start, i - chunk_start);
                        if (!part.empty())
                            chunks.push_back(part);
                        i += 2;
                        chunk_start = i + 1;
                    }
                }
            }
            if (chunk_start < query.size()) {
                const std::string_view part = query.substr(chunk_start);
                if (!part.empty())
                    chunks.push_back(part);
            }
            return chunks;
        }

        std::vector<std::string> extractElasticIndicatorsFromChunk(std::string_view pos_query) {
            std::vector<std::string> out;
            // 1. Direct API names from EQL `api.name` clauses
            extractFieldQuotedValues(pos_query, "api.name", out, {});

            // 2. Syscall / event action names (excluding generic lifecycle actions)
            static const std::vector<std::string_view> kGenericActions = {
                "start",        "exec",         "end",      "fork",     "exit",   "connection_attempted",
                "file_created", "modification", "creation", "deletion", "rename", "open"};
            extractFieldQuotedValues(pos_query, "event.action", out, kGenericActions);

            // 3. Process, executable, command-line, and file indicators from positive EQL clauses
            static const std::vector<std::string_view> kGenericProcessTokens = {
                "find",    "touch",    "link",      "echo",      "open",     "read",    "write",  "close",  "start",
                "exec",    "exit",     "fork",      "http",      "https",    "auto",    "test",   "true",   "false",
                "null",    "data",     "args",      "file",      "path",     "name",    "type",   "user",   "home",
                "none",    "sudo",     "coreutils", "busybox",   "bash",     "tcsh",    "mksh",   "gzip",   "bzip2",
                "install", "xargs",    "strings",   "command",   "stop",     "service", "node",   "nodejs", "dash",
                "fish",    "truncate", "logger",    "tty",       "user_tty", "base64",  "system", "python", "perl",
                "ruby",    "curl",     "wget",      "vim.basic", "env",      "grep",    "azure",  "kube",   "database"};
            static constexpr std::string_view kEqlIndicatorFields[] = {"process.name",
                                                                       "Target.process.name",
                                                                       "process.parent.name",
                                                                       "process.executable",
                                                                       "process.parent.executable",
                                                                       "process.command_line",
                                                                       "process.parent.command_line",
                                                                       "process.args",
                                                                       "file.name",
                                                                       "file.path",
                                                                       "memfd.name"};
            for (std::string_view field : kEqlIndicatorFields) {
                extractFieldQuotedValues(pos_query, field, out, kGenericProcessTokens, true, 4);
            }
            return out;
        }

        void extractElasticRuleIndicators(std::string_view query, std::string_view title, std::string_view description,
                                          DatasetRule &rule) {
            const std::string pos_query = stripEqlNegationsAndComments(query);

            // Extract known high-signal APIs & syscalls referenced in query, title, or description
            static constexpr std::string_view kKnownApis[] = {"VirtualAlloc",
                                                              "VirtualAllocEx",
                                                              "VirtualProtect",
                                                              "VirtualProtectEx",
                                                              "WriteProcessMemory",
                                                              "ReadProcessMemory",
                                                              "CreateRemoteThread",
                                                              "CreateRemoteThreadEx",
                                                              "NtCreateThreadEx",
                                                              "NtAllocateVirtualMemory",
                                                              "NtWriteVirtualMemory",
                                                              "NtProtectVirtualMemory",
                                                              "OpenProcess",
                                                              "OpenThread",
                                                              "QueueUserAPC",
                                                              "SetThreadContext",
                                                              "ResumeThread",
                                                              "SetWindowsHookEx",
                                                              "SetWindowsHookExA",
                                                              "SetWindowsHookExW",
                                                              "RegisterRawInputDevices",
                                                              "GetAsyncKeyState",
                                                              "GetKeyState",
                                                              "MiniDumpWriteDump",
                                                              "LoadLibrary",
                                                              "LoadLibraryA",
                                                              "LoadLibraryW",
                                                              "GetProcAddress",
                                                              "CreateProcess",
                                                              "CreateProcessA",
                                                              "CreateProcessW",
                                                              "WinExec",
                                                              "ShellExecute",
                                                              "ShellExecuteA",
                                                              "ShellExecuteW",
                                                              "URLDownloadToFile",
                                                              "InternetOpen",
                                                              "InternetConnect",
                                                              "HttpSendRequest",
                                                              "ptrace",
                                                              "memfd_create",
                                                              "process_vm_writev",
                                                              "process_vm_readv",
                                                              "dlopen",
                                                              "dlsym",
                                                              "mprotect",
                                                              "execve",
                                                              "execveat",
                                                              "personality",
                                                              "setsid",
                                                              "bpf"};
            for (std::string_view api : kKnownApis) {
                if (containsWholeWord(pos_query, api) || containsWholeWord(title, api) ||
                    containsWholeWord(description, api)) {
                    appendUnique(rule.apis, std::string(api));
                }
            }

            const std::vector<std::string_view> chunks = splitEqlTopLevelAnd(pos_query);
            size_t group_idx = 0;
            for (std::string_view chunk : chunks) {
                std::vector<std::string> chunk_inds = extractElasticIndicatorsFromChunk(chunk);
                if (!chunk_inds.empty()) {
                    const std::string sel_name = "eql_" + std::to_string(group_idx++);
                    for (auto &ind : chunk_inds) {
                        appendUnique(rule.apis, ind);
                    }
                    rule.selections[sel_name] = std::move(chunk_inds);
                }
            }

            const bool has_and_or_seq = containsWholeWord(pos_query, "and") || containsWholeWord(pos_query, "sequence");
            if (has_and_or_seq && group_idx >= 2) {
                rule.condition_expr = "all of them";
            } else {
                rule.selections.clear();
            }
        }

        bool isCommandOrPathIndicator(std::string_view ind) {
            if (ind.empty())
                return false;
            bool has_ws_or_path = false;
            for (char ch : ind) {
                if (std::isspace(static_cast<unsigned char>(ch)) || ch == '/' || ch == '\\') {
                    has_ws_or_path = true;
                    break;
                }
            }
            if (has_ws_or_path)
                return true;

            const std::string low = toLower(ind);
            static constexpr std::string_view kExecExts[] = {".exe", ".dll", ".so", ".bat", ".cmd",
                                                             ".ps1", ".vbs", ".sh", ".py"};
            for (std::string_view ext : kExecExts) {
                if (low.size() > ext.size() && low.compare(low.size() - ext.size(), ext.size(), ext) == 0) {
                    return true;
                }
            }
            return false;
        }

        bool matchWildcardInsensitive(std::string_view pattern, std::string_view text) {
            size_t p = 0;
            size_t t = 0;
            size_t star_p = std::string_view::npos;
            size_t star_t = 0;

            while (t < text.size()) {
                if (p < pattern.size() &&
                    (pattern[p] == '?' || std::tolower(static_cast<unsigned char>(pattern[p])) ==
                                              std::tolower(static_cast<unsigned char>(text[t])))) {
                    ++p;
                    ++t;
                } else if (p < pattern.size() && pattern[p] == '*') {
                    star_p = p++;
                    star_t = t;
                } else if (star_p != std::string_view::npos) {
                    p = star_p + 1;
                    t = ++star_t;
                } else {
                    return false;
                }
            }
            while (p < pattern.size() && pattern[p] == '*') {
                ++p;
            }
            return p == pattern.size();
        }

        bool containsInsensitiveWordBoundary(std::string_view haystack, std::string_view needle) {
            if (needle.empty() || haystack.size() < needle.size())
                return false;
            const bool need_left = isIdentifierChar(needle.front());
            const bool need_right = isIdentifierChar(needle.back());
            for (size_t pos = 0; pos + needle.size() <= haystack.size(); ++pos) {
                bool eq = true;
                for (size_t j = 0; j < needle.size(); ++j) {
                    if (std::tolower(static_cast<unsigned char>(haystack[pos + j])) !=
                        std::tolower(static_cast<unsigned char>(needle[j]))) {
                        eq = false;
                        break;
                    }
                }
                if (!eq)
                    continue;
                const bool left_ok = !need_left || pos == 0 || !isIdentifierChar(haystack[pos - 1]);
                const bool right_ok = !need_right || (pos + needle.size() == haystack.size()) ||
                                      !isIdentifierChar(haystack[pos + needle.size()]);
                if (left_ok && right_ok) {
                    return true;
                }
            }
            return false;
        }

        bool equalsInsensitive(std::string_view a, std::string_view b) {
            if (a.size() != b.size())
                return false;
            for (size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
                    return false;
                }
            }
            return true;
        }

        bool matchIndicatorPattern(std::string_view pattern, std::string_view indicator) {
            if (pattern.empty())
                return false;
            if (pattern.rfind(kRegexPrefix, 0) == 0) {
                const std::string_view raw_re = pattern.substr(kRegexPrefix.size());
                try {
                    const std::regex re(raw_re.begin(), raw_re.end(),
                                        std::regex_constants::ECMAScript | std::regex_constants::icase);
                    return std::regex_search(indicator.begin(), indicator.end(), re);
                } catch (const std::regex_error &) {
                    return false;
                }
            }

            const bool has_wild =
                (pattern.find('*') != std::string_view::npos || pattern.find('?') != std::string_view::npos);
            const std::string short_ind = normalizeSymbolKey(indicator);
            const bool ind_is_cmd_or_path = isCommandOrPathIndicator(indicator);

            if (!has_wild) {
                if (equalsInsensitive(pattern, indicator) ||
                    (short_ind != indicator && equalsInsensitive(pattern, short_ind))) {
                    return true;
                }
                if (ind_is_cmd_or_path && pattern.size() >= 4 && containsInsensitiveWordBoundary(indicator, pattern)) {
                    return true;
                }
                return false;
            }

            size_t start = 0;
            size_t end = pattern.size();
            while (start < end && (pattern[start] == '*' || pattern[start] == '?'))
                ++start;
            while (end > start && (pattern[end - 1] == '*' || pattern[end - 1] == '?'))
                --end;
            const std::string_view core = pattern.substr(start, end - start);
            if (core.empty())
                return false;

            const bool core_has_wild =
                (core.find('*') != std::string_view::npos || core.find('?') != std::string_view::npos);

            if (core_has_wild) {
                return ind_is_cmd_or_path && matchWildcardInsensitive(pattern, indicator);
            }

            const bool lead_wild = (start > 0);
            const bool trail_wild = (end < pattern.size());

            if (lead_wild && trail_wild) {
                if (!ind_is_cmd_or_path) {
                    return equalsInsensitive(core, indicator) ||
                           (short_ind != indicator && equalsInsensitive(core, short_ind));
                }
                return containsInsensitiveWordBoundary(indicator, core);
            }

            if (lead_wild) {
                auto matchesSuffix = [&](std::string_view target) -> bool {
                    if (target.size() < core.size())
                        return false;
                    const size_t pos = target.size() - core.size();
                    if (!equalsInsensitive(target.substr(pos), core))
                        return false;
                    if (pos > 0 && isIdentifierChar(core.front()) && isIdentifierChar(target[pos - 1])) {
                        return false;
                    }
                    return true;
                };
                return matchesSuffix(indicator) || (short_ind != indicator && matchesSuffix(short_ind));
            }

            // trail_wild only (prefix*)
            auto matchesPrefix = [&](std::string_view target) -> bool {
                if (target.size() < core.size())
                    return false;
                if (!equalsInsensitive(target.substr(0, core.size()), core))
                    return false;
                if (target.size() > core.size() && isIdentifierChar(core.back())) {
                    const unsigned char next_ch = static_cast<unsigned char>(target[core.size()]);
                    if (std::isalpha(next_ch) != 0 || next_ch == '_') {
                        return false;
                    }
                }
                return true;
            };
            return matchesPrefix(indicator) || (short_ind != indicator && matchesPrefix(short_ind));
        }

        bool selectionMatchesIndicators(const std::vector<std::string> &patterns,
                                        const std::vector<std::string> &indicators) {
            for (const auto &pat : patterns) {
                for (const auto &ind : indicators) {
                    if (matchIndicatorPattern(pat, ind)) {
                        return true;
                    }
                }
            }
            return false;
        }

        bool selectionMatchesAllPatterns(const std::vector<std::string> &patterns,
                                         const std::vector<std::string> &indicators) {
            if (patterns.empty())
                return false;
            for (const auto &pat : patterns) {
                bool matched_one = false;
                for (const auto &ind : indicators) {
                    if (matchIndicatorPattern(pat, ind)) {
                        matched_one = true;
                        break;
                    }
                }
                if (!matched_one)
                    return false;
            }
            return true;
        }

        bool evalRuleSelection(const DatasetRule &rule, const std::string &sel_name,
                               const std::vector<std::string> &indicators) {
            const auto it = rule.selections.find(sel_name);
            const auto all_it = rule.selection_all_of.find(sel_name);
            const bool has_any = (it != rule.selections.end() && !it->second.empty());
            const bool has_all = (all_it != rule.selection_all_of.end() && !all_it->second.empty());
            if (!has_any && !has_all)
                return false;
            if (has_any && !selectionMatchesIndicators(it->second, indicators))
                return false;
            if (has_all && !selectionMatchesAllPatterns(all_it->second, indicators))
                return false;
            return true;
        }

        struct SigmaCondNode {
            enum class Kind { Ident, Not, And, Or, OneOf, AllOf };
            Kind kind = Kind::Ident;
            std::string target;
            std::unique_ptr<SigmaCondNode> left;
            std::unique_ptr<SigmaCondNode> right;
        };

        class SigmaConditionParser {
          public:
            explicit SigmaConditionParser(std::string_view expr) : expr_(expr) {
                tokenize();
            }

            std::unique_ptr<SigmaCondNode> parse() {
                if (tokens_.empty())
                    return nullptr;
                pos_ = 0;
                auto node = parseOr();
                if (!node || pos_ != tokens_.size()) {
                    return nullptr;
                }
                return node;
            }

          private:
            struct Token {
                enum class Type { LParen, RParen, And, Or, Not, OneOf, AllOf, Word };
                Type type = Type::Word;
                std::string text;
            };

            void tokenize() {
                std::vector<std::string> raw;
                size_t i = 0;
                while (i < expr_.size()) {
                    if (std::isspace(static_cast<unsigned char>(expr_[i]))) {
                        ++i;
                        continue;
                    }
                    if (expr_[i] == '(' || expr_[i] == ')') {
                        raw.emplace_back(1, expr_[i]);
                        ++i;
                        continue;
                    }
                    const size_t start = i;
                    while (i < expr_.size() && !std::isspace(static_cast<unsigned char>(expr_[i])) && expr_[i] != '(' &&
                           expr_[i] != ')') {
                        ++i;
                    }
                    raw.emplace_back(expr_.substr(start, i - start));
                }

                for (size_t idx = 0; idx < raw.size(); ++idx) {
                    const std::string &w = raw[idx];
                    const std::string low = toLower(w);
                    if (w == "(") {
                        tokens_.push_back({Token::Type::LParen, w});
                    } else if (w == ")") {
                        tokens_.push_back({Token::Type::RParen, w});
                    } else if (low == "and") {
                        tokens_.push_back({Token::Type::And, w});
                    } else if (low == "or") {
                        tokens_.push_back({Token::Type::Or, w});
                    } else if (low == "not") {
                        tokens_.push_back({Token::Type::Not, w});
                    } else if ((low == "1" || low == "all") && idx + 2 < raw.size() && toLower(raw[idx + 1]) == "of") {
                        const Token::Type t = (low == "1") ? Token::Type::OneOf : Token::Type::AllOf;
                        tokens_.push_back({t, raw[idx + 2]});
                        idx += 2;
                    } else {
                        tokens_.push_back({Token::Type::Word, w});
                    }
                }
            }

            std::unique_ptr<SigmaCondNode> parseOr() {
                auto lhs = parseAnd();
                if (!lhs)
                    return nullptr;
                while (pos_ < tokens_.size() && tokens_[pos_].type == Token::Type::Or) {
                    ++pos_;
                    auto rhs = parseAnd();
                    if (!rhs)
                        return nullptr;
                    auto node = std::make_unique<SigmaCondNode>();
                    node->kind = SigmaCondNode::Kind::Or;
                    node->left = std::move(lhs);
                    node->right = std::move(rhs);
                    lhs = std::move(node);
                }
                return lhs;
            }

            std::unique_ptr<SigmaCondNode> parseAnd() {
                auto lhs = parseNot();
                if (!lhs)
                    return nullptr;
                while (pos_ < tokens_.size() && tokens_[pos_].type == Token::Type::And) {
                    ++pos_;
                    auto rhs = parseNot();
                    if (!rhs)
                        return nullptr;
                    auto node = std::make_unique<SigmaCondNode>();
                    node->kind = SigmaCondNode::Kind::And;
                    node->left = std::move(lhs);
                    node->right = std::move(rhs);
                    lhs = std::move(node);
                }
                return lhs;
            }

            std::unique_ptr<SigmaCondNode> parseNot() {
                if (pos_ < tokens_.size() && tokens_[pos_].type == Token::Type::Not) {
                    ++pos_;
                    auto sub = parseNot();
                    if (!sub)
                        return nullptr;
                    auto node = std::make_unique<SigmaCondNode>();
                    node->kind = SigmaCondNode::Kind::Not;
                    node->left = std::move(sub);
                    return node;
                }
                return parsePrimary();
            }

            std::unique_ptr<SigmaCondNode> parsePrimary() {
                if (pos_ >= tokens_.size())
                    return nullptr;
                const Token &tok = tokens_[pos_];
                if (tok.type == Token::Type::LParen) {
                    ++pos_;
                    auto inner = parseOr();
                    if (!inner || pos_ >= tokens_.size() || tokens_[pos_].type != Token::Type::RParen) {
                        return nullptr;
                    }
                    ++pos_;
                    return inner;
                }
                if (tok.type == Token::Type::OneOf || tok.type == Token::Type::AllOf) {
                    ++pos_;
                    auto node = std::make_unique<SigmaCondNode>();
                    node->kind =
                        (tok.type == Token::Type::OneOf) ? SigmaCondNode::Kind::OneOf : SigmaCondNode::Kind::AllOf;
                    node->target = tok.text;
                    return node;
                }
                if (tok.type == Token::Type::Word) {
                    ++pos_;
                    auto node = std::make_unique<SigmaCondNode>();
                    node->kind = SigmaCondNode::Kind::Ident;
                    node->target = tok.text;
                    return node;
                }
                return nullptr;
            }

            std::string_view expr_;
            std::vector<Token> tokens_;
            size_t pos_ = 0;
        };

        bool evalSigmaCondNode(const SigmaCondNode &node, const DatasetRule &rule,
                               const std::vector<std::string> &indicators) {
            switch (node.kind) {
            case SigmaCondNode::Kind::Ident: {
                return evalRuleSelection(rule, node.target, indicators);
            }
            case SigmaCondNode::Kind::Not:
                return node.left ? !evalSigmaCondNode(*node.left, rule, indicators) : false;
            case SigmaCondNode::Kind::And:
                return node.left && node.right && evalSigmaCondNode(*node.left, rule, indicators) &&
                       evalSigmaCondNode(*node.right, rule, indicators);
            case SigmaCondNode::Kind::Or:
                return (node.left && evalSigmaCondNode(*node.left, rule, indicators)) ||
                       (node.right && evalSigmaCondNode(*node.right, rule, indicators));
            case SigmaCondNode::Kind::OneOf:
            case SigmaCondNode::Kind::AllOf: {
                const bool is_all = (node.kind == SigmaCondNode::Kind::AllOf);
                const bool is_them = (toLower(node.target) == "them");
                size_t matched_groups = 0;
                size_t satisfied_groups = 0;
                for (const auto &[sel_name, patterns] : rule.selections) {
                    (void)patterns;
                    if (!is_them && !matchWildcardInsensitive(node.target, sel_name)) {
                        continue;
                    }
                    ++matched_groups;
                    if (evalRuleSelection(rule, sel_name, indicators)) {
                        ++satisfied_groups;
                        if (!is_all)
                            return true;
                    } else if (is_all) {
                        return false;
                    }
                }
                if (matched_groups == 0)
                    return false;
                return is_all ? (satisfied_groups == matched_groups) : (satisfied_groups > 0);
            }
            }
            return false;
        }

        enum class SigmaModifier { None, Regex, Contains, StartsWith, EndsWith };

        bool hasSigmaAllModifier(std::string_view field_key) {
            const size_t pipe = field_key.find('|');
            if (pipe == std::string_view::npos)
                return false;
            const std::string mods = toLower(field_key.substr(pipe + 1));
            return mods == "all" || mods.rfind("all|", 0) == 0 || mods.find("|all") != std::string::npos;
        }

        SigmaModifier parseSigmaFieldModifiers(std::string_view field_key) {
            const size_t pipe = field_key.find('|');
            if (pipe == std::string_view::npos)
                return SigmaModifier::None;
            const std::string mods = toLower(field_key.substr(pipe + 1));
            if (mods == "re" || mods.rfind("re|", 0) == 0 || mods.find("|re") != std::string::npos) {
                return SigmaModifier::Regex;
            }
            if (mods.find("contains") != std::string::npos) {
                return SigmaModifier::Contains;
            }
            if (mods.find("startswith") != std::string::npos) {
                return SigmaModifier::StartsWith;
            }
            if (mods.find("endswith") != std::string::npos) {
                return SigmaModifier::EndsWith;
            }
            return SigmaModifier::None;
        }

        std::string applySigmaModifier(std::string val, SigmaModifier mod) {
            if (val.empty())
                return val;
            switch (mod) {
            case SigmaModifier::Regex:
                return std::string(kRegexPrefix) + val;
            case SigmaModifier::Contains:
                if (val.front() != '*')
                    val.insert(val.begin(), '*');
                if (val.back() != '*')
                    val.push_back('*');
                return val;
            case SigmaModifier::StartsWith:
                if (val.back() != '*')
                    val.push_back('*');
                return val;
            case SigmaModifier::EndsWith:
                if (val.front() != '*')
                    val.insert(val.begin(), '*');
                return val;
            case SigmaModifier::None:
                return val;
            }
            return val;
        }

        bool isCleanApiSymbol(std::string_view sym) {
            if (sym.empty() || sym.rfind(kRegexPrefix, 0) == 0)
                return false;
            for (char ch : sym) {
                if (ch == '*' || ch == '?' || ch == '/' || ch == '\\' || std::isspace(static_cast<unsigned char>(ch))) {
                    return false;
                }
            }
            return true;
        }

        bool hasRegexMetacharacters(std::string_view sv) {
            for (const char ch : sv) {
                switch (ch) {
                case '\\':
                case '.':
                case '*':
                case '+':
                case '?':
                case '(':
                case ')':
                case '[':
                case ']':
                case '{':
                case '}':
                case '|':
                case '^':
                case '$':
                    return true;
                default:
                    break;
                }
            }
            return false;
        }

        std::string_view extractStaticLiteralCore(std::string_view pattern) {
            if (pattern.empty())
                return {};
            if (pattern.rfind(kRegexPrefix, 0) == 0) {
                const std::string_view raw_re = pattern.substr(kRegexPrefix.size());
                if (raw_re.size() >= 4 && !hasRegexMetacharacters(raw_re)) {
                    return raw_re;
                }
                return {};
            }

            std::string_view best;
            size_t i = 0;
            while (i < pattern.size()) {
                while (i < pattern.size() && (pattern[i] == '*' || pattern[i] == '?')) {
                    ++i;
                }
                const size_t start = i;
                while (i < pattern.size() && pattern[i] != '*' && pattern[i] != '?') {
                    ++i;
                }
                if (i - start > best.size()) {
                    best = pattern.substr(start, i - start);
                }
            }
            return best.size() >= 4 ? best : std::string_view{};
        }

    } // namespace

    void DatasetLoader::clear() {
        api_index_.clear();
        rules_.clear();
        loaded_files_.clear();
        ac_automaton_.clear();
        fallback_rule_ids_.clear();
    }

    void DatasetLoader::indexApiEntry(DatasetApiEntry entry) {
        if (entry.symbol.empty())
            return;
        api_index_[entry.symbol].push_back(std::move(entry));
    }

    void DatasetLoader::indexRuleForAhoCorasick(uint32_t rule_idx) {
        const DatasetRule &rule = rules_[rule_idx];
        bool indexed_any = false;
        bool has_unindexable = false;

        auto addPatternList = [&](const std::vector<std::string> &patterns) {
            for (const auto &pat : patterns) {
                const std::string_view core = extractStaticLiteralCore(pat);
                if (core.size() >= 4) {
                    ac_automaton_.addPattern(core, rule_idx);
                    indexed_any = true;
                } else {
                    has_unindexable = true;
                }
            }
        };

        for (const auto &[sel_name, patterns] : rule.selections) {
            (void)sel_name;
            addPatternList(patterns);
        }
        for (const auto &[sel_name, patterns] : rule.selection_all_of) {
            (void)sel_name;
            addPatternList(patterns);
        }
        addPatternList(rule.apis);
        addPatternList(rule.sequence);

        if (!rule.condition_expr.empty() && containsInsensitiveWordBoundary(rule.condition_expr, "not")) {
            has_unindexable = true;
        }

        if (!indexed_any || has_unindexable) {
            fallback_rule_ids_.push_back(rule_idx);
        }
    }

    size_t DatasetLoader::loadFile(const std::string &file_path) {
        return loadFileInternal(file_path, true);
    }

    size_t DatasetLoader::loadFileInternal(const std::string &file_path, bool build_ac) {
        std::ifstream ifs(file_path, std::ios::binary);
        if (!ifs.is_open()) {
            return 0;
        }
        std::ostringstream oss;
        oss << ifs.rdbuf();
        const std::string content = oss.str();

        const size_t prev_rules = rules_.size();
        size_t added = 0;
        const std::string ext = toLower(std::filesystem::path(file_path).extension().string());
        if (ext == ".yml" || ext == ".yaml") {
            added = parseSigmaYaml(content, file_path);
        } else if (ext == ".toml") {
            added = parseElasticToml(content, file_path);
        } else {
            added = parseJsonDataset(content, file_path);
        }
        if (added > 0) {
            loaded_files_.push_back(file_path);
        }
        for (size_t i = prev_rules; i < rules_.size(); ++i) {
            indexRuleForAhoCorasick(static_cast<uint32_t>(i));
        }
        if (build_ac && rules_.size() > prev_rules) {
            ac_automaton_.build();
        }
        return added;
    }

    size_t DatasetLoader::loadDirectory(const std::string &dir_path) {
        std::error_code ec;
        if (!std::filesystem::exists(dir_path, ec) || !std::filesystem::is_directory(dir_path, ec)) {
            return 0;
        }
        const size_t prev_rules = rules_.size();
        size_t total = 0;
        for (const auto &entry : std::filesystem::recursive_directory_iterator(
                 dir_path, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (!entry.is_regular_file(ec))
                continue;
            const std::string ext = toLower(entry.path().extension().string());
            if (ext == ".json" || ext == ".yml" || ext == ".yaml" || ext == ".toml") {
                total += loadFileInternal(entry.path().string(), false);
            }
        }
        if (rules_.size() > prev_rules) {
            ac_automaton_.build();
        }
        return total;
    }

    size_t DatasetLoader::parseJsonDataset(const std::string &content, const std::string &source_file) {
        const nlohmann::json root = nlohmann::json::parse(content, nullptr, false);
        if (root.is_discarded()) {
            return 0;
        }

        auto getString = [](const nlohmann::json &obj, const char *key, std::string_view def = "") -> std::string {
            if (!obj.is_object())
                return std::string(def);
            auto it = obj.find(key);
            if (it != obj.end() && it->is_string()) {
                return it->get<std::string>();
            }
            return std::string(def);
        };

        auto getUInt = [](const nlohmann::json &obj, const char *key, uint32_t def = 0) -> uint32_t {
            if (!obj.is_object())
                return def;
            auto it = obj.find(key);
            if (it != obj.end() && it->is_number()) {
                const double v = it->get<double>();
                if (v >= 0.0) {
                    return static_cast<uint32_t>(v);
                }
            }
            return def;
        };

        auto getStringArray = [](const nlohmann::json &obj, const char *key) -> std::vector<std::string> {
            std::vector<std::string> out;
            if (!obj.is_object())
                return out;
            auto it = obj.find(key);
            if (it != obj.end() && it->is_array()) {
                for (const auto &item : *it) {
                    if (item.is_string()) {
                        std::string s = item.get<std::string>();
                        if (!s.empty()) {
                            out.push_back(std::move(s));
                        }
                    }
                }
            }
            return out;
        };

        size_t count = 0;

        auto ingestRuleObj = [&](const nlohmann::json &obj) {
            DatasetRule rule;
            rule.rule_id = getString(obj, "id", getString(obj, "rule_id", "DS-RULE"));
            rule.title = getString(obj, "title", getString(obj, "name", rule.rule_id));
            rule.severity = getString(obj, "severity", getString(obj, "level", "medium"));
            rule.risk_score = getUInt(obj, "risk_score", getUInt(obj, "risk", severityToRisk(rule.severity)));
            rule.target_os = getString(obj, "target_os", "auto");
            rule.description = getString(obj, "description");
            rule.apis = getStringArray(obj, "apis");
            if (rule.apis.empty()) {
                rule.apis = getStringArray(obj, "symbols");
            }
            rule.sequence = getStringArray(obj, "sequence");
            if (rule.sequence.empty()) {
                rule.sequence = getStringArray(obj, "chain");
            }
            rule.mitre_techniques = getStringArray(obj, "mitre");
            if (rule.mitre_techniques.empty()) {
                rule.mitre_techniques = getStringArray(obj, "mitre_techniques");
            }
            rule.source_file = source_file;

            for (const auto &api : rule.apis) {
                DatasetApiEntry entry;
                entry.symbol = api;
                entry.category = getString(obj, "category", "DatasetRule");
                entry.severity = rule.severity;
                entry.risk_score = rule.risk_score;
                entry.rule_id = rule.rule_id;
                entry.title = rule.title;
                entry.description = rule.description;
                entry.mitre_techniques = rule.mitre_techniques;
                entry.source_file = source_file;
                indexApiEntry(std::move(entry));
                ++count;
            }

            if (!rule.sequence.empty() || !rule.apis.empty()) {
                rules_.push_back(std::move(rule));
                ++count;
            }
        };

        // Case 1: { "rules": [...] } or { "apis": [...] }
        if (root.is_object()) {
            if (auto rules_it = root.find("rules"); rules_it != root.end() && rules_it->is_array()) {
                for (const auto &item : *rules_it) {
                    if (item.is_object()) {
                        ingestRuleObj(item);
                    }
                }
                return count;
            }

            // Case 2: Nested category-grouped MalAPI object or flat MalAPI-style object.
            for (const auto &[key, val] : root.items()) {
                if (!val.is_object())
                    continue;

                bool is_category_group = false;
                if (!val.contains("description") && !val.contains("category") && !val.contains("severity") &&
                    !val.contains("risk_score") && !val.contains("risk") && !val.contains("rule_id") &&
                    !val.contains("title") && !val.contains("dll")) {
                    for (const auto &[sub_k, sub_v] : val.items()) {
                        (void)sub_k;
                        if (sub_v.is_object()) {
                            is_category_group = true;
                            break;
                        }
                    }
                }

                if (is_category_group) {
                    for (const auto &[api_name, api_val] : val.items()) {
                        if (!api_val.is_object())
                            continue;
                        DatasetApiEntry entry;
                        entry.symbol = api_name;
                        entry.category = getString(api_val, "category", key);
                        entry.severity = getString(api_val, "severity", "high");
                        entry.risk_score = getUInt(
                            api_val, "risk_score", getUInt(api_val, "risk", categoryToDefaultRisk(entry.category)));
                        entry.rule_id = getString(api_val, "rule_id", "DS-API-" + api_name);
                        entry.title = getString(api_val, "title", api_name + " (" + entry.category + ")");
                        entry.description = getString(api_val, "description");
                        entry.mitre_techniques = getStringArray(api_val, "mitre");
                        entry.source_file = source_file;
                        indexApiEntry(std::move(entry));
                        ++count;
                    }
                    continue;
                }

                DatasetApiEntry entry;
                entry.symbol = key;
                entry.category = getString(val, "category", "ExternalDataset");
                entry.severity = getString(val, "severity", "high");
                entry.risk_score =
                    getUInt(val, "risk_score", getUInt(val, "risk", categoryToDefaultRisk(entry.category)));
                entry.rule_id = getString(val, "rule_id", "DS-API-" + key);
                entry.title = getString(val, "title", key + " (" + entry.category + ")");
                entry.description = getString(val, "description");
                entry.mitre_techniques = getStringArray(val, "mitre");
                entry.source_file = source_file;
                indexApiEntry(std::move(entry));
                ++count;
            }
            return count;
        }

        // Case 3: Top-level array of API entries, LOLBAS entries, or rules
        if (root.is_array()) {
            for (const auto &item : root) {
                if (!item.is_object())
                    continue;
                if (item.contains("apis") || item.contains("sequence") || item.contains("chain")) {
                    ingestRuleObj(item);
                } else {
                    const bool is_lolbas =
                        item.contains("Name") && !item.contains("name") && !item.contains("symbol");
                    std::string sym = getString(item, "name", getString(item, "symbol", getString(item, "Name")));
                    if (!sym.empty()) {
                        DatasetApiEntry entry;
                        entry.symbol = std::move(sym);
                        if (is_lolbas) {
                            entry.category = getString(item, "category", "LOLBAS");
                            entry.severity = getString(item, "severity", "medium");
                            entry.risk_score = getUInt(item, "risk_score", getUInt(item, "risk", 50));
                            entry.rule_id = getString(item, "id", "LOLBAS-" + entry.symbol);
                            entry.title = getString(item, "title", entry.symbol + " (LOLBAS)");
                            entry.description = getString(item, "Description", getString(item, "description"));
                            if (auto cmds_it = item.find("Commands"); cmds_it != item.end() && cmds_it->is_array()) {
                                for (const auto &cmd : *cmds_it) {
                                    if (!cmd.is_object())
                                        continue;
                                    appendUnique(entry.mitre_techniques, getString(cmd, "MitreID"));
                                }
                            }
                        } else {
                            entry.category = getString(item, "category", "ExternalDataset");
                            entry.severity = getString(item, "severity", "medium");
                            entry.risk_score = getUInt(item, "risk_score",
                                                       getUInt(item, "risk", categoryToDefaultRisk(entry.category)));
                            entry.rule_id = getString(item, "id", "DS-API-" + entry.symbol);
                            entry.title = getString(item, "title", entry.symbol);
                            entry.description = getString(item, "description");
                            entry.mitre_techniques = getStringArray(item, "mitre");
                        }
                        entry.source_file = source_file;
                        indexApiEntry(std::move(entry));
                        ++count;
                    }
                }
            }
        }

        return count;
    }

    size_t DatasetLoader::parseSigmaYaml(const std::string &content, const std::string &source_file) {
        std::vector<YAML::Node> docs;
        try {
            docs = YAML::LoadAll(content);
        } catch (const YAML::Exception &) {
            return 0;
        }

        size_t count = 0;

        for (const YAML::Node &doc : docs) {
            if (!doc.IsMap())
                continue;

            DatasetRule current;

            auto addSelectionItem = [&](const std::string &sel_name, std::string raw_item, SigmaModifier mod,
                                        bool require_all) {
                if (raw_item.empty())
                    return;
                const std::string transformed = applySigmaModifier(raw_item, mod);
                if (!sel_name.empty()) {
                    if (require_all) {
                        appendUnique(current.selection_all_of[sel_name], transformed);
                    } else {
                        appendUnique(current.selections[sel_name], transformed);
                    }
                }
                const std::string low_sel = toLower(sel_name);
                const bool is_filter = (low_sel.rfind("filter", 0) == 0);
                if (!is_filter && !require_all && mod != SigmaModifier::Regex &&
                    raw_item.find('*') == std::string::npos && raw_item.find('?') == std::string::npos &&
                    raw_item != "selection" && raw_item != "condition") {
                    appendUnique(current.apis, std::move(raw_item));
                }
            };

            auto ingestSelectionNode = [&](auto &self, const std::string &sel_name, const YAML::Node &node,
                                           SigmaModifier mod, bool require_all) -> void {
                if (node.IsScalar()) {
                    std::string item = node.as<std::string>("");
                    if (!item.empty() && item != "selection" && item != "condition") {
                        addSelectionItem(sel_name, std::move(item), mod, require_all);
                    }
                } else if (node.IsSequence()) {
                    for (const auto &elem : node) {
                        if (elem.IsMap()) {
                            for (const auto &sub_kv : elem) {
                                const std::string field_key = sub_kv.first.as<std::string>("");
                                const SigmaModifier sub_mod = parseSigmaFieldModifiers(field_key);
                                const bool sub_all = hasSigmaAllModifier(field_key);
                                self(self, sel_name, sub_kv.second, sub_mod, sub_all);
                            }
                        } else {
                            self(self, sel_name, elem, mod, require_all);
                        }
                    }
                } else if (node.IsMap()) {
                    for (const auto &sub_kv : node) {
                        const std::string field_key = sub_kv.first.as<std::string>("");
                        const SigmaModifier sub_mod = parseSigmaFieldModifiers(field_key);
                        const bool sub_all = hasSigmaAllModifier(field_key);
                        self(self, sel_name, sub_kv.second, sub_mod, sub_all);
                    }
                }
            };

            if (const auto title_node = doc["title"]; title_node && title_node.IsScalar()) {
                current.title = title_node.as<std::string>("");
            }
            if (const auto id_node = doc["id"]; id_node && id_node.IsScalar()) {
                current.rule_id = id_node.as<std::string>("");
            }
            if (const auto level_node = doc["level"]; level_node && level_node.IsScalar()) {
                current.severity = level_node.as<std::string>("");
            }
            if (const auto desc_node = doc["description"]; desc_node && desc_node.IsScalar()) {
                current.description = desc_node.as<std::string>("");
            }
            if (const auto ls_node = doc["logsource"]; ls_node && ls_node.IsMap()) {
                if (const auto prod_node = ls_node["product"]; prod_node && prod_node.IsScalar()) {
                    current.target_os = prod_node.as<std::string>("");
                }
            }
            if (const auto tags_node = doc["tags"]; tags_node && tags_node.IsSequence()) {
                for (const auto &tag_node : tags_node) {
                    if (!tag_node.IsScalar())
                        continue;
                    std::string tag = tag_node.as<std::string>("");
                    const std::string lower_tag = toLower(tag);
                    if (lower_tag.rfind("attack.t", 0) == 0) {
                        std::string tid = tag.substr(7);
                        for (char &c : tid) {
                            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                        }
                        current.mitre_techniques.push_back(std::move(tid));
                    }
                }
            }

            if (const auto det_node = doc["detection"]; det_node && det_node.IsMap()) {
                for (const auto &det_kv : det_node) {
                    const std::string key = det_kv.first.as<std::string>("");
                    const YAML::Node &val = det_kv.second;
                    if (key == "condition") {
                        if (val.IsScalar()) {
                            current.condition_expr = val.as<std::string>("");
                        }
                    } else if (key == "sequence") {
                        if (val.IsSequence()) {
                            for (const auto &elem : val) {
                                if (!elem.IsScalar())
                                    continue;
                                std::string item = elem.as<std::string>("");
                                if (!item.empty() && item != "selection" && item != "condition") {
                                    current.sequence.push_back(std::move(item));
                                }
                            }
                        }
                    } else if (!key.empty()) {
                        current.selections[key];
                        ingestSelectionNode(ingestSelectionNode, key, val, SigmaModifier::None, false);
                    }
                }
            }

            if (current.title.empty() && current.apis.empty() && current.sequence.empty() &&
                current.selections.empty()) {
                continue;
            }
            if (current.rule_id.empty()) {
                current.rule_id = "SIGMA-" + std::to_string(rules_.size() + 1);
            }
            current.risk_score = severityToRisk(current.severity);
            current.source_file = source_file;
            for (const auto &api : current.apis) {
                if (!isCleanApiSymbol(api))
                    continue;
                DatasetApiEntry entry;
                entry.symbol = api;
                entry.category = "SigmaRule";
                entry.severity = current.severity;
                entry.risk_score = current.risk_score;
                entry.rule_id = current.rule_id;
                entry.title = current.title;
                entry.description = current.description;
                entry.mitre_techniques = current.mitre_techniques;
                entry.source_file = source_file;
                indexApiEntry(std::move(entry));
                ++count;
            }
            if (!current.apis.empty() || !current.sequence.empty() || !current.selections.empty()) {
                rules_.push_back(std::move(current));
                ++count;
            }
        }

        return count;
    }

    size_t DatasetLoader::parseElasticToml(const std::string &content, const std::string &source_file) {
        DatasetRule rule;
        rule.severity = "medium";
        rule.risk_score = 65;

        std::string query_text;
        std::string section;
        bool has_severity = false;
        bool has_risk_score = false;

        enum class MultilineTarget { None, Description, Query };
        MultilineTarget ml_target = MultilineTarget::None;
        std::string ml_delim;
        std::string ml_buf;

        enum class ArrayTarget { None, Tags, OsList };
        ArrayTarget arr_target = ArrayTarget::None;
        std::string arr_buf;

        auto applyOsList = [&](const std::vector<std::string> &os_items) {
            if (os_items.empty())
                return;
            std::string joined;
            for (const auto &os : os_items) {
                const std::string low = toLower(os);
                if (low == "linux" || low == "windows" || low == "macos") {
                    if (!joined.empty())
                        joined.push_back(',');
                    joined += low;
                }
            }
            if (!joined.empty()) {
                rule.target_os = std::move(joined);
            }
        };

        auto applyTags = [&](const std::vector<std::string> &tags) {
            std::vector<std::string> os_from_tags;
            for (const auto &tag : tags) {
                const std::string low = toLower(tag);
                if (low == "linux" || low == "windows" || low == "macos") {
                    os_from_tags.push_back(low);
                } else if (tag.size() >= 5 && (tag[0] == 'T' || tag[0] == 't') &&
                           std::isdigit(static_cast<unsigned char>(tag[1]))) {
                    std::string tid = tag;
                    tid[0] = 'T';
                    appendUnique(rule.mitre_techniques, std::move(tid));
                } else if (low.rfind("attack.t", 0) == 0 && tag.size() >= 12) {
                    std::string tid = tag.substr(7);
                    for (char &ch : tid) {
                        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
                    }
                    appendUnique(rule.mitre_techniques, std::move(tid));
                }
            }
            if (rule.target_os == "auto" && !os_from_tags.empty()) {
                applyOsList(os_from_tags);
            }
        };

        std::istringstream iss(content);
        std::string line;
        while (std::getline(iss, line)) {
            if (ml_target != MultilineTarget::None) {
                const size_t end_pos = line.find(ml_delim);
                if (end_pos != std::string::npos) {
                    ml_buf.append(line.substr(0, end_pos));
                    if (ml_target == MultilineTarget::Description) {
                        rule.description = trim(ml_buf);
                    } else if (ml_target == MultilineTarget::Query) {
                        query_text = std::move(ml_buf);
                    }
                    ml_target = MultilineTarget::None;
                    ml_buf.clear();
                    ml_delim.clear();
                } else {
                    ml_buf.append(line);
                    ml_buf.push_back('\n');
                }
                continue;
            }

            if (arr_target != ArrayTarget::None) {
                arr_buf.append(line);
                arr_buf.push_back('\n');
                if (line.find(']') != std::string::npos) {
                    const auto items = parseTomlStringList(arr_buf);
                    if (arr_target == ArrayTarget::Tags) {
                        applyTags(items);
                    } else if (arr_target == ArrayTarget::OsList) {
                        applyOsList(items);
                    }
                    arr_target = ArrayTarget::None;
                    arr_buf.clear();
                }
                continue;
            }

            const std::string t = trim(line);
            if (t.empty() || t[0] == '#')
                continue;

            if (t.front() == '[') {
                size_t start = 1;
                while (start < t.size() && t[start] == '[')
                    ++start;
                size_t end = t.find(']', start);
                if (end != std::string::npos) {
                    section = toLower(trim(std::string_view(t).substr(start, end - start)));
                }
                continue;
            }

            const size_t eq_pos = t.find('=');
            if (eq_pos == std::string::npos)
                continue;

            const std::string key = toLower(trim(std::string_view(t).substr(0, eq_pos)));
            const std::string val_raw = trim(std::string_view(t).substr(eq_pos + 1));

            // Check for multiline string start (""" or ''')
            if (val_raw.rfind("\"\"\"", 0) == 0 || val_raw.rfind("'''", 0) == 0) {
                const std::string delim = val_raw.substr(0, 3);
                const std::string rest = val_raw.substr(3);
                const size_t close_pos = rest.find(delim);
                if (close_pos != std::string::npos) {
                    const std::string extracted = trim(rest.substr(0, close_pos));
                    if (key == "description" && (section.empty() || section == "rule")) {
                        rule.description = extracted;
                    } else if (key == "query" && (section.empty() || section == "rule")) {
                        query_text = extracted;
                    }
                } else if (key == "description" && (section.empty() || section == "rule")) {
                    ml_target = MultilineTarget::Description;
                    ml_delim = delim;
                    ml_buf = rest + "\n";
                } else if (key == "query" && (section.empty() || section == "rule")) {
                    ml_target = MultilineTarget::Query;
                    ml_delim = delim;
                    ml_buf = rest + "\n";
                }
                continue;
            }

            // Check for multiline array start
            if (!val_raw.empty() && val_raw.front() == '[' && val_raw.find(']') == std::string::npos) {
                if ((key == "tags" || key == "os_list") && (section.empty() || section == "rule")) {
                    arr_target = (key == "tags") ? ArrayTarget::Tags : ArrayTarget::OsList;
                    arr_buf = val_raw + "\n";
                }
                continue;
            }

            const bool in_rule_section = section.empty() || section == "rule";
            const bool in_threat_section =
                section.find("threat") != std::string::npos && section.find("tactic") == std::string::npos;

            if (in_rule_section) {
                if (key == "id" || key == "rule_id") {
                    rule.rule_id = stripQuotes(val_raw);
                } else if (key == "name") {
                    rule.title = stripQuotes(val_raw);
                } else if (key == "severity") {
                    rule.severity = toLower(stripQuotes(val_raw));
                    has_severity = true;
                    if (!has_risk_score) {
                        rule.risk_score = severityToRisk(rule.severity);
                    }
                } else if (key == "risk_score") {
                    try {
                        const long parsed = std::stol(stripQuotes(val_raw));
                        if (parsed >= 0) {
                            rule.risk_score = static_cast<uint32_t>(parsed);
                            has_risk_score = true;
                        }
                    } catch (...) {
                    }
                } else if (key == "description") {
                    rule.description = stripQuotes(val_raw);
                } else if (key == "query") {
                    query_text = stripQuotes(val_raw);
                } else if (key == "os_list" || key == "os") {
                    if (!val_raw.empty() && val_raw.front() == '[') {
                        applyOsList(parseTomlStringList(val_raw));
                    } else {
                        applyOsList({stripQuotes(val_raw)});
                    }
                } else if (key == "tags") {
                    applyTags(parseTomlStringList(val_raw));
                }
            } else if (in_threat_section && key == "id") {
                std::string tid = stripQuotes(val_raw);
                if (tid.size() >= 5 && (tid[0] == 'T' || tid[0] == 't') &&
                    std::isdigit(static_cast<unsigned char>(tid[1]))) {
                    tid[0] = 'T';
                    appendUnique(rule.mitre_techniques, std::move(tid));
                }
            }
        }

        if (rule.title.empty() && rule.rule_id.empty() && query_text.empty()) {
            return 0;
        }
        if (rule.rule_id.empty()) {
            rule.rule_id = "ELASTIC-" + std::to_string(rules_.size() + 1);
        }
        if (rule.title.empty()) {
            rule.title = rule.rule_id;
        }
        if (!has_risk_score && has_severity) {
            rule.risk_score = severityToRisk(rule.severity);
        }
        rule.source_file = source_file;
        extractElasticRuleIndicators(query_text, rule.title, rule.description, rule);

        size_t count = 0;
        for (const auto &api : rule.apis) {
            if (!isCleanApiSymbol(api))
                continue;
            DatasetApiEntry entry;
            entry.symbol = api;
            entry.category = "ElasticRule";
            entry.severity = rule.severity;
            entry.risk_score = rule.risk_score;
            entry.rule_id = rule.rule_id;
            entry.title = rule.title;
            entry.description = rule.description;
            entry.mitre_techniques = rule.mitre_techniques;
            entry.source_file = source_file;
            indexApiEntry(std::move(entry));
            ++count;
        }

        rules_.push_back(std::move(rule));
        ++count;
        return count;
    }

    std::vector<DatasetApiEntry> DatasetLoader::matchSymbol(std::string_view symbol) const {
        std::vector<DatasetApiEntry> matches;
        if (auto it = api_index_.find(std::string(symbol)); it != api_index_.end()) {
            matches.insert(matches.end(), it->second.begin(), it->second.end());
        }
        const std::string short_sym = normalizeSymbolKey(symbol);
        if (short_sym != symbol) {
            if (auto it = api_index_.find(short_sym); it != api_index_.end()) {
                matches.insert(matches.end(), it->second.begin(), it->second.end());
            }
        }
        return matches;
    }

    std::vector<DatasetRule> DatasetLoader::matchSequence(const std::vector<std::string> &call_symbols) const {
        std::vector<DatasetRule> matched;
        for (const auto &rule : rules_) {
            if (rule.sequence.empty())
                continue;
            size_t seq_idx = 0;
            for (const auto &sym : call_symbols) {
                const std::string short_sym = normalizeSymbolKey(sym);
                if (sym == rule.sequence[seq_idx] || short_sym == rule.sequence[seq_idx]) {
                    ++seq_idx;
                    if (seq_idx == rule.sequence.size()) {
                        matched.push_back(rule);
                        break;
                    }
                }
            }
        }
        return matched;
    }

    std::vector<DatasetRule> DatasetLoader::matchIndicators(const std::vector<std::string> &indicators) const {
        std::vector<DatasetRule> matched;
        if (indicators.empty()) {
            return matched;
        }

        std::vector<uint32_t> candidate_ids;
        candidate_ids.reserve(fallback_rule_ids_.size() + 32);
        for (const auto &ind : indicators) {
            ac_automaton_.matchAll(ind, candidate_ids);
        }
        candidate_ids.insert(candidate_ids.end(), fallback_rule_ids_.begin(), fallback_rule_ids_.end());
        std::sort(candidate_ids.begin(), candidate_ids.end());
        candidate_ids.erase(std::unique(candidate_ids.begin(), candidate_ids.end()), candidate_ids.end());

        for (const uint32_t rule_idx : candidate_ids) {
            if (rule_idx >= rules_.size())
                continue;
            const auto &rule = rules_[rule_idx];
            bool is_match = false;

            if (!rule.condition_expr.empty() && !rule.selections.empty()) {
                SigmaConditionParser parser(rule.condition_expr);
                if (const auto ast = parser.parse()) {
                    is_match = evalSigmaCondNode(*ast, rule, indicators);
                }
            } else if (!rule.selections.empty()) {
                for (const auto &[sel_name, patterns] : rule.selections) {
                    (void)patterns;
                    if (evalRuleSelection(rule, sel_name, indicators)) {
                        is_match = true;
                        break;
                    }
                }
            } else if (!rule.apis.empty()) {
                is_match = selectionMatchesIndicators(rule.apis, indicators);
            } else if (!rule.sequence.empty()) {
                size_t seq_idx = 0;
                for (const auto &ind : indicators) {
                    const std::string short_ind = normalizeSymbolKey(ind);
                    if (ind == rule.sequence[seq_idx] || short_ind == rule.sequence[seq_idx]) {
                        ++seq_idx;
                        if (seq_idx == rule.sequence.size()) {
                            is_match = true;
                            break;
                        }
                    }
                }
            }

            if (is_match) {
                matched.push_back(rule);
            }
        }

        // Match LOLBAS binary names against command/path/executable indicators.
        bool has_cmd_or_path = false;
        for (const auto &ind : indicators) {
            if (isCommandOrPathIndicator(ind)) {
                has_cmd_or_path = true;
                break;
            }
        }
        if (has_cmd_or_path) {
            std::vector<std::string> seen_lolbas_ids;
            for (const auto &[sym, entries] : api_index_) {
                if (sym.size() < 4)
                    continue;
                for (const auto &entry : entries) {
                    if (entry.category != "LOLBAS")
                        continue;
                    bool sym_matched = false;
                    for (const auto &ind : indicators) {
                        if (!isCommandOrPathIndicator(ind))
                            continue;
                        if (containsInsensitiveWordBoundary(ind, entry.symbol)) {
                            sym_matched = true;
                            break;
                        }
                    }
                    if (!sym_matched)
                        continue;
                    if (std::find(seen_lolbas_ids.begin(), seen_lolbas_ids.end(), entry.rule_id) !=
                        seen_lolbas_ids.end()) {
                        continue;
                    }
                    seen_lolbas_ids.push_back(entry.rule_id);
                    DatasetRule lolbas_rule;
                    lolbas_rule.rule_id = entry.rule_id;
                    lolbas_rule.title = entry.title;
                    lolbas_rule.severity = entry.severity;
                    lolbas_rule.risk_score = entry.risk_score;
                    lolbas_rule.target_os = "windows";
                    lolbas_rule.description = entry.description;
                    lolbas_rule.apis.push_back(entry.symbol);
                    lolbas_rule.mitre_techniques = entry.mitre_techniques;
                    lolbas_rule.source_file = entry.source_file;
                    matched.push_back(std::move(lolbas_rule));
                }
            }
        }

        return matched;
    }

} // namespace traceql
