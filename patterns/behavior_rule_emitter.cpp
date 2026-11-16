#include "patterns/behavior_rule_emitter.h"
#include "analysis/dataset_loader.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace traceql {
    namespace {

        std::string toLowerAscii(std::string_view input) {
            std::string out;
            out.reserve(input.size());
            for (unsigned char ch : input) {
                out.push_back(static_cast<char>(std::tolower(ch)));
            }
            return out;
        }

        bool containsInsensitive(std::string_view haystack, std::string_view needle) {
            if (needle.empty() || haystack.size() < needle.size()) {
                return false;
            }
            const std::string h = toLowerAscii(haystack);
            const std::string n = toLowerAscii(needle);
            return h.find(n) != std::string::npos;
        }

        bool hasAnyToken(const std::vector<std::string> &items, std::initializer_list<std::string_view> tokens) {
            for (const auto &item : items) {
                for (const auto token : tokens) {
                    if (containsInsensitive(item, token)) {
                        return true;
                    }
                }
            }
            return false;
        }

        bool hasToken(std::string_view value, std::initializer_list<std::string_view> tokens) {
            for (const auto token : tokens) {
                if (containsInsensitive(value, token)) {
                    return true;
                }
            }
            return false;
        }

        void appendUnique(std::vector<std::string> &dst, std::string value) {
            if (value.empty()) {
                return;
            }
            if (std::find(dst.begin(), dst.end(), value) == dst.end()) {
                dst.push_back(std::move(value));
            }
        }

        void appendUniqueAll(std::vector<std::string> &dst, const std::vector<std::string> &src) {
            for (const auto &item : src) {
                appendUnique(dst, item);
            }
        }

        std::string normalizeOs(std::string_view target_os) {
            const std::string lower = toLowerAscii(target_os);
            if (lower == "windows" || lower == "win32" || lower == "win64") {
                return "windows";
            }
            if (lower == "linux" || lower == "posix" || lower == "unix") {
                return "linux";
            }
            if (lower == "android" || lower == "bionic" || lower == "ndk") {
                return "android";
            }
            if (lower.empty() || lower == "auto") {
                return "auto";
            }
            return lower;
        }

        std::string inferOsFromObservations(const std::vector<BehaviorCallObservation> &calls,
                                            const std::vector<BehaviorSequenceObservation> &sequences,
                                            std::string_view requested_os) {
            const std::string norm = normalizeOs(requested_os);
            if (norm != "auto") {
                return norm;
            }

            bool seen_windows = false;
            bool seen_linux = false;
            bool seen_android = false;

            auto checkTag = [&](std::string_view text) {
                if (hasToken(text, {"windows", "win32", "peb", "seh", "veh"})) {
                    seen_windows = true;
                }
                if (hasToken(text, {"android", "bionic", "ndk", "jni", "dalvik", "art"})) {
                    seen_android = true;
                }
                if (hasToken(text, {"linux", "elf", "procfs", "glibc", "musl"})) {
                    seen_linux = true;
                }
            };

            for (const auto &call : calls) {
                checkTag(call.behavior_category);
                for (const auto &tag : call.behavior_tags) {
                    checkTag(tag);
                }
                if (containsInsensitive(call.library, ".dll")) {
                    seen_windows = true;
                } else if (containsInsensitive(call.library, ".so")) {
                    if (!seen_android) {
                        seen_linux = true;
                    }
                }
            }

            for (const auto &seq : sequences) {
                for (const auto &tag : seq.behavior_chain_tags) {
                    checkTag(tag);
                }
            }

            const int count = (seen_windows ? 1 : 0) + (seen_linux ? 1 : 0) + (seen_android ? 1 : 0);
            if (count == 1) {
                if (seen_windows) {
                    return "windows";
                }
                if (seen_android) {
                    return "android";
                }
                if (seen_linux) {
                    return "linux";
                }
            }
            if (seen_android && seen_linux && !seen_windows) {
                return "android";
            }
            return "cross-platform";
        }

        uint32_t severityRank(std::string_view severity) {
            if (severity == "critical") {
                return 4;
            }
            if (severity == "high") {
                return 3;
            }
            if (severity == "medium") {
                return 2;
            }
            return 1;
        }

        std::string severityFromScore(uint32_t score, uint32_t threshold) {
            if (score >= std::max<uint32_t>(85, threshold * 2)) {
                return "critical";
            }
            if (score >= std::max<uint32_t>(65, threshold + 20)) {
                return "high";
            }
            if (score >= threshold) {
                return "medium";
            }
            return "low";
        }

        std::string maxSeverity(std::string_view a, std::string_view b) {
            return severityRank(a) >= severityRank(b) ? std::string(a) : std::string(b);
        }

        std::string escalateSeverityOneTier(std::string_view severity) {
            if (severity == "critical" || severity == "high") {
                return "critical";
            }
            if (severity == "medium") {
                return "high";
            }
            return "medium";
        }

        void escalateForAutoInit(BehaviorFinding &f, bool is_auto_init, std::string_view entrypoint_kind,
                                 uint32_t risk_threshold) {
            if (!is_auto_init || f.risk_score < risk_threshold) {
                return;
            }
            f.risk_score = std::min<uint32_t>(100, f.risk_score + 10);
            f.severity = escalateSeverityOneTier(f.severity);
            appendUnique(f.indicators, entrypoint_kind.empty()
                                           ? std::string("auto_init_entrypoint")
                                           : ("auto_init_entrypoint:" + std::string(entrypoint_kind)));
            appendUnique(f.mitre_techniques, "T1547");
        }

        std::string sarifLevelFromSeverity(std::string_view severity) {
            if (severity == "critical" || severity == "high") {
                return "error";
            }
            if (severity == "medium") {
                return "warning";
            }
            return "note";
        }

        std::string formatDouble(double val) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(2) << val;
            return oss.str();
        }

        std::string buildCallIndicator(const BehaviorCallObservation &call) {
            std::ostringstream oss;
            if (!call.file.empty()) {
                oss << call.file << ":" << call.line << " ";
            }
            if (!call.behavior_category.empty()) {
                oss << "[" << call.behavior_category << "] ";
            }
            if (!call.pattern.empty()) {
                oss << call.pattern;
            } else if (!call.symbol.empty()) {
                oss << call.symbol;
            } else if (!call.kind.empty()) {
                oss << call.kind;
            }
            if (call.is_inline_asm) {
                oss << " (inline_asm)";
            }
            if (call.is_indirect_call) {
                oss << " (indirect_call)";
            }
            if (!call.resolved_from_symbol.empty()) {
                oss << " (resolved_from=" << call.resolved_from_symbol << ")";
            }
            return oss.str();
        }

        /// @brief Deterministic FNV-1a-based UUIDv4-formatted identifier for Sigma rules.
        std::string deterministicRuleUuid(std::string_view rule_id, std::string_view caller,
                                          std::string_view target_os) {
            auto fnv1a = [](std::string_view s, uint64_t seed) -> uint64_t {
                uint64_t h = seed;
                for (unsigned char c : s) {
                    h ^= c;
                    h *= 1099511628211ULL;
                }
                return h;
            };

            uint64_t hi = fnv1a(rule_id, 14695981039346656037ULL);
            hi = fnv1a("|", hi);
            hi = fnv1a(caller, hi);

            uint64_t lo = fnv1a(target_os, 14695981039346656037ULL ^ 0x9e3779b97f4a7c15ULL);
            lo = fnv1a("|", lo);
            lo = fnv1a(rule_id, lo);
            lo = fnv1a(caller, lo);

            // Set UUID version 4 and RFC 4122 variant bits.
            hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
            lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

            char buf[40];
            std::snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%04x-%04x%08x",
                          static_cast<uint32_t>((hi >> 32) & 0xFFFFFFFFU), static_cast<uint32_t>((hi >> 16) & 0xFFFFU),
                          static_cast<uint32_t>(hi & 0xFFFFU), static_cast<uint32_t>((lo >> 48) & 0xFFFFU),
                          static_cast<uint32_t>((lo >> 32) & 0xFFFFU), static_cast<uint32_t>(lo & 0xFFFFFFFFU));
            return std::string(buf);
        }

        std::string formatMitreSigmaTag(std::string_view technique) {
            std::string tag = "attack.";
            for (unsigned char ch : technique) {
                if (ch == ' ') {
                    tag.push_back('_');
                } else {
                    tag.push_back(static_cast<char>(std::tolower(ch)));
                }
            }
            return tag;
        }

        struct FindingAggregator {
            std::unordered_map<std::string, size_t> index_by_key;
            std::vector<BehaviorFinding> findings;

            void merge(BehaviorFinding candidate) {
                const std::string key = candidate.rule_id + "\n" + candidate.caller;
                auto it = index_by_key.find(key);
                if (it == index_by_key.end()) {
                    index_by_key.emplace(key, findings.size());
                    findings.push_back(std::move(candidate));
                    return;
                }
                BehaviorFinding &existing = findings[it->second];
                existing.severity = maxSeverity(existing.severity, candidate.severity);
                existing.risk_score = std::max(existing.risk_score, candidate.risk_score);
                existing.entropy = std::max(existing.entropy, candidate.entropy);
                if (existing.file.empty() && !candidate.file.empty()) {
                    existing.file = candidate.file;
                    existing.line = candidate.line;
                    existing.column = candidate.column;
                } else if (existing.line == 0 && candidate.line > 0) {
                    existing.line = candidate.line;
                    existing.column = candidate.column;
                }
                appendUniqueAll(existing.indicators, candidate.indicators);
                appendUniqueAll(existing.mitre_techniques, candidate.mitre_techniques);
            }
        };

        void appendOsSpecificInjectionTechniques(std::vector<std::string> &techniques, std::string_view os,
                                                 const std::vector<std::string> &tags) {
            appendUnique(techniques, "T1055");
            if (os == "windows") {
                if (hasAnyToken(tags, {"hollow"})) {
                    appendUnique(techniques, "T1055.012");
                }
                if (hasAnyToken(tags, {"thread", "hijack"})) {
                    appendUnique(techniques, "T1055.003");
                }
                if (hasAnyToken(tags, {"dll", "module"})) {
                    appendUnique(techniques, "T1055.001");
                }
            } else if (os == "linux" || os == "android") {
                if (hasAnyToken(tags, {"proc_mem", "ptrace"})) {
                    appendUnique(techniques, "T1055.009");
                }
            }
        }

        bool isSuspiciousArgLiteral(std::string_view lit) {
            if (lit.empty()) {
                return false;
            }
            return hasToken(lit, {"/etc/", "/proc/", "/dev/", "hklm", "hkey_", ".exe", "sh ", "bash", "curl", "wget",
                                  "nc ", "python", "base64", "certutil"});
        }

        std::vector<std::string> extractLiteralSymbolCandidates(std::string_view lit) {
            std::vector<std::string> candidates;
            appendUnique(candidates, std::string(lit));

            auto isDelim = [](char c) {
                return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ';' || c == '|' || c == '&' ||
                       c == '\'' || c == '"' || c == '(' || c == ')';
            };

            size_t pos = 0;
            while (pos < lit.size()) {
                while (pos < lit.size() && isDelim(lit[pos])) {
                    ++pos;
                }
                if (pos >= lit.size()) {
                    break;
                }
                size_t end = pos;
                while (end < lit.size() && !isDelim(lit[end])) {
                    ++end;
                }
                const std::string_view tok = lit.substr(pos, end - pos);
                if (!tok.empty()) {
                    appendUnique(candidates, std::string(tok));
                    const size_t slash = tok.find_last_of("/\\");
                    if (slash != std::string_view::npos && slash + 1 < tok.size()) {
                        appendUnique(candidates, std::string(tok.substr(slash + 1)));
                    }
                }
                pos = end;
            }

            return candidates;
        }

    } // namespace

    std::vector<BehaviorFinding> BehaviorRuleEmitter::analyzeFindings(
        const std::vector<BehaviorCallObservation> &calls, const std::vector<BehaviorSequenceObservation> &sequences,
        std::string_view target_os, uint32_t risk_threshold, double entropy_threshold, const DatasetLoader *dataset) {
        const std::string resolved_os = inferOsFromObservations(calls, sequences, target_os);
        FindingAggregator aggregator;

        // 1. Evaluate multi-step behavioral sequences.
        for (const auto &seq : sequences) {
            const std::string caller = seq.caller.empty() ? "<unknown>" : seq.caller;
            const double seq_entropy = seq.max_arg_entropy;
            const auto &tags = seq.behavior_chain_tags;

            const bool has_injection_chain = hasAnyToken(tags, {"process_injection", "injection", "cross_process",
                                                                "remote_thread", "process_hollowing", "proc_mem"}) ||
                                             (hasAnyToken(tags, {"memory_alloc", "memory_allocation"}) &&
                                              hasAnyToken(tags, {"memory_write", "cross_process"}) &&
                                              hasAnyToken(tags, {"thread_exec", "remote_thread", "execution"}));

            const bool has_rwx_chain = hasAnyToken(tags, {"rwx", "wx_transition", "exec_mem"}) ||
                                       (hasAnyToken(tags, {"memory_alloc", "memory_allocation", "memory_protection"}) &&
                                        hasAnyToken(tags, {"exec", "shellcode", "code_staging"}));

            const bool has_dynamic_resolve_chain =
                hasAnyToken(tags, {"dynamic_resolution", "dynamic_api", "symbol_resolve", "peb_walk"}) &&
                hasAnyToken(tags, {"indirect_call", "indirect_dispatch", "api_hashing", "obfuscation"});

            const bool has_syscall_chain =
                hasAnyToken(tags, {"direct_syscall", "indirect_syscall", "syscall", "inline_asm"});

            const bool has_antidebug_chain =
                hasAnyToken(tags, {"anti_debug", "anti_analysis", "debugger_check", "sandbox_evasion", "root_detection",
                                   "instrumentation_check"});

            const bool has_high_entropy_chain =
                (seq.max_arg_entropy >= entropy_threshold && seq.caller_risk_score >= risk_threshold) ||
                hasAnyToken(tags, {"high_entropy_payload_staging", "obfuscated_payload", "encrypted_payload"});

            auto makeSeqIndicators = [&]() {
                std::vector<std::string> indicators;
                if (!seq.chain.empty()) {
                    std::string chain_str = "chain: ";
                    for (size_t i = 0; i < seq.chain.size(); ++i) {
                        if (i > 0) {
                            chain_str += " -> ";
                        }
                        chain_str += seq.chain[i];
                    }
                    indicators.push_back(std::move(chain_str));
                }
                for (const auto &tag : tags) {
                    appendUnique(indicators, "tag:" + tag);
                }
                return indicators;
            };

            auto emitSeqFinding = [&](BehaviorFinding f) {
                escalateForAutoInit(f, seq.is_auto_init_entrypoint, seq.entrypoint_kind, risk_threshold);
                aggregator.merge(std::move(f));
            };

            bool matched_specific = false;

            if (has_injection_chain) {
                matched_specific = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-SEQ-INJECTION-001";
                f.title = "Cross-Process Memory Staging and Injection Sequence";
                f.severity = (seq.caller_risk_score >= 80 || has_syscall_chain) ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                f.indicators = makeSeqIndicators();
                appendOsSpecificInjectionTechniques(f.mitre_techniques, resolved_os, tags);
                appendUnique(f.mitre_techniques, "TA0005");
                f.risk_score = std::max<uint32_t>(seq.caller_risk_score, 75);
                f.entropy = seq_entropy;
                f.description = "Detected multi-step behavioral chain consistent with cross-process "
                                "memory allocation, payload staging, and remote execution.";
                emitSeqFinding(std::move(f));
            }

            if (has_rwx_chain) {
                matched_specific = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-SEQ-RWX-002";
                f.title = "Executable Memory (RWX / W^X) Staging Sequence";
                f.severity = (seq.caller_risk_score >= 80 || seq_entropy >= entropy_threshold) ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                f.indicators = makeSeqIndicators();
                appendUnique(f.mitre_techniques, "T1055");
                appendUnique(f.mitre_techniques, "T1620");
                appendUnique(f.mitre_techniques, "T1027");
                f.risk_score = std::max<uint32_t>(seq.caller_risk_score, 70);
                f.entropy = seq_entropy;
                f.description = "Detected behavioral sequence allocating or transitioning memory to "
                                "writable-executable (RWX) or W^X permissions for in-memory code staging.";
                emitSeqFinding(std::move(f));
            }

            if (has_dynamic_resolve_chain) {
                matched_specific = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-SEQ-DYNRES-003";
                f.title = "Dynamic API Resolution Coupled with Indirect Invocation";
                f.severity = (seq.caller_risk_score >= 75 || has_high_entropy_chain) ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                f.indicators = makeSeqIndicators();
                appendUnique(f.mitre_techniques, "T1027");
                appendUnique(f.mitre_techniques, "T1106");
                appendUnique(f.mitre_techniques, "T1574");
                f.risk_score = std::max<uint32_t>(seq.caller_risk_score, 65);
                f.entropy = seq_entropy;
                f.description = "Detected runtime symbol resolution followed by indirect dispatch, "
                                "characteristic of import-table hiding and API-hashing loaders.";
                emitSeqFinding(std::move(f));
            }

            if (has_syscall_chain) {
                matched_specific = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-SEQ-SYSCALL-004";
                f.title = "Direct or Indirect Syscall Hook-Evasion Sequence";
                f.severity =
                    (has_rwx_chain || has_injection_chain || seq.caller_risk_score >= 75) ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                f.indicators = makeSeqIndicators();
                appendUnique(f.mitre_techniques, "T1106");
                appendUnique(f.mitre_techniques, "T1562");
                appendUnique(f.mitre_techniques, "TA0005");
                f.risk_score = std::max<uint32_t>(seq.caller_risk_score, 75);
                f.entropy = seq_entropy;
                f.description = "Detected direct/indirect syscall or inline assembly transition "
                                "bypassing standard user-mode API hooking boundaries.";
                emitSeqFinding(std::move(f));
            }

            if (has_antidebug_chain) {
                matched_specific = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-SEQ-EVASION-005";
                f.title = "Anti-Debug and Environmental Evasion Sequence";
                f.severity = seq.caller_risk_score >= std::max<uint32_t>(70, risk_threshold * 2) ? "high" : "medium";
                f.target_os = resolved_os;
                f.caller = caller;
                f.indicators = makeSeqIndicators();
                appendUnique(f.mitre_techniques, "T1622");
                appendUnique(f.mitre_techniques, "T1497");
                appendUnique(f.mitre_techniques, "T1562");
                f.risk_score = std::max<uint32_t>(seq.caller_risk_score, 50);
                f.entropy = seq_entropy;
                f.description = "Detected anti-debugging, instrumentation-check, or sandbox-evasion "
                                "behavioral sequence.";
                emitSeqFinding(std::move(f));
            }

            if (has_high_entropy_chain && seq.caller_risk_score >= risk_threshold) {
                matched_specific = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-SEQ-ENTROPY-006";
                f.title = "High-Entropy Obfuscated Payload Sequence";
                f.severity =
                    (seq_entropy >= entropy_threshold + 1.5 || seq.caller_risk_score >= 75) ? "high" : "medium";
                f.target_os = resolved_os;
                f.caller = caller;
                f.indicators = makeSeqIndicators();
                appendUnique(f.mitre_techniques, "T1027");
                appendUnique(f.mitre_techniques, "T1140");
                f.risk_score = std::max<uint32_t>(seq.caller_risk_score, 55);
                f.entropy = seq_entropy;
                f.description = "Detected call sequence operating on high-entropy or obfuscated "
                                "literals/payloads exceeding threshold (" +
                                formatDouble(entropy_threshold) + ").";
                emitSeqFinding(std::move(f));
            }

            if (!matched_specific && seq.caller_risk_score >= risk_threshold) {
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-SEQ-RISK-007";
                f.title = "Elevated-Risk Behavioral Call Sequence";
                f.severity = severityFromScore(seq.caller_risk_score, risk_threshold);
                f.target_os = resolved_os;
                f.caller = caller;
                f.indicators = makeSeqIndicators();
                appendUnique(f.mitre_techniques, "TA0002");
                f.risk_score = seq.caller_risk_score;
                f.entropy = seq_entropy;
                f.description = "Detected behavioral call sequence exceeding configured risk threshold.";
                emitSeqFinding(std::move(f));
            }
        }

        // 2. Evaluate individual call-site observations.
        for (const auto &call : calls) {
            const std::string caller = call.caller.empty() ? "<unknown>" : call.caller;
            const bool high_entropy =
                (call.has_high_entropy_literal || call.arg_entropy >= entropy_threshold) &&
                (call.risk_score >= risk_threshold || hasAnyToken(call.behavior_tags, {"xor_decoding_loop"}));
            const bool is_syscall = hasToken(call.behavior_category, {"directsyscall", "direct_syscall"}) ||
                                    hasAnyToken(call.behavior_tags, {"direct_syscall", "indirect_syscall"});
            const bool is_dyn_resolve =
                !call.resolved_from_symbol.empty() ||
                hasToken(call.behavior_category, {"dynamicresolution", "dynamic_resolution", "dynamic_api"}) ||
                hasAnyToken(call.behavior_tags,
                            {"dynamic_resolution", "dynamic_resolve", "peb_teb_access", "fn_ptr_cast"});
            const bool is_rwx = hasToken(call.behavior_category, {"memory_protection", "memory_allocation"}) &&
                                hasAnyToken(call.behavior_tags, {"rwx", "wx_transition", "exec_mem", "executable"});
            const bool is_rwx_tag = hasAnyToken(call.behavior_tags, {"rwx", "wx_transition"});
            const bool is_injection =
                hasToken(call.behavior_category, {"process_injection", "injection"}) ||
                hasAnyToken(call.behavior_tags, {"process_injection", "cross_process", "remote_thread"});
            const bool is_antidebug = hasToken(call.behavior_category, {"anti_debug", "evasion", "anti_analysis"}) ||
                                      hasAnyToken(call.behavior_tags, {"anti_debug", "anti_analysis", "sandbox_evasion",
                                                                       "debugger_check", "root_detection"});
            const bool is_api_hashing =
                hasAnyToken(call.behavior_tags, {"api_hashing"}) && call.risk_score >= risk_threshold;
            const bool is_tainted_exec =
                call.tainted_exec_flow ||
                hasAnyToken(call.behavior_tags, {"tainted_buffer_exec_flow", "cross_tu_taint_summary"});
            const bool is_dangling_lifetime =
                call.lifetime_kind == "dangling_view" || call.lifetime_kind == "stack_escape";
            const bool is_uaf_lifetime = call.lifetime_kind == "use_after_free" || call.lifetime_kind == "double_free";
            const bool is_ast_vs_ir_delta = hasAnyToken(call.behavior_tags, {"ast_vs_ir_delta"});
            const bool is_lock_inversion = hasAnyToken(call.behavior_tags, {"lock_order_inversion"});
            const bool is_lock_unclosed =
                call.lifetime_kind == "lock_unclosed" || hasAnyToken(call.behavior_tags, {"lock_unclosed"});

            const std::string indicator = buildCallIndicator(call);
            auto emitCallFinding = [&](BehaviorFinding f) {
                f.file = call.file;
                f.line = call.line;
                f.column = call.column;
                escalateForAutoInit(f, call.is_auto_init_entrypoint, call.entrypoint_kind, risk_threshold);
                aggregator.merge(std::move(f));
            };

            // External dataset API matching runs regardless of built-in risk_score.
            // Skip C++ namespaced/member symbols (e.g. std::basic_string::find, bgfx::touch)
            // unless it is a global-namespace qualifier (::foo).
            const bool is_cpp_namespaced_symbol =
                call.symbol.find("::") != std::string::npos &&
                !(call.symbol.rfind("::", 0) == 0 && call.symbol.find("::", 2) == std::string::npos);
            if (dataset != nullptr && !call.symbol.empty() && !is_cpp_namespaced_symbol) {
                for (const auto &entry : dataset->matchSymbol(call.symbol)) {
                    if (entry.risk_score < risk_threshold)
                        continue;
                    BehaviorFinding f;
                    f.rule_id = entry.rule_id;
                    f.title = entry.title;
                    f.severity =
                        entry.severity.empty() ? severityFromScore(entry.risk_score, risk_threshold) : entry.severity;
                    f.target_os = resolved_os;
                    f.caller = caller;
                    appendUnique(f.indicators, indicator);
                    for (const auto &m : entry.mitre_techniques) {
                        appendUnique(f.mitre_techniques, m);
                    }
                    f.risk_score = std::max(entry.risk_score, call.risk_score);
                    f.entropy = call.arg_entropy;
                    f.description = entry.description.empty() ? ("Matched external dataset category: " + entry.category)
                                                              : entry.description;
                    emitCallFinding(std::move(f));
                }
            }

            if (dataset != nullptr && !call.arg_literals.empty()) {
                for (const auto &lit : call.arg_literals) {
                    if (!isSuspiciousArgLiteral(lit)) {
                        continue;
                    }
                    for (const auto &candidate : extractLiteralSymbolCandidates(lit)) {
                        for (const auto &entry : dataset->matchSymbol(candidate)) {
                            if (entry.risk_score < risk_threshold)
                                continue;
                            BehaviorFinding f;
                            f.rule_id = entry.rule_id;
                            f.title = entry.title;
                            f.severity = entry.severity.empty() ? severityFromScore(entry.risk_score, risk_threshold)
                                                                : entry.severity;
                            f.target_os = resolved_os;
                            f.caller = caller;
                            appendUnique(f.indicators, indicator);
                            appendUnique(f.indicators, "arg_literal:" + lit);
                            for (const auto &m : entry.mitre_techniques) {
                                appendUnique(f.mitre_techniques, m);
                            }
                            f.risk_score = std::max(entry.risk_score, call.risk_score);
                            f.entropy = call.arg_entropy;
                            f.description = entry.description.empty()
                                                ? ("Matched external dataset category: " + entry.category)
                                                : entry.description;
                            emitCallFinding(std::move(f));
                        }
                    }
                }
            }

            const bool exceeds_risk = call.risk_score >= risk_threshold;
            if (!exceeds_risk && !high_entropy && !is_syscall && !is_dyn_resolve && !is_rwx && !is_rwx_tag &&
                !is_injection && !is_antidebug && !is_api_hashing && !is_tainted_exec && !is_dangling_lifetime &&
                !is_uaf_lifetime && !is_ast_vs_ir_delta && !is_lock_inversion && !is_lock_unclosed) {
                continue;
            }

            bool matched_call_rule = false;

            if (is_syscall) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-SYSCALL-001";
                f.title = "Direct Syscall or Inline Assembly Invocation";
                f.severity = (call.risk_score >= 75 || high_entropy) ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.mitre_techniques, "T1106");
                appendUnique(f.mitre_techniques, "T1562");
                f.risk_score = std::max<uint32_t>(call.risk_score, 70);
                f.entropy = call.arg_entropy;
                f.description = "Call site uses inline assembly or direct syscall semantics that may "
                                "bypass user-mode runtime instrumentation.";
                emitCallFinding(std::move(f));
            }

            if (is_injection) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-INJECTION-002";
                f.title = "Process Injection Behavioral Call Site";
                f.severity = call.risk_score >= 80 ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendOsSpecificInjectionTechniques(f.mitre_techniques, resolved_os, call.behavior_tags);
                f.risk_score = std::max<uint32_t>(call.risk_score, 75);
                f.entropy = call.arg_entropy;
                f.description = "Call site exhibits cross-process memory or thread manipulation behavior.";
                emitCallFinding(std::move(f));
            }

            if (is_rwx || is_rwx_tag) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-RWX-003";
                f.title = "Executable Memory Allocation or Protection Change (RWX / W^X)";
                f.severity = (call.risk_score >= 75 || high_entropy) ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.mitre_techniques, "T1055");
                appendUnique(f.mitre_techniques, "T1620");
                f.risk_score = std::max<uint32_t>(call.risk_score, 65);
                f.entropy = call.arg_entropy;
                f.description = "Call site requests or transitions executable memory permissions.";
                emitCallFinding(std::move(f));
            }

            if (is_dyn_resolve) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-DYNRES-004";
                f.title = "Dynamic Symbol Resolution or Indirect Call Dispatch";
                f.severity = (call.is_indirect_call && !call.resolved_from_symbol.empty())
                                 ? "high"
                                 : severityFromScore(std::max<uint32_t>(call.risk_score, 45), risk_threshold);
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.mitre_techniques, "T1027");
                appendUnique(f.mitre_techniques, "T1106");
                f.risk_score = std::max<uint32_t>(call.risk_score, 50);
                f.entropy = call.arg_entropy;
                f.description = "Call site performs dynamic API resolution or invokes a function pointer "
                                "resolved at runtime.";
                emitCallFinding(std::move(f));
            }

            if (is_antidebug) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-EVASION-005";
                f.title = "Anti-Debugging or Analysis Evasion Call Site";
                f.severity = severityFromScore(std::max<uint32_t>(call.risk_score, 45), risk_threshold);
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.mitre_techniques, "T1622");
                appendUnique(f.mitre_techniques, "T1497");
                f.risk_score = std::max<uint32_t>(call.risk_score, 45);
                f.entropy = call.arg_entropy;
                f.description = "Call site performs debugger, tracer, root, or sandbox detection.";
                emitCallFinding(std::move(f));
            }

            if (high_entropy) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-ENTROPY-006";
                f.title = "High-Entropy Argument or Obfuscated Literal";
                f.severity = (call.arg_entropy >= entropy_threshold + 1.5 || call.risk_score >= 75) ? "high" : "medium";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.mitre_techniques, "T1027");
                appendUnique(f.mitre_techniques, "T1140");
                f.risk_score = std::max<uint32_t>(call.risk_score, 50);
                f.entropy = call.arg_entropy;
                f.description = "Call site passes a high-entropy or obfuscated literal argument.";
                emitCallFinding(std::move(f));
            }

            if (is_api_hashing) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-HASH-008";
                f.title = "API Hashing or Cryptographic Constant in Dynamic Context";
                f.severity = call.risk_score >= 75 ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.mitre_techniques, "T1027");
                appendUnique(f.mitre_techniques, "T1027.007");
                appendUnique(f.mitre_techniques, "T1106");
                f.risk_score = std::max<uint32_t>(call.risk_score, 65);
                f.entropy = call.arg_entropy;
                f.description = "Call site uses API-hashing or cryptographic constants in a dynamic "
                                "or loop context to obscure resolved symbols or payloads.";
                emitCallFinding(std::move(f));
            }

            if (is_tainted_exec) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-TAINT-009";
                f.title = "Tainted Buffer-to-Execution Flow (Intra/Cross-TU)";
                f.severity = call.risk_score >= 75 ? "critical" : "high";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.mitre_techniques, "T1055");
                appendUnique(f.mitre_techniques, "T1620");
                f.risk_score = std::max<uint32_t>(call.risk_score, 65);
                f.entropy = call.arg_entropy;
                f.description = "Tainted allocation or dynamic resolution data flows into an "
                                "executable memory or sink invocation.";
                emitCallFinding(std::move(f));
            }

            if (is_dangling_lifetime) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-LIFE-DANGLING-010";
                f.title = "Dangling View or Escaping Stack Reference";
                f.severity = "high";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.indicators, "lifetime:" + call.lifetime_kind);
                f.risk_score = std::max<uint32_t>(call.risk_score, 75);
                f.entropy = call.arg_entropy;
                f.description = "Non-owning view or pointer escapes the lifetime of its temporary or stack-allocated "
                                "backing storage.";
                emitCallFinding(std::move(f));
            }

            if (is_uaf_lifetime) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-LIFE-UAF-011";
                f.title = "Use-After-Free or Double-Free Lifetime Violation";
                f.severity = "critical";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.indicators, "lifetime:" + call.lifetime_kind);
                f.risk_score = std::max<uint32_t>(call.risk_score, 85);
                f.entropy = call.arg_entropy;
                f.description = "Detected memory access or deallocation on a previously freed pointer.";
                emitCallFinding(std::move(f));
            }

            if (is_ast_vs_ir_delta) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-DIFF-OBFUSCATION-012";
                f.title = "AST vs IR Differential Obfuscation";
                f.severity = "high";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.indicators, "tag:ast_vs_ir_delta");
                appendUnique(f.mitre_techniques, "T1027");
                f.risk_score = std::max<uint32_t>(call.risk_score, 80);
                f.entropy = call.arg_entropy;
                f.description =
                    "Optimized LLVM IR introduces or reveals call targets absent from source-level AST observations.";
                emitCallFinding(std::move(f));
            }

            if (is_lock_inversion) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-THREAD-DEADLOCK-013";
                f.title = "Potential Deadlock via Lock-Order Inversion";
                f.severity = "high";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.indicators, "tag:lock_order_inversion");
                if (!call.lock_name.empty()) {
                    appendUnique(f.indicators, "lock:" + call.lock_name);
                }
                if (!call.lock_held_prev.empty()) {
                    appendUnique(f.indicators, "lock_prev:" + call.lock_held_prev);
                }
                f.risk_score = std::max<uint32_t>(call.risk_score, 75);
                f.entropy = call.arg_entropy;
                f.description =
                    "Detected conflicting lock acquisition ordering (AB/BA) across functions or translation units.";
                emitCallFinding(std::move(f));
            }

            if (is_lock_unclosed) {
                matched_call_rule = true;
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-THREAD-UNLOCK-014";
                f.title = "Unclosed Lock Acquisition";
                f.severity = "medium";
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.indicators, "tag:lock_unclosed");
                if (!call.lock_name.empty()) {
                    appendUnique(f.indicators, "lock:" + call.lock_name);
                }
                f.risk_score = std::max<uint32_t>(call.risk_score, 60);
                f.entropy = call.arg_entropy;
                f.description = "Lock acquired in function without a matching unlock on all exit paths.";
                emitCallFinding(std::move(f));
            }

            if (!matched_call_rule && exceeds_risk) {
                BehaviorFinding f;
                f.rule_id = "BEHAVIOR-CALL-RISK-007";
                f.title = "High-Risk Behavioral Call Site";
                f.severity = severityFromScore(call.risk_score, risk_threshold);
                f.target_os = resolved_os;
                f.caller = caller;
                appendUnique(f.indicators, indicator);
                appendUnique(f.mitre_techniques, "TA0002");
                f.risk_score = call.risk_score;
                f.entropy = call.arg_entropy;
                f.description = "Call site behavioral risk score exceeded threshold.";
                emitCallFinding(std::move(f));
            }
        }

        // 4. External dataset multi-step sequence and Sigma indicator matching.
        if (dataset != nullptr) {
            std::unordered_map<std::string, std::vector<std::string>> caller_symbols;
            std::unordered_map<std::string, std::vector<std::string>> caller_indicators;
            for (const auto &call : calls) {
                const std::string caller = call.caller.empty() ? "<unknown>" : call.caller;
                if (!call.symbol.empty()) {
                    caller_symbols[caller].push_back(call.symbol);
                    appendUnique(caller_indicators[caller], call.symbol);
                }
                if (!call.resolved_from_symbol.empty()) {
                    appendUnique(caller_indicators[caller], call.resolved_from_symbol);
                }
                for (const auto &tag : call.behavior_tags) {
                    appendUnique(caller_indicators[caller], tag);
                }
                for (const auto &lit : call.arg_literals) {
                    appendUnique(caller_indicators[caller], lit);
                }
            }
            for (const auto &[caller, syms] : caller_symbols) {
                for (const auto &rule : dataset->matchSequence(syms)) {
                    if (rule.risk_score < risk_threshold)
                        continue;
                    BehaviorFinding f;
                    f.rule_id = rule.rule_id;
                    f.title = rule.title;
                    f.severity =
                        rule.severity.empty() ? severityFromScore(rule.risk_score, risk_threshold) : rule.severity;
                    f.target_os = (rule.target_os.empty() || rule.target_os == "auto") ? resolved_os : rule.target_os;
                    f.caller = caller;
                    for (const auto &api : rule.sequence) {
                        appendUnique(f.indicators, api);
                    }
                    for (const auto &m : rule.mitre_techniques) {
                        appendUnique(f.mitre_techniques, m);
                    }
                    f.risk_score = rule.risk_score;
                    f.entropy = 0.0;
                    f.description = rule.description.empty() ? "Matched external dataset behavioral call sequence."
                                                             : rule.description;
                    aggregator.merge(std::move(f));
                }
            }
            for (const auto &[caller, indicators] : caller_indicators) {
                for (const auto &rule : dataset->matchIndicators(indicators)) {
                    if (rule.risk_score < risk_threshold)
                        continue;
                    BehaviorFinding f;
                    f.rule_id = rule.rule_id;
                    f.title = rule.title;
                    f.severity =
                        rule.severity.empty() ? severityFromScore(rule.risk_score, risk_threshold) : rule.severity;
                    f.target_os = (rule.target_os.empty() || rule.target_os == "auto") ? resolved_os : rule.target_os;
                    f.caller = caller;
                    for (const auto &[sel_name, sel_vals] : rule.selections) {
                        (void)sel_name;
                        for (const auto &val : sel_vals) {
                            appendUnique(f.indicators, val);
                        }
                    }
                    for (const auto &api : rule.apis) {
                        appendUnique(f.indicators, api);
                    }
                    if (f.indicators.empty()) {
                        for (const auto &ind : indicators) {
                            appendUnique(f.indicators, ind);
                        }
                    }
                    for (const auto &m : rule.mitre_techniques) {
                        appendUnique(f.mitre_techniques, m);
                    }
                    f.risk_score = rule.risk_score;
                    f.entropy = 0.0;
                    f.description =
                        rule.description.empty() ? "Matched external dataset Sigma/indicator rule." : rule.description;
                    aggregator.merge(std::move(f));
                }
            }
        }

        // Deterministic ordering: severity desc, risk_score desc, rule_id asc, caller asc.
        std::sort(aggregator.findings.begin(), aggregator.findings.end(),
                  [](const BehaviorFinding &a, const BehaviorFinding &b) {
                      const uint32_t ra = severityRank(a.severity);
                      const uint32_t rb = severityRank(b.severity);
                      if (ra != rb) {
                          return ra > rb;
                      }
                      if (a.risk_score != b.risk_score) {
                          return a.risk_score > b.risk_score;
                      }
                      if (a.rule_id != b.rule_id) {
                          return a.rule_id < b.rule_id;
                      }
                      return a.caller < b.caller;
                  });

        return aggregator.findings;
    }

    std::string BehaviorRuleEmitter::toJsonRules(const std::vector<BehaviorFinding> &findings,
                                                 std::string_view target_os) {
        const std::string norm_os = normalizeOs(target_os);
        const std::string effective_os = (norm_os == "auto") ? "cross-platform" : norm_os;

        nlohmann::json findings_arr = nlohmann::json::array();
        for (const auto &f : findings) {
            const std::string &row_os = f.target_os.empty() ? effective_os : f.target_os;
            findings_arr.push_back({
                {"rule_id", f.rule_id},
                {"title", f.title},
                {"severity", f.severity},
                {"target_os", row_os},
                {"caller", f.caller},
                {"file", f.file},
                {"line", f.line},
                {"column", f.column},
                {"risk_score", f.risk_score},
                {"entropy", std::round(f.entropy * 100.0) / 100.0},
                {"mitre_techniques", f.mitre_techniques},
                {"indicators", f.indicators},
                {"description", f.description},
            });
        }

        nlohmann::json root = {
            {"schema", "traceql.behavior_rules.v1"},
            {"target_os", effective_os},
            {"finding_count", findings.size()},
            {"findings", std::move(findings_arr)},
        };
        return root.dump(2) + "\n";
    }

    std::string BehaviorRuleEmitter::toSigmaYaml(const std::vector<BehaviorFinding> &findings,
                                                 std::string_view target_os) {
        const std::string norm_os = normalizeOs(target_os);
        const std::string fallback_os = (norm_os == "auto") ? "cross-platform" : norm_os;

        if (findings.empty()) {
            return "# No behavioral risk findings exceeded thresholds.\n";
        }

        YAML::Emitter out;
        for (const auto &f : findings) {
            const std::string &row_os =
                (norm_os != "auto") ? norm_os : (f.target_os.empty() ? fallback_os : f.target_os);
            const std::string uuid = deterministicRuleUuid(f.rule_id, f.caller, row_os);

            out << YAML::BeginDoc;
            out << YAML::BeginMap;
            out << YAML::Key << "title" << YAML::Value << (f.title + " (" + f.caller + ")");
            out << YAML::Key << "id" << YAML::Value << uuid;
            out << YAML::Key << "status" << YAML::Value << "experimental";
            out << YAML::Key << "description" << YAML::Value << f.description;
            out << YAML::Key << "author" << YAML::Value << "TraceQL";

            if (!f.mitre_techniques.empty()) {
                out << YAML::Key << "tags" << YAML::Value << YAML::BeginSeq;
                for (const auto &tech : f.mitre_techniques) {
                    out << formatMitreSigmaTag(tech);
                }
                out << YAML::EndSeq;
            }

            out << YAML::Key << "logsource" << YAML::Value << YAML::BeginMap;
            if (row_os == "windows") {
                out << YAML::Key << "product" << YAML::Value << "windows";
                out << YAML::Key << "category" << YAML::Value << "process_creation";
            } else if (row_os == "linux") {
                out << YAML::Key << "product" << YAML::Value << "linux";
                out << YAML::Key << "category" << YAML::Value << "process_creation";
            } else if (row_os == "android") {
                out << YAML::Key << "product" << YAML::Value << "android";
                out << YAML::Key << "category" << YAML::Value << "application_behavior";
            } else {
                out << YAML::Key << "category" << YAML::Value << "behavioral_telemetry";
            }
            out << YAML::EndMap;

            out << YAML::Key << "detection" << YAML::Value << YAML::BeginMap;
            out << YAML::Key << "selection" << YAML::Value << YAML::BeginMap;
            out << YAML::Key << "RuleId" << YAML::Value << f.rule_id;
            out << YAML::Key << "CallerFunction" << YAML::Value << f.caller;
            if (!f.indicators.empty()) {
                out << YAML::Key << "BehavioralIndicators|contains" << YAML::Value << YAML::BeginSeq;
                for (const auto &ind : f.indicators) {
                    out << ind;
                }
                out << YAML::EndSeq;
            }
            out << YAML::EndMap;
            out << YAML::Key << "condition" << YAML::Value << "selection";
            out << YAML::EndMap;

            out << YAML::Key << "falsepositives" << YAML::Value << YAML::BeginSeq;
            out << "Legitimate JIT compilers, runtime loaders, or authorized instrumentation";
            out << YAML::EndSeq;

            out << YAML::Key << "level" << YAML::Value << (f.severity.empty() ? "medium" : f.severity);
            out << YAML::EndMap;
            out << YAML::EndDoc;
        }

        std::string yaml_str = out.c_str();
        if (!yaml_str.empty() && yaml_str.back() != '\n') {
            yaml_str.push_back('\n');
        }
        return yaml_str;
    }

    std::string BehaviorRuleEmitter::toSarif(const std::vector<BehaviorFinding> &findings, std::string_view target_os) {
        const std::string norm_os = normalizeOs(target_os);
        const std::string effective_os = (norm_os == "auto") ? "cross-platform" : norm_os;

        // Collect unique rules in order of appearance.
        std::vector<const BehaviorFinding *> unique_rules;
        std::unordered_map<std::string, size_t> rule_index_by_id;
        for (const auto &f : findings) {
            if (rule_index_by_id.find(f.rule_id) == rule_index_by_id.end()) {
                rule_index_by_id.emplace(f.rule_id, unique_rules.size());
                unique_rules.push_back(&f);
            }
        }

        nlohmann::json rules_arr = nlohmann::json::array();
        for (const BehaviorFinding *r_ptr : unique_rules) {
            const BehaviorFinding &r = *r_ptr;
            rules_arr.push_back({
                {"id", r.rule_id},
                {"name", r.title},
                {"shortDescription", {{"text", r.title}}},
                {"fullDescription", {{"text", r.description}}},
                {"defaultConfiguration", {{"level", sarifLevelFromSeverity(r.severity)}}},
                {"properties", {{"tags", r.mitre_techniques}}},
            });
        }

        nlohmann::json results_arr = nlohmann::json::array();
        for (const BehaviorFinding &f : findings) {
            const std::string &row_os = f.target_os.empty() ? effective_os : f.target_os;
            const auto rule_it = rule_index_by_id.find(f.rule_id);
            const size_t rule_idx = (rule_it != rule_index_by_id.end()) ? rule_it->second : 0;

            std::string msg_text = f.title;
            if (!f.caller.empty()) {
                msg_text += " in " + f.caller;
            }
            msg_text += " (risk=" + std::to_string(f.risk_score) + "): " + f.description;

            nlohmann::json result_obj = {
                {"ruleId", f.rule_id},
                {"ruleIndex", rule_idx},
                {"level", sarifLevelFromSeverity(f.severity)},
                {"message", {{"text", msg_text}}},
                {"properties",
                 {
                     {"caller", f.caller},
                     {"severity", f.severity},
                     {"target_os", row_os},
                     {"risk_score", f.risk_score},
                     {"entropy", std::round(f.entropy * 100.0) / 100.0},
                     {"mitre_techniques", f.mitre_techniques},
                     {"indicators", f.indicators},
                 }},
            };

            if (!f.file.empty() || !f.caller.empty()) {
                nlohmann::json loc_obj = nlohmann::json::object();
                if (!f.file.empty()) {
                    nlohmann::json phys = {
                        {"artifactLocation", {{"uri", f.file}}},
                    };
                    if (f.line > 0) {
                        nlohmann::json region = {{"startLine", f.line}};
                        if (f.column > 0) {
                            region["startColumn"] = f.column;
                        }
                        phys["region"] = std::move(region);
                    }
                    loc_obj["physicalLocation"] = std::move(phys);
                }
                if (!f.caller.empty()) {
                    loc_obj["logicalLocations"] = nlohmann::json::array({
                        {{"name", f.caller}, {"kind", "function"}},
                    });
                }
                result_obj["locations"] = nlohmann::json::array({std::move(loc_obj)});
            }

            results_arr.push_back(std::move(result_obj));
        }

        nlohmann::json root = {
            {"$schema",
             "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"},
            {"version", "2.1.0"},
            {"runs",
             nlohmann::json::array({
                 {
                     {"tool",
                      {
                          {"driver",
                           {
                               {"name", "TraceQL"},
                               {"informationUri", "https://clang.llvm.org/"},
                               {"rules", std::move(rules_arr)},
                           }},
                      }},
                     {"results", std::move(results_arr)},
                 },
             })},
        };
        return root.dump(2) + "\n";
    }

    bool BehaviorRuleEmitter::writeRulesFile(const std::string &output_path,
                                             const std::vector<BehaviorFinding> &findings, std::string_view target_os,
                                             BehaviorRuleFormat format) {
        std::ofstream out(output_path, std::ios::out | std::ios::trunc);
        if (!out.is_open()) {
            return false;
        }
        std::string content;
        switch (format) {
        case BehaviorRuleFormat::SigmaYaml:
            content = toSigmaYaml(findings, target_os);
            break;
        case BehaviorRuleFormat::Sarif:
            content = toSarif(findings, target_os);
            break;
        case BehaviorRuleFormat::Json:
        default:
            content = toJsonRules(findings, target_os);
            break;
        }
        out << content;
        return out.good();
    }

    bool BehaviorRuleEmitter::writeRulesFile(const std::string &output_path,
                                             const std::vector<BehaviorFinding> &findings, std::string_view target_os,
                                             bool as_yaml) {
        return writeRulesFile(output_path, findings, target_os,
                              as_yaml ? BehaviorRuleFormat::SigmaYaml : BehaviorRuleFormat::Json);
    }

} // namespace traceql
