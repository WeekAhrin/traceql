#include "analysis/behavior_classifier.h"

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <sstream>

namespace traceql {

    namespace {

        std::string toLowerAscii(std::string_view sv) {
            std::string out;
            out.reserve(sv.size());
            for (const unsigned char ch : sv) {
                out.push_back(static_cast<char>(std::tolower(ch)));
            }
            return out;
        }

        std::string normalizeType(std::string_view ty) {
            std::string out;
            out.reserve(ty.size());
            bool last_space = true;
            for (const unsigned char ch : ty) {
                if (std::isspace(ch) != 0) {
                    if (!last_space) {
                        out.push_back(' ');
                        last_space = true;
                    }
                    continue;
                }
                if (ch == '*' || ch == '&') {
                    if (!out.empty() && out.back() == ' ') {
                        out.pop_back();
                    }
                    out.push_back(static_cast<char>(ch));
                    last_space = false;
                    continue;
                }
                out.push_back(static_cast<char>(std::tolower(ch)));
                last_space = false;
            }
            if (!out.empty() && out.back() == ' ') {
                out.pop_back();
            }
            return out;
        }

        bool isFunctionPointerType(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return ty.find("(*)") != std::string::npos || ty.find("(*") != std::string::npos || ty == "farproc" ||
                   ty == "proc";
        }

        bool isVoidPointer(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return ty == "void*" || ty == "const void*" || ty == "lpvoid" || ty == "lpcvoid" || ty == "pvoid";
        }

        bool isOpaqueHandleType(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return isVoidPointer(ty) || ty == "handle" || ty == "hmodule" || ty == "hinstance" || ty == "uintptr_t" ||
                   ty == "intptr_t" || ty == "jnienv*" || ty == "jclass";
        }

        bool isCStringType(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return ty == "const char*" || ty == "char*" || ty == "const wchar_t*" || ty == "wchar_t*" ||
                   ty == "lpcstr" || ty == "lpstr" || ty == "lpcwstr" || ty == "lpwstr";
        }

        bool isIntegerOrSizeType(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return ty == "int" || ty == "unsigned" || ty == "unsigned int" || ty == "uint32_t" || ty == "int32_t" ||
                   ty == "long" || ty == "unsigned long" || ty == "size_t" || ty == "ssize_t" || ty == "dword" ||
                   ty == "ulong" || ty == "bool" || ty == "jint" || ty == "off_t" || ty == "uint64_t" ||
                   ty == "int64_t" || ty == "socklen_t" || ty == "pid_t";
        }

        bool isSizeType(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return ty == "size_t" || ty == "unsigned long" || ty == "unsigned long long" || ty == "uint64_t" ||
                   ty == "uint32_t" || ty == "unsigned int" || ty == "unsigned";
        }

        bool isOutPointerType(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return ty == "dword*" || ty == "pdword" || ty == "uint32_t*" || ty == "unsigned long*" ||
                   ty == "unsigned int*" || ty == "int*" || ty == "size_t*" || ty == "pbool" || ty == "bool*";
        }

        bool isFilePointerType(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return ty == "file*" || ty == "struct _io_file*";
        }

        bool isRegistryHandleType(std::string_view raw_ty) {
            const std::string ty = normalizeType(raw_ty);
            return ty == "hkey" || ty == "phkey" || ty == "hkey*";
        }

        bool isWordBoundaryChar(char ch) {
            return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
        }

        bool containsAsmToken(std::string_view asm_lower, std::string_view token) {
            size_t pos = 0;
            while ((pos = asm_lower.find(token, pos)) != std::string_view::npos) {
                const bool left_ok = (pos == 0) || !isWordBoundaryChar(asm_lower[pos - 1]);
                const size_t end = pos + token.size();
                const bool right_ok = (end >= asm_lower.size()) || !isWordBoundaryChar(asm_lower[end]);
                if (left_ok && right_ok) {
                    return true;
                }
                pos += token.size();
            }
            return false;
        }

        bool containsSegmentRegister(std::string_view asm_lower, std::string_view seg) {
            const std::string colon_seg = std::string(seg) + ":";
            return asm_lower.find(colon_seg) != std::string_view::npos;
        }

        bool hasConstant(const BehaviorFeatures &features, uint64_t value) {
            return std::find(features.numeric_constants.begin(), features.numeric_constants.end(), value) !=
                   features.numeric_constants.end();
        }

        bool hasAnyConstant(const BehaviorFeatures &features, std::initializer_list<uint64_t> values) {
            for (const uint64_t v : values) {
                if (hasConstant(features, v)) {
                    return true;
                }
            }
            return false;
        }

        void addTag(std::vector<std::string> &tags, std::string_view tag) {
            for (const auto &existing : tags) {
                if (existing == tag) {
                    return;
                }
            }
            tags.emplace_back(tag);
        }

        double computeEffectiveMaxEntropy(const BehaviorFeatures &features) {
            double max_ent = features.max_arg_entropy;
            for (const double ent : features.arg_entropies) {
                max_ent = std::max(max_ent, ent);
            }
            return max_ent;
        }

        bool startsWithAny(std::string_view s, std::initializer_list<std::string_view> prefixes) {
            for (const auto prefix : prefixes) {
                if (s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix) {
                    return true;
                }
            }
            return false;
        }

        bool hasRwxProtectionConstant(const BehaviorFeatures &features, TargetOS os) {
            const bool win_rwx = hasAnyConstant(features, {0x40ULL, 0x80ULL});
            const bool posix_rwx = hasAnyConstant(features, {0x06ULL, 0x07ULL});
            if (os == TargetOS::Windows) {
                return win_rwx;
            }
            if (os == TargetOS::Linux || os == TargetOS::Android || os == TargetOS::MacOS) {
                return posix_rwx;
            }
            return win_rwx || posix_rwx;
        }

        bool hasExecProtectionConstant(const BehaviorFeatures &features, TargetOS os) {
            const bool win_exec = hasAnyConstant(features, {0x10ULL, 0x20ULL, 0x40ULL, 0x80ULL});
            const bool posix_exec = hasAnyConstant(features, {0x04ULL, 0x05ULL, 0x06ULL, 0x07ULL});
            if (os == TargetOS::Windows) {
                return win_exec;
            }
            if (os == TargetOS::Linux || os == TargetOS::Android || os == TargetOS::MacOS) {
                return posix_exec;
            }
            return win_exec || posix_exec;
        }

        struct PatternMatch {
            bool matched{false};
            BehaviorCategory category{BehaviorCategory::Benign};
            uint32_t base_risk{0};
            std::string reason;
        };

        PatternMatch classifyInlineAsm(const BehaviorFeatures &features, std::vector<std::string> &tags) {
            PatternMatch match;
            const std::string asm_lower = toLowerAscii(features.asm_text);
            addTag(tags, "inline_asm");

            // Direct syscall instructions across x86, x86_64, ARM, and ARM64.
            const bool x64_syscall = containsAsmToken(asm_lower, "syscall") || containsAsmToken(asm_lower, "sysenter");
            const bool x86_int_syscall =
                asm_lower.find("int 0x80") != std::string::npos || asm_lower.find("int $0x80") != std::string::npos ||
                asm_lower.find("int 80h") != std::string::npos || asm_lower.find("int 0x2e") != std::string::npos ||
                asm_lower.find("int $0x2e") != std::string::npos;
            const bool arm_svc = containsAsmToken(asm_lower, "svc") || containsAsmToken(asm_lower, "swi");

            if (x64_syscall || x86_int_syscall || arm_svc) {
                match.matched = true;
                match.category = BehaviorCategory::DirectSyscall;
                match.base_risk = 88;
                addTag(tags, "direct_syscall");
                addTag(tags, "hook_evasion");
                if (x64_syscall) {
                    addTag(tags, "x86_64_syscall");
                }
                if (x86_int_syscall) {
                    addTag(tags, "x86_int_syscall");
                }
                if (arm_svc) {
                    addTag(tags, "arm_svc_syscall");
                }
                if (features.target_os == TargetOS::Windows || features.target_os == TargetOS::Android) {
                    match.base_risk = 92;
                }
                match.reason = "Inline assembly issues a direct kernel syscall instruction bypassing user-mode hooks";
                return match;
            }

            // Hardware timing / CPUID anti-debug & VM detection instructions.
            const bool has_rdtsc = containsAsmToken(asm_lower, "rdtsc") || containsAsmToken(asm_lower, "rdtscp");
            const bool has_cpuid = containsAsmToken(asm_lower, "cpuid");
            if (has_rdtsc || has_cpuid) {
                match.matched = true;
                match.category = BehaviorCategory::AntiDebugOrTiming;
                match.base_risk = has_rdtsc ? 72 : 55;
                if (has_rdtsc) {
                    addTag(tags, "rdtsc_timing");
                    addTag(tags, "anti_debug");
                }
                if (has_cpuid) {
                    addTag(tags, "cpuid_probe");
                }
                match.reason = "Inline assembly executes hardware timing or CPU identification instructions";
                return match;
            }

            // Segment register TEB/PEB traversal (Windows x86 fs:[0x30] / x64 gs:[0x60]).
            if (containsSegmentRegister(asm_lower, "fs") || containsSegmentRegister(asm_lower, "gs")) {
                match.matched = true;
                match.category = BehaviorCategory::DynamicResolution;
                match.base_risk = 82;
                addTag(tags, "peb_teb_access");
                addTag(tags, "iat_evasion");
                match.reason = "Inline assembly accesses thread/process environment block via segment register";
                return match;
            }

            match.matched = true;
            match.category = BehaviorCategory::IndirectCall;
            match.base_risk = 20;
            match.reason = "Inline assembly block executed";
            return match;
        }

        PatternMatch classifyDynamicResolution(const BehaviorFeatures &features, std::vector<std::string> &tags) {
            PatternMatch match;
            const size_t argc = features.param_types.size();
            const auto &params = features.param_types;

            // Function pointer cast from opaque pointer/integer to callable signature.
            if (features.call_kind == "fn_ptr_cast") {
                if (argc == 1) {
                    const std::string src_ty = normalizeType(params[0]);
                    if (src_ty == "std::nullptr_t" || src_ty == "nullptr_t") {
                        return match;
                    }
                }
                match.matched = true;
                match.category = BehaviorCategory::DynamicResolution;
                match.base_risk = 65;
                addTag(tags, "fn_ptr_cast");
                addTag(tags, "dynamic_resolution");
                match.reason = "Opaque pointer or address cast to a callable function pointer";
                return match;
            }

            // 2-arg symbol resolver: (handle/void*, const char*) -> void* / FARPROC / fn_ptr
            if (argc == 2 && isOpaqueHandleType(params[0]) && isCStringType(params[1]) &&
                (isVoidPointer(features.return_type) || isFunctionPointerType(features.return_type))) {
                match.matched = true;
                match.category = BehaviorCategory::DynamicResolution;
                match.base_risk = 68;
                addTag(tags, "dynamic_symbol_lookup");
                addTag(tags, "iat_evasion");
                match.reason = "Resolves function address from module handle and symbol string";
                return match;
            }

            // 2-arg shared object loader: (const char*, int) -> void* (e.g. dlopen-like)
            if (argc == 2 && isCStringType(params[0]) && isIntegerOrSizeType(params[1]) &&
                isOpaqueHandleType(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::DynamicResolution;
                match.base_risk = 60;
                addTag(tags, "dynamic_library_load");
                match.reason = "Loads shared module dynamically from path and mode flags";
                return match;
            }

            // 1-arg module loader: (const char* / const wchar_t*) -> void* / HANDLE / HMODULE
            if (argc == 1 && isCStringType(params[0]) && isOpaqueHandleType(features.return_type) &&
                !isFilePointerType(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::DynamicResolution;
                match.base_risk = 58;
                addTag(tags, "dynamic_library_load");
                match.reason = "Loads or queries module handle dynamically by string path";
                return match;
            }

            // 4-arg JNI native registration: (JNIEnv*, jclass, const JNINativeMethod*, jint) -> jint
            if (argc == 4 && isOpaqueHandleType(params[0]) && isOpaqueHandleType(params[1]) &&
                normalizeType(params[2]).find('*') != std::string::npos && isIntegerOrSizeType(params[3]) &&
                isIntegerOrSizeType(features.return_type)) {
                const std::string p0 = normalizeType(params[0]);
                const std::string p1 = normalizeType(params[1]);
                if (p0.find("jnienv") != std::string::npos || p1.find("jclass") != std::string::npos) {
                    match.matched = true;
                    match.category = BehaviorCategory::DynamicResolution;
                    match.base_risk = 64;
                    addTag(tags, "jni_dynamic_registration");
                    match.reason = "Dynamically registers native methods via JNI environment table";
                    return match;
                }
            }

            return match;
        }

        PatternMatch classifyMemoryProtection(const BehaviorFeatures &features, std::vector<std::string> &tags) {
            PatternMatch match;
            const size_t argc = features.param_types.size();
            const auto &params = features.param_types;

            // POSIX-style 3-arg: (void*, size_t, int/uint) -> int
            const bool posix_prot_sig = (argc == 3 && isVoidPointer(params[0]) && isSizeType(params[1]) &&
                                         isIntegerOrSizeType(params[2]) && isIntegerOrSizeType(features.return_type));

            // Windows-style 4-arg: (void*, size_t, DWORD, PDWORD) -> BOOL/int
            const bool win_prot_sig =
                (argc == 4 && isVoidPointer(params[0]) && isSizeType(params[1]) && isIntegerOrSizeType(params[2]) &&
                 isOutPointerType(params[3]) && isIntegerOrSizeType(features.return_type));

            // Cross-process 5-arg: (HANDLE, void*, size_t, DWORD, PDWORD) -> BOOL/NTSTATUS
            const bool remote_prot_sig = (argc == 5 && isOpaqueHandleType(params[0]) && isVoidPointer(params[1]) &&
                                          isSizeType(params[2]) && isIntegerOrSizeType(params[3]) &&
                                          isOutPointerType(params[4]) && isIntegerOrSizeType(features.return_type));

            if (!posix_prot_sig && !win_prot_sig && !remote_prot_sig) {
                return match;
            }

            match.matched = true;
            match.category = BehaviorCategory::MemoryProtection;
            match.base_risk = remote_prot_sig ? 72 : 52;
            addTag(tags, "memory_protection");

            if (remote_prot_sig) {
                addTag(tags, "cross_process_memory");
            }

            if (hasRwxProtectionConstant(features, features.target_os)) {
                match.base_risk = std::max<uint32_t>(match.base_risk, 86);
                addTag(tags, "rwx_violation");
                addTag(tags, "wx_violation");
                match.reason = "Changes virtual memory page protection to simultaneous Read-Write-Execute (RWX)";
            } else if (hasExecProtectionConstant(features, features.target_os)) {
                match.base_risk = std::max<uint32_t>(match.base_risk, 72);
                addTag(tags, "executable_memory");
                match.reason = "Changes virtual memory page protection to executable";
            } else {
                match.reason = "Modifies virtual memory page protection attributes";
            }

            return match;
        }

        PatternMatch classifyMemoryAllocation(const BehaviorFeatures &features, std::vector<std::string> &tags) {
            PatternMatch match;
            const size_t argc = features.param_types.size();
            const auto &params = features.param_types;

            // 6-arg anonymous/virtual mapping: (void*, size_t, int, int, int, off_t) -> void*
            const bool mmap_sig =
                (argc == 6 && isVoidPointer(params[0]) && isSizeType(params[1]) && isIntegerOrSizeType(params[2]) &&
                 isIntegerOrSizeType(params[3]) && isIntegerOrSizeType(params[4]) && isIntegerOrSizeType(params[5]) &&
                 isVoidPointer(features.return_type));

            // 4-arg virtual alloc: (void*, size_t, DWORD, DWORD) -> void*
            const bool virt_alloc_sig =
                (argc == 4 && isVoidPointer(params[0]) && isSizeType(params[1]) && isIntegerOrSizeType(params[2]) &&
                 isIntegerOrSizeType(params[3]) && isVoidPointer(features.return_type));

            // 5-arg remote virtual alloc: (HANDLE, void*, size_t, DWORD, DWORD) -> void*
            const bool remote_alloc_sig = (argc == 5 && isOpaqueHandleType(params[0]) && isVoidPointer(params[1]) &&
                                           isSizeType(params[2]) && isIntegerOrSizeType(params[3]) &&
                                           isIntegerOrSizeType(params[4]) && isVoidPointer(features.return_type));

            if (mmap_sig || virt_alloc_sig || remote_alloc_sig) {
                match.matched = true;
                match.category = BehaviorCategory::MemoryAllocation;
                match.base_risk = remote_alloc_sig ? 70 : 48;
                addTag(tags, "virtual_memory_allocation");
                if (remote_alloc_sig) {
                    addTag(tags, "cross_process_memory");
                }
                if (hasRwxProtectionConstant(features, features.target_os)) {
                    match.base_risk = std::max<uint32_t>(match.base_risk, 86);
                    addTag(tags, "rwx_violation");
                    addTag(tags, "wx_violation");
                    match.reason = "Allocates virtual memory with simultaneous Write and Execute permissions";
                } else if (hasExecProtectionConstant(features, features.target_os)) {
                    match.base_risk = std::max<uint32_t>(match.base_risk, 72);
                    addTag(tags, "executable_memory");
                    match.reason = "Allocates executable virtual memory pages";
                } else {
                    match.reason = "Allocates virtual memory pages";
                }
                return match;
            }

            // 2-arg anonymous memory fd creation: (const char*, uint) -> int (memfd-style)
            if (argc == 2 && isCStringType(params[0]) && isIntegerOrSizeType(params[1]) &&
                isIntegerOrSizeType(features.return_type)) {
                for (const auto &lit : features.string_literals) {
                    if (startsWithAny(lit, {"memfd:", "/dev/shm/"})) {
                        match.matched = true;
                        match.category = BehaviorCategory::MemoryAllocation;
                        match.base_risk = 74;
                        addTag(tags, "anonymous_memory_fd");
                        addTag(tags, "fileless_staging");
                        match.reason = "Creates anonymous RAM-backed memory file descriptor";
                        return match;
                    }
                }
            }

            // Standard heap allocation: (size_t) -> void* or (size_t, size_t) -> void*
            const bool heap_alloc_sig = ((argc == 1 && isSizeType(params[0])) ||
                                         (argc == 2 && isSizeType(params[0]) && isSizeType(params[1]))) &&
                                        isVoidPointer(features.return_type);

            if (heap_alloc_sig || features.call_kind == "new") {
                match.matched = true;
                match.category = BehaviorCategory::MemoryAllocation;
                match.base_risk = 10;
                addTag(tags, "heap_allocation");
                match.reason = "Standard heap memory allocation";
                return match;
            }

            return match;
        }

        PatternMatch classifyProcessThreadOrDebug(const BehaviorFeatures &features, std::vector<std::string> &tags) {
            PatternMatch match;
            const size_t argc = features.param_types.size();
            const auto &params = features.param_types;

            // 4-arg POSIX tracing signature: (int/enum, pid_t/int, void*, void*) -> long/int
            if (argc == 4 && isIntegerOrSizeType(params[0]) && isIntegerOrSizeType(params[1]) &&
                isVoidPointer(params[2]) && isVoidPointer(params[3]) && isIntegerOrSizeType(features.return_type)) {
                if (hasConstant(features, 0ULL)) {
                    // Request 0 (self-trace anti-debug).
                    match.matched = true;
                    match.category = BehaviorCategory::AntiDebugOrTiming;
                    match.base_risk = 74;
                    addTag(tags, "ptrace_traceme");
                    addTag(tags, "anti_debug");
                    match.reason = "Self-tracing anti-debug check via 4-argument process trace signature";
                    return match;
                }
                if (hasAnyConstant(features, {4ULL, 5ULL, 13ULL, 16ULL, 17ULL, 0x4206ULL})) {
                    match.matched = true;
                    match.category = BehaviorCategory::ProcessThreadOp;
                    match.base_risk = 84;
                    addTag(tags, "process_trace_attach");
                    addTag(tags, "process_injection");
                    match.reason = "Attaches to or modifies another process via trace request constant";
                    return match;
                }
            }

            // 5-arg remote process memory write/read: (HANDLE, void*, [const] void*, size_t, size_t*) -> BOOL/int
            if (argc == 5 && isOpaqueHandleType(params[0]) && isVoidPointer(params[1]) && isVoidPointer(params[2]) &&
                isSizeType(params[3]) && isOutPointerType(params[4]) && isIntegerOrSizeType(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::ProcessThreadOp;
                match.base_risk = 82;
                addTag(tags, "cross_process_memory");
                addTag(tags, "process_injection");
                match.reason = "Reads or writes memory across process boundaries";
                return match;
            }

            // 7-arg remote thread creation: (HANDLE, void*, size_t, fn_ptr, void*, DWORD, PDWORD) -> HANDLE
            if (argc == 7 && isOpaqueHandleType(params[0]) && isSizeType(params[2]) &&
                (isFunctionPointerType(params[3]) || isVoidPointer(params[3])) &&
                isOpaqueHandleType(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::ProcessThreadOp;
                match.base_risk = 88;
                addTag(tags, "remote_thread_creation");
                addTag(tags, "process_injection");
                match.reason = "Creates a thread inside a remote process handle";
                return match;
            }

            // 6-arg local thread creation: (void*, size_t, fn_ptr, void*, DWORD, PDWORD) -> HANDLE
            if (argc == 6 && isVoidPointer(params[0]) && isSizeType(params[1]) &&
                (isFunctionPointerType(params[2]) || isVoidPointer(params[2])) &&
                isOpaqueHandleType(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::ProcessThreadOp;
                match.base_risk = 52;
                addTag(tags, "thread_creation");
                match.reason = "Spawns an execution thread via function pointer entry";
                return match;
            }

            // 3-arg process handle open: (DWORD, BOOL, DWORD) -> HANDLE
            if (argc == 3 && isIntegerOrSizeType(params[0]) && isIntegerOrSizeType(params[1]) &&
                isIntegerOrSizeType(params[2]) && isOpaqueHandleType(features.return_type) &&
                !isVoidPointer(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::ProcessThreadOp;
                match.base_risk = 62;
                addTag(tags, "process_handle_open");
                match.reason = "Opens handle to external process by access mask and PID";
                return match;
            }

            // 3-arg execve-style process execution: (const char*, char* const*, char* const*) -> int
            if (argc == 3 && isCStringType(params[0]) && normalizeType(params[1]).find("char") != std::string::npos &&
                normalizeType(params[2]).find("char") != std::string::npos &&
                isIntegerOrSizeType(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::ProcessThreadOp;
                match.base_risk = 65;
                addTag(tags, "process_execution");
                match.reason = "Replaces or executes process image with argument and environment vectors";
                return match;
            }

            // 4-arg POSIX thread creation: (pthread_t*, const pthread_attr_t*, void*(*)(void*), void*) -> int
            if (argc == 4 && normalizeType(params[0]).find('*') != std::string::npos &&
                isFunctionPointerType(params[2]) && isVoidPointer(params[3]) &&
                isIntegerOrSizeType(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::ProcessThreadOp;
                match.base_risk = 45;
                addTag(tags, "thread_creation");
                match.reason = "Creates POSIX thread with entry routine";
                return match;
            }

            // Structural /proc/ path inspection (e.g. /proc/self/maps, /proc/self/mem).
            for (const auto &lit : features.string_literals) {
                if (startsWithAny(lit, {"/proc/"})) {
                    match.matched = true;
                    match.category = BehaviorCategory::ProcessThreadOp;
                    match.base_risk = 60;
                    addTag(tags, "procfs_access");
                    match.reason = "Accesses Linux/Android procfs process introspection path";
                    return match;
                }
            }

            return match;
        }

        PatternMatch classifyNetworkOrIPC(const BehaviorFeatures &features, std::vector<std::string> &tags) {
            PatternMatch match;
            const size_t argc = features.param_types.size();
            const auto &params = features.param_types;

            // 3-arg socket creation: (int, int, int) -> int with AF_INET(2)/AF_INET6(10)/AF_UNIX(1)
            if (argc == 3 && isIntegerOrSizeType(params[0]) && isIntegerOrSizeType(params[1]) &&
                isIntegerOrSizeType(params[2]) && isIntegerOrSizeType(features.return_type)) {
                bool has_distinct_domain_and_type = false;
                const auto &nums = features.numeric_constants;
                for (const uint64_t dom : {10ULL, 2ULL, 1ULL}) {
                    const auto it = std::find(nums.begin(), nums.end(), dom);
                    if (it == nums.end())
                        continue;
                    const size_t dom_idx = static_cast<size_t>(it - nums.begin());
                    for (size_t i = 0; i < nums.size(); ++i) {
                        if (i == dom_idx)
                            continue;
                        if (nums[i] == 1ULL || nums[i] == 2ULL || nums[i] == 3ULL) {
                            has_distinct_domain_and_type = true;
                            break;
                        }
                    }
                    if (has_distinct_domain_and_type)
                        break;
                }
                if (has_distinct_domain_and_type) {
                    match.matched = true;
                    match.category = BehaviorCategory::NetworkOrIPC;
                    match.base_risk = hasConstant(features, 3ULL) ? 68 : 42;
                    addTag(tags, "socket_creation");
                    if (hasConstant(features, 3ULL)) {
                        addTag(tags, "raw_socket");
                    }
                    match.reason = "Creates network or Unix domain socket with address/protocol constants";
                    return match;
                }
            }

            // 3-arg sockaddr connect/bind: (int, const struct sockaddr*, socklen_t) -> int
            if (argc == 3 && isIntegerOrSizeType(params[0]) &&
                normalizeType(params[1]).find("sockaddr") != std::string::npos && isIntegerOrSizeType(params[2]) &&
                isIntegerOrSizeType(features.return_type)) {
                match.matched = true;
                match.category = BehaviorCategory::NetworkOrIPC;
                match.base_risk = 50;
                addTag(tags, "network_endpoint");
                match.reason = "Binds or connects socket to a sockaddr endpoint";
                return match;
            }

            // Structural network/IPC URI or named pipe literals.
            for (const auto &lit : features.string_literals) {
                const std::string lower_lit = toLowerAscii(lit);
                if (startsWithAny(lower_lit, {"http://", "https://", "ws://", "wss://", "tcp://", "udp://",
                                              "\\\\.\\pipe\\", "\\device\\namedpipe\\"})) {
                    match.matched = true;
                    match.category = BehaviorCategory::NetworkOrIPC;
                    match.base_risk = 45;
                    addTag(tags, "network_or_ipc_uri");
                    match.reason = "References network URL scheme or named pipe IPC path";
                    return match;
                }
            }

            return match;
        }

        PatternMatch classifyFileOrRegistryIO(const BehaviorFeatures &features, std::vector<std::string> &tags) {
            PatternMatch match;
            const size_t argc = features.param_types.size();
            const auto &params = features.param_types;

            // Returning FILE* from (const char*, const char*).
            if (isFilePointerType(features.return_type) && argc >= 2 && isCStringType(params[0]) &&
                isCStringType(params[1])) {
                match.matched = true;
                match.category = BehaviorCategory::FileOrRegistryIO;
                match.base_risk = 25;
                addTag(tags, "file_stream_io");
                match.reason = "Opens buffered file stream";
                return match;
            }

            // Windows Registry signature using HKEY/PHKEY.
            for (const auto &p : params) {
                if (isRegistryHandleType(p)) {
                    match.matched = true;
                    match.category = BehaviorCategory::FileOrRegistryIO;
                    match.base_risk = 48;
                    addTag(tags, "registry_io");
                    match.reason = "Accesses Windows registry via HKEY handle";
                    return match;
                }
            }

            // Structural registry or sensitive system path literals.
            for (const auto &lit : features.string_literals) {
                if (startsWithAny(lit, {"HKEY_", "HKLM\\", "HKCU\\", "\\Registry\\", "\\??\\"})) {
                    match.matched = true;
                    match.category = BehaviorCategory::FileOrRegistryIO;
                    match.base_risk = 35;
                    addTag(tags, "system_or_registry_path");
                    match.reason = "References Windows registry or NT object path";
                    return match;
                }
                if (startsWithAny(lit, {"/etc/", "/tmp/", "/dev/"})) {
                    match.matched = true;
                    match.category = BehaviorCategory::FileOrRegistryIO;
                    match.base_risk = 15;
                    addTag(tags, "system_or_registry_path");
                    match.reason = "References OS configuration, temporary, or device path";
                    return match;
                }
            }

            return match;
        }

        PatternMatch classifyObfuscatedPayload(const BehaviorFeatures &features, std::vector<std::string> &tags) {
            PatternMatch match;
            const double max_ent = computeEffectiveMaxEntropy(features);
            // Real packed/encrypted payloads sit at >= 6.8 bits/byte; normal ASCII text is 3.5-5.5.
            const bool high_entropy = features.has_high_entropy_literal || max_ent >= 6.8;

            if (!high_entropy && !features.has_bitwise_xor_loop) {
                return match;
            }

            match.matched = true;
            match.category = BehaviorCategory::ObfuscatedPayload;

            if (features.has_bitwise_xor_loop) {
                addTag(tags, "xor_decoding_loop");
                match.base_risk = 35;
            }

            if (high_entropy) {
                addTag(tags, "high_entropy_literal");
                // Standalone high-entropy data without an unpacking loop or dangerous sink is low risk
                // (e.g., compressed textures/assets). Risk escalates sharply when paired with XOR/sinks.
                uint32_t ent_score = (max_ent >= 7.4) ? 25 : 20;
                if (max_ent >= 6.8) {
                    addTag(tags, "encrypted_or_packed_blob");
                }
                match.base_risk = std::max(match.base_risk, ent_score);
            }

            if (features.has_bitwise_xor_loop && high_entropy) {
                match.base_risk = 82;
                match.reason = "Combines high-entropy (>= 6.8) payload with bitwise XOR decoding loop";
            } else if (features.has_bitwise_xor_loop) {
                match.reason = "Exhibits bitwise XOR/rolling-key decoding loop pattern";
            } else {
                match.reason = "Contains high-entropy (>= 6.8) binary blob without execution sink";
            }

            return match;
        }

    } // namespace

    const char *getBehaviorCategoryName(BehaviorCategory cat) noexcept {
        switch (cat) {
        case BehaviorCategory::Benign:
            return "Benign";
        case BehaviorCategory::MemoryAllocation:
            return "MemoryAllocation";
        case BehaviorCategory::MemoryProtection:
            return "MemoryProtection";
        case BehaviorCategory::DynamicResolution:
            return "DynamicResolution";
        case BehaviorCategory::DirectSyscall:
            return "DirectSyscall";
        case BehaviorCategory::IndirectCall:
            return "IndirectCall";
        case BehaviorCategory::ProcessThreadOp:
            return "ProcessThreadOp";
        case BehaviorCategory::ObfuscatedPayload:
            return "ObfuscatedPayload";
        case BehaviorCategory::AntiDebugOrTiming:
            return "AntiDebugOrTiming";
        case BehaviorCategory::NetworkOrIPC:
            return "NetworkOrIPC";
        case BehaviorCategory::FileOrRegistryIO:
            return "FileOrRegistryIO";
        }
        return "Unknown";
    }

    BehaviorAssessment BehaviorClassifier::classify(const BehaviorFeatures &features) {
        BehaviorAssessment assessment;
        std::vector<std::string> reasons;

        PatternMatch primary;

        if (features.call_kind == "inline_asm") {
            primary = classifyInlineAsm(features, assessment.tags);
        }

        if (!primary.matched) {
            primary = classifyMemoryProtection(features, assessment.tags);
        }
        if (!primary.matched) {
            primary = classifyDynamicResolution(features, assessment.tags);
        }
        if (!primary.matched) {
            primary = classifyProcessThreadOrDebug(features, assessment.tags);
        }
        if (!primary.matched) {
            primary = classifyMemoryAllocation(features, assessment.tags);
        }
        if (!primary.matched) {
            primary = classifyNetworkOrIPC(features, assessment.tags);
        }
        if (!primary.matched) {
            primary = classifyFileOrRegistryIO(features, assessment.tags);
        }
        if (!primary.matched) {
            primary = classifyObfuscatedPayload(features, assessment.tags);
        }

        if (!primary.matched && (features.call_kind == "indirect" || features.resolved_from_symbol)) {
            primary.matched = true;
            primary.category = BehaviorCategory::IndirectCall;
            primary.base_risk = features.resolved_from_symbol ? 70 : 28;
            addTag(assessment.tags, "indirect_call");
            primary.reason = features.resolved_from_symbol
                                 ? "Invokes function pointer obtained from dynamic symbol resolution"
                                 : "Indirect call through function pointer";
        }

        if (primary.matched) {
            assessment.primary_category = primary.category;
            assessment.risk_score = primary.base_risk;
            reasons.push_back(primary.reason);
        } else {
            assessment.primary_category = BehaviorCategory::Benign;
            assessment.risk_score = 0;
            reasons.emplace_back("No anomalous behavioral or structural indicators detected");
        }

        // Secondary risk modifiers & compositional tags.
        if (features.resolved_from_symbol) {
            addTag(assessment.tags, "resolved_symbol_invocation");
            addTag(assessment.tags, "iat_evasion");
            if (assessment.primary_category != BehaviorCategory::IndirectCall) {
                assessment.risk_score += 18;
                reasons.emplace_back("Invoked via dynamically resolved function pointer");
            }
        }

        const double max_ent = computeEffectiveMaxEntropy(features);
        if ((features.has_high_entropy_literal || max_ent >= 6.8) &&
            assessment.primary_category != BehaviorCategory::ObfuscatedPayload &&
            assessment.primary_category != BehaviorCategory::Benign) {
            addTag(assessment.tags, "high_entropy_literal");
            assessment.risk_score += (max_ent >= 7.2 ? 18 : 12);
            reasons.emplace_back("Paired with high-entropy (>= 6.8) literal argument");
        }

        if (features.has_bitwise_xor_loop && assessment.primary_category != BehaviorCategory::ObfuscatedPayload) {
            addTag(assessment.tags, "xor_decoding_loop");
            assessment.risk_score += 15;
            reasons.emplace_back("Paired with bitwise XOR decoding loop");
        }

        if (features.inside_loop && (assessment.primary_category == BehaviorCategory::DirectSyscall ||
                                     assessment.primary_category == BehaviorCategory::AntiDebugOrTiming ||
                                     assessment.primary_category == BehaviorCategory::ObfuscatedPayload)) {
            addTag(assessment.tags, "inside_loop");
            assessment.risk_score += 8;
        }

        if (features.pointer_indirection_depth >= 3) {
            addTag(assessment.tags, "deep_pointer_indirection");
            assessment.risk_score += 10;
        }

        if (features.has_crypto_or_hash_constant) {
            addTag(assessment.tags, "api_hashing");
            addTag(assessment.tags, "crypto_constant");
            for (const auto &tag : features.crypto_hash_tags) {
                if (!tag.empty()) {
                    addTag(assessment.tags, tag);
                }
            }

            if (assessment.primary_category == BehaviorCategory::Benign) {
                if (features.inside_loop || features.pointer_indirection_depth >= 1) {
                    assessment.primary_category = BehaviorCategory::DynamicResolution;
                    assessment.risk_score = 68;
                    reasons.clear();
                    reasons.emplace_back(
                        "Combines cryptographic or API-hashing constant with loop or pointer indirection");
                    if (features.inside_loop) {
                        addTag(assessment.tags, "inside_loop");
                    }
                } else {
                    // Standalone crypto/hash constants without loop or dynamic context stay informational.
                    assessment.risk_score = std::max<uint32_t>(assessment.risk_score, 20);
                    reasons.clear();
                    reasons.emplace_back("Contains standalone cryptographic or hash constant (informational)");
                }
            } else {
                const bool dynamic_or_loop_context =
                    features.inside_loop || assessment.primary_category == BehaviorCategory::DynamicResolution ||
                    assessment.primary_category == BehaviorCategory::IndirectCall ||
                    assessment.primary_category == BehaviorCategory::ObfuscatedPayload;
                if (dynamic_or_loop_context) {
                    assessment.risk_score += 20;
                    reasons.emplace_back("Paired with API-hashing or cryptographic constant");
                    if (features.inside_loop) {
                        addTag(assessment.tags, "inside_loop");
                    }
                }
            }
        }

        if (features.is_auto_init_entrypoint && assessment.primary_category != BehaviorCategory::Benign &&
            assessment.risk_score > 0) {
            addTag(assessment.tags, "auto_init_entrypoint");
            if (!features.entrypoint_kind.empty()) {
                addTag(assessment.tags, features.entrypoint_kind);
            }
            assessment.risk_score += 12;
            reasons.emplace_back("Executed from auto-initialized entrypoint");
        }

        auto clearBenignPlaceholderReason = [&]() {
            if (reasons.size() == 1 && reasons[0] == "No anomalous behavioral or structural indicators detected") {
                reasons.clear();
            }
        };

        if (features.has_stack_string) {
            addTag(assessment.tags, "stack_string_obfuscation");
            const bool paired_with_context = assessment.primary_category == BehaviorCategory::MemoryAllocation ||
                                             assessment.primary_category == BehaviorCategory::MemoryProtection ||
                                             assessment.primary_category == BehaviorCategory::DynamicResolution ||
                                             assessment.primary_category == BehaviorCategory::IndirectCall ||
                                             features.inside_loop || features.has_bitwise_xor_loop ||
                                             features.resolved_from_symbol || features.has_tainted_exec_flow ||
                                             features.pointer_indirection_depth >= 1;
            if (paired_with_context && (assessment.primary_category == BehaviorCategory::Benign ||
                                        assessment.primary_category == BehaviorCategory::ObfuscatedPayload)) {
                assessment.primary_category = BehaviorCategory::ObfuscatedPayload;
                assessment.risk_score = std::max<uint32_t>(
                    assessment.primary_category == BehaviorCategory::Benign ? 0 : assessment.risk_score + 18, 55);
                clearBenignPlaceholderReason();
                reasons.emplace_back("Reconstructed stack-built string paired with loop or dynamic/memory context");
            } else {
                assessment.risk_score += 18;
                clearBenignPlaceholderReason();
                reasons.emplace_back("Constructs or consumes stack-obfuscated string");
            }
        }

        if (features.has_cff_dispatcher) {
            addTag(assessment.tags, "control_flow_flattening");
            const bool paired_with_non_benign_or_entropy =
                assessment.primary_category != BehaviorCategory::Benign || features.has_high_entropy_literal ||
                max_ent >= 6.8 || features.has_bitwise_xor_loop || features.has_stack_string ||
                features.resolved_from_symbol || features.has_tainted_exec_flow;
            if (paired_with_non_benign_or_entropy &&
                (assessment.primary_category == BehaviorCategory::Benign ||
                 assessment.primary_category == BehaviorCategory::ObfuscatedPayload)) {
                assessment.primary_category = BehaviorCategory::ObfuscatedPayload;
                assessment.risk_score = std::max<uint32_t>(assessment.risk_score + 20, 62);
                clearBenignPlaceholderReason();
                reasons.emplace_back(
                    "Control-flow flattening dispatcher paired with obfuscation or entropy indicators");
            } else {
                assessment.risk_score += 20;
                clearBenignPlaceholderReason();
                reasons.emplace_back("Exhibits switch-inside-loop control-flow flattening dispatcher");
            }
        }

        if (features.has_tainted_exec_flow) {
            addTag(assessment.tags, "tainted_buffer_exec_flow");
            assessment.risk_score += 22;
            clearBenignPlaceholderReason();
            reasons.emplace_back("Flows tainted buffer into executable memory or indirect execution sink");
        }

        if (!features.is_system_header && assessment.primary_category != BehaviorCategory::Benign &&
            assessment.primary_category != BehaviorCategory::MemoryAllocation) {
            addTag(assessment.tags, "non_system_header_origin");
        }

        assessment.risk_score = std::min<uint32_t>(100, assessment.risk_score);

        std::ostringstream oss;
        if (!features.caller_function.empty()) {
            oss << "[" << features.caller_function << "] ";
        }
        oss << getBehaviorCategoryName(assessment.primary_category) << ": ";
        for (size_t i = 0; i < reasons.size(); ++i) {
            if (i > 0) {
                oss << "; ";
            }
            oss << reasons[i];
        }
        assessment.rationale = oss.str();

        return assessment;
    }

} // namespace traceql
