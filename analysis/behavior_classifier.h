#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "platform/header_classifier.h"

namespace traceql {

    /// @brief Behavioral categories for AST call sites, inline assembly, and payload patterns.
    enum class BehaviorCategory : uint8_t {
        Benign = 0,
        MemoryAllocation,
        MemoryProtection,
        DynamicResolution,
        DirectSyscall,
        IndirectCall,
        ProcessThreadOp,
        ObfuscatedPayload,
        AntiDebugOrTiming,
        NetworkOrIPC,
        FileOrRegistryIO
    };

    /// @brief Returns a human-readable static string for a BehaviorCategory.
    [[nodiscard]] const char *getBehaviorCategoryName(BehaviorCategory cat) noexcept;

    /// @brief Structural, semantic, and entropy features extracted from an AST node / call site.
    struct BehaviorFeatures {
        TargetOS target_os{TargetOS::Unknown};
        std::string
            call_kind; ///< "direct", "indirect", "fn_ptr_cast", "inline_asm", "new", "delete", "throw", "construct"
        std::string return_type;              ///< Normalized return type (e.g. "void*", "int", "FARPROC", "HANDLE")
        std::vector<std::string> param_types; ///< Normalized parameter types
        std::vector<std::string>
            arg_shapes; ///< Argument shape descriptors (e.g. "lit:const char*", "const:0x40", "var:void*")
        std::vector<uint64_t> numeric_constants; ///< Constant integer/bitmask values passed as arguments
        std::vector<std::string>
            string_literals;               ///< Literal strings passed as arguments (for structural path/scheme checks)
        std::string asm_text;              ///< Inline assembly template text when call_kind == "inline_asm"
        std::vector<double> arg_entropies; ///< Shannon entropies of literal arguments
        double max_arg_entropy{0.0};       ///< Maximum Shannon entropy among literal arguments
        bool has_high_entropy_literal{false};
        bool is_variadic{false};
        bool is_system_header{false};
        bool resolved_from_symbol{false};      ///< True if invoking a function pointer obtained via dynamic resolution
        bool inside_loop{false};               ///< True if the call/asm resides inside a loop
        bool has_bitwise_xor_loop{false};      ///< True if structural XOR/rolling-key decoding loop is detected
        uint32_t pointer_indirection_depth{0}; ///< Depth of pointer/struct indirection (e.g. PEB/LDR walks)
        std::string caller_function;           ///< Optional enclosing function name for rationale reporting
        bool has_crypto_or_hash_constant{false};   ///< True if cryptographic S-box or API-hash constant is present
        std::vector<std::string> crypto_hash_tags; ///< e.g. "fnv1a_hash", "crc32_poly", "chacha20_const", "aes_sbox",
                                                   ///< "ror13_hash", "djb2_hash"
        bool is_auto_init_entrypoint{false};       ///< True if inside constructor, DllMain, JNI_OnLoad, or TLS callback
        std::string entrypoint_kind;               ///< e.g. "constructor", "dllmain", "jni_onload", "tls_callback"
        bool has_stack_string{false}; ///< True if character-by-character stack string construction is detected
        std::vector<std::string> reconstructed_stack_strings; ///< Stack-built strings reconstructed via AST analysis
        bool has_cff_dispatcher{false}; ///< True if switch-inside-loop control-flow flattening dispatcher is detected
        bool has_tainted_exec_flow{
            false}; ///< True if intra-procedural taint flows into executable memory or indirect exec
    };

    /// @brief Behavioral classification output with primary category, tags, risk score [0, 100], and rationale.
    struct BehaviorAssessment {
        BehaviorCategory primary_category{BehaviorCategory::Benign};
        std::vector<std::string> tags;
        uint32_t risk_score{0};
        std::string rationale;
    };

    /// @brief Table-free, structural, semantic, and entropy-driven behavioral classifier.
    class BehaviorClassifier {
      public:
        /// @brief Classifies an AST call site or inline assembly block using structural and entropy heuristics.
        [[nodiscard]] static BehaviorAssessment classify(const BehaviorFeatures &features);
    };

} // namespace traceql
