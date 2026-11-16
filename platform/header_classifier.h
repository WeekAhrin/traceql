#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace traceql {

    /// @brief Target operating system family detected from header paths or target triples.
    enum class TargetOS : uint8_t { Unknown = 0, Linux, Windows, Android, MacOS };

    /// @brief Target operating system and environment.
    enum class TargetPlatform : uint8_t {
        Auto = 0,
        Linux_Glibc,
        Linux_Musl,
        Android_Bionic,
        Windows_MSVC_UCRT,
        Windows_MinGW,
        Apple_Darwin
    };

    /// @brief Header classification derived purely from physical path structure (zero hardcoded library names).
    struct HeaderPathInfo {
        TargetPlatform platform{TargetPlatform::Auto};
        std::string module_hint; ///< Top-level include group or header name (e.g. "X11", "ucrt", "c++", "stdio.h")
        bool is_system_path{false};
    };

    /// @brief Classifies headers and target triples purely from physical file path structure
    /// and compiler target/SDK conventions (zero hardcoded library names or symbol tables).
    class HeaderClassifier {
      public:
        /// @brief Detects TargetOS from a header path and optional compiler target triple.
        [[nodiscard]] TargetOS detectTargetOS(std::string_view header_path,
                                              std::string_view triple = "") const noexcept;

        /// @brief Classifies a header path into TargetPlatform, module hint, and system-path status.
        [[nodiscard]] HeaderPathInfo classify(std::string_view file_path,
                                              TargetPlatform target_hint = TargetPlatform::Auto,
                                              std::string_view triple = "") const noexcept;

        /// @brief Maps a TargetPlatform to its corresponding TargetOS.
        [[nodiscard]] static TargetOS platformToTargetOS(TargetPlatform platform) noexcept;

        /// @brief Detects TargetPlatform purely from physical path structure and optional triple.
        [[nodiscard]] static TargetPlatform detectPlatformFromPath(std::string_view file_path,
                                                                   std::string_view triple = "") noexcept;
    };

    /// @brief Extracts platform and include module hint purely from the physical header path.
    [[nodiscard]] HeaderPathInfo classifyHeaderPath(std::string_view file_path,
                                                    TargetPlatform target_hint = TargetPlatform::Auto) noexcept;

    /// @brief Gets human-readable string for TargetPlatform.
    [[nodiscard]] const char *getPlatformName(TargetPlatform platform) noexcept;

    /// @brief Gets human-readable string for TargetOS.
    [[nodiscard]] const char *getTargetOSName(TargetOS os) noexcept;

    /// @brief Parses platform from string ("linux", "android", "windows", "mingw", "darwin", "auto").
    [[nodiscard]] TargetPlatform parsePlatform(std::string_view str) noexcept;

} // namespace traceql
