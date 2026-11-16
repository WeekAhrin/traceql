#include "tools/traceql/platform/header_classifier.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

namespace traceql {

    namespace {

        [[nodiscard]] bool containsCaseInsensitive(std::string_view str, std::string_view substr) noexcept {
            if (substr.empty())
                return true;
            if (str.size() < substr.size())
                return false;

            auto it = std::search(str.begin(), str.end(), substr.begin(), substr.end(), [](char ch1, char ch2) {
                return std::tolower(static_cast<unsigned char>(ch1)) == std::tolower(static_cast<unsigned char>(ch2));
            });
            return it != str.end();
        }

        [[nodiscard]] std::string normalizeSlashes(std::string_view file_path) {
            std::string norm(file_path);
            std::replace(norm.begin(), norm.end(), '\\', '/');
            return norm;
        }

        [[nodiscard]] bool hasWindowsDrivePrefix(std::string_view file_path) noexcept {
            return file_path.size() >= 3 && std::isalpha(static_cast<unsigned char>(file_path[0])) &&
                   file_path[1] == ':' && (file_path[2] == '\\' || file_path[2] == '/');
        }

        [[nodiscard]] bool endsWithCaseInsensitive(std::string_view str, std::string_view suffix) noexcept {
            if (str.size() < suffix.size())
                return false;
            const std::string_view tail = str.substr(str.size() - suffix.size());
            return std::equal(tail.begin(), tail.end(), suffix.begin(), [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
            });
        }

        [[nodiscard]] bool hasPathSegmentPrefix(std::string_view norm_path, std::string_view segment) noexcept {
            if (containsCaseInsensitive(norm_path, segment)) {
                return true;
            }
            if (!segment.empty() && segment.front() == '/') {
                const std::string_view no_leading = segment.substr(1);
                if (norm_path.size() >= no_leading.size() &&
                    std::equal(no_leading.begin(), no_leading.end(), norm_path.begin(), [](char a, char b) {
                        return std::tolower(static_cast<unsigned char>(a)) ==
                               std::tolower(static_cast<unsigned char>(b));
                    })) {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] TargetPlatform detectFromTriple(std::string_view triple) noexcept {
            if (triple.empty())
                return TargetPlatform::Auto;

            if (containsCaseInsensitive(triple, "android")) {
                return TargetPlatform::Android_Bionic;
            }
            if (containsCaseInsensitive(triple, "mingw")) {
                return TargetPlatform::Windows_MinGW;
            }
            if (containsCaseInsensitive(triple, "windows") || containsCaseInsensitive(triple, "win32") ||
                containsCaseInsensitive(triple, "win64") || containsCaseInsensitive(triple, "msvc") ||
                containsCaseInsensitive(triple, "cygwin")) {
                return TargetPlatform::Windows_MSVC_UCRT;
            }
            if (containsCaseInsensitive(triple, "darwin") || containsCaseInsensitive(triple, "macosx") ||
                containsCaseInsensitive(triple, "apple") || containsCaseInsensitive(triple, "ios")) {
                return TargetPlatform::Apple_Darwin;
            }
            if (containsCaseInsensitive(triple, "musl")) {
                return TargetPlatform::Linux_Musl;
            }
            if (containsCaseInsensitive(triple, "linux")) {
                return TargetPlatform::Linux_Glibc;
            }
            return TargetPlatform::Auto;
        }

        [[nodiscard]] std::string extractSubpathHint(std::string_view file_path) {
            std::string norm = normalizeSlashes(file_path);

            // Find the last "/include/" (case-insensitive for Windows Kits "/Include/")
            size_t anchor = std::string::npos;
            if (const size_t pos = norm.rfind("/include/"); pos != std::string::npos) {
                anchor = pos + 9;
            } else if (const size_t pos2 = norm.rfind("/Include/"); pos2 != std::string::npos) {
                anchor = pos2 + 9;
            }

            if (anchor != std::string::npos && anchor < norm.size()) {
                std::string_view sub(norm.data() + anchor, norm.size() - anchor);
                // Skip numeric SDK version segment (e.g. Windows Kits "10.0.22621.0/ucrt/...")
                const size_t slash = sub.find('/');
                if (slash != std::string_view::npos && !sub.empty() &&
                    std::isdigit(static_cast<unsigned char>(sub[0]))) {
                    sub = sub.substr(slash + 1);
                }
                const size_t next_slash = sub.find('/');
                if (next_slash != std::string_view::npos) {
                    return std::string(sub.substr(0, next_slash));
                }
                return std::string(sub);
            }

            const size_t last_slash = norm.rfind('/');
            if (last_slash != std::string::npos && last_slash + 1 < norm.size()) {
                return norm.substr(last_slash + 1);
            }
            return norm;
        }

    } // namespace

    TargetOS HeaderClassifier::platformToTargetOS(TargetPlatform platform) noexcept {
        switch (platform) {
        case TargetPlatform::Linux_Glibc:
        case TargetPlatform::Linux_Musl:
            return TargetOS::Linux;
        case TargetPlatform::Windows_MSVC_UCRT:
        case TargetPlatform::Windows_MinGW:
            return TargetOS::Windows;
        case TargetPlatform::Android_Bionic:
            return TargetOS::Android;
        case TargetPlatform::Apple_Darwin:
            return TargetOS::MacOS;
        case TargetPlatform::Auto:
        default:
            return TargetOS::Unknown;
        }
    }

    TargetPlatform HeaderClassifier::detectPlatformFromPath(std::string_view file_path,
                                                            std::string_view triple) noexcept {
        // 1. Explicit compiler target triple takes highest precedence when present.
        if (const TargetPlatform from_triple = detectFromTriple(triple); from_triple != TargetPlatform::Auto) {
            return from_triple;
        }

        if (file_path.empty()) {
            return TargetPlatform::Auto;
        }

        const std::string norm = normalizeSlashes(file_path);

        // 2. Android NDK / Bionic (checked before generic sysroot / /usr/include / Windows host slashes).
        const bool is_jni_header = endsWithCaseInsensitive(norm, "/jni.h") || norm == "jni.h";
        if (containsCaseInsensitive(norm, "aarch64-linux-android") ||
            containsCaseInsensitive(norm, "arm-linux-androideabi") ||
            containsCaseInsensitive(norm, "armv7a-linux-androideabi") ||
            containsCaseInsensitive(norm, "x86_64-linux-android") ||
            containsCaseInsensitive(norm, "i686-linux-android") || containsCaseInsensitive(norm, "-linux-android") ||
            containsCaseInsensitive(norm, "/bionic/") || containsCaseInsensitive(norm, "android-ndk") ||
            hasPathSegmentPrefix(norm, "/ndk/") || hasPathSegmentPrefix(norm, "/android/") ||
            (is_jni_header && (containsCaseInsensitive(norm, "ndk") || containsCaseInsensitive(norm, "android") ||
                               containsCaseInsensitive(norm, "sysroot")))) {
            return TargetPlatform::Android_Bionic;
        }

        // 3. Windows (MinGW / w32api / MSVC / Windows Kits / UCRT / WinRT / backslash paths).
        if (containsCaseInsensitive(norm, "mingw") || containsCaseInsensitive(norm, "w32api")) {
            return TargetPlatform::Windows_MinGW;
        }

        if (containsCaseInsensitive(norm, "windows kits") || containsCaseInsensitive(norm, "msvc") ||
            containsCaseInsensitive(norm, "visual studio") || hasPathSegmentPrefix(norm, "/ucrt/") ||
            hasPathSegmentPrefix(norm, "/um/") || hasPathSegmentPrefix(norm, "/shared/") ||
            hasPathSegmentPrefix(norm, "/winrt/") || hasPathSegmentPrefix(norm, "/km/") ||
            hasWindowsDrivePrefix(file_path) || file_path.find('\\') != std::string_view::npos) {
            return TargetPlatform::Windows_MSVC_UCRT;
        }

        // 4. Apple / Darwin SDKs.
        if (containsCaseInsensitive(norm, "MacOSX") || containsCaseInsensitive(norm, "iPhoneOS") ||
            containsCaseInsensitive(norm, "iPhoneSimulator") || containsCaseInsensitive(norm, "Xcode.app") ||
            containsCaseInsensitive(norm, "Developer/SDKs") || containsCaseInsensitive(norm, ".sdk/usr/include")) {
            return TargetPlatform::Apple_Darwin;
        }

        // 5. Linux (musl / glibc / multiarch triples / standard system include roots).
        if (containsCaseInsensitive(norm, "-linux-musl") || hasPathSegmentPrefix(norm, "/musl/")) {
            return TargetPlatform::Linux_Musl;
        }

        if (containsCaseInsensitive(norm, "x86_64-linux-gnu") || containsCaseInsensitive(norm, "aarch64-linux-gnu") ||
            containsCaseInsensitive(norm, "arm-linux-gnueabi") || containsCaseInsensitive(norm, "i386-linux-gnu") ||
            containsCaseInsensitive(norm, "riscv64-linux-gnu") || containsCaseInsensitive(norm, "-linux-gnu") ||
            containsCaseInsensitive(norm, "/usr/include") || containsCaseInsensitive(norm, "/usr/local/include") ||
            hasPathSegmentPrefix(norm, "/sys/") || hasPathSegmentPrefix(norm, "/linux/") ||
            containsCaseInsensitive(norm, "sysroot")) {
            return TargetPlatform::Linux_Glibc;
        }

        return TargetPlatform::Auto;
    }

    TargetOS HeaderClassifier::detectTargetOS(std::string_view header_path, std::string_view triple) const noexcept {
        return platformToTargetOS(detectPlatformFromPath(header_path, triple));
    }

    HeaderPathInfo HeaderClassifier::classify(std::string_view file_path, TargetPlatform target_hint,
                                              std::string_view triple) const noexcept {
        HeaderPathInfo info{};
        info.platform = target_hint;
        info.module_hint = extractSubpathHint(file_path);

        if (target_hint == TargetPlatform::Auto) {
            info.platform = detectPlatformFromPath(file_path, triple);
        }

        info.is_system_path =
            (info.platform != TargetPlatform::Auto) || containsCaseInsensitive(file_path, "/usr/") ||
            containsCaseInsensitive(file_path, "sysroot") || containsCaseInsensitive(file_path, "windows kits") ||
            containsCaseInsensitive(file_path, "msvc") || containsCaseInsensitive(file_path, "mingw") ||
            containsCaseInsensitive(file_path, "w32api") || containsCaseInsensitive(file_path, "ndk") ||
            containsCaseInsensitive(file_path, "bionic");
        return info;
    }

    HeaderPathInfo classifyHeaderPath(std::string_view file_path, TargetPlatform target_hint) noexcept {
        const HeaderClassifier classifier;
        return classifier.classify(file_path, target_hint);
    }

    const char *getPlatformName(TargetPlatform platform) noexcept {
        switch (platform) {
        case TargetPlatform::Linux_Glibc:
            return "Linux (glibc)";
        case TargetPlatform::Linux_Musl:
            return "Linux (musl)";
        case TargetPlatform::Android_Bionic:
            return "Android (Bionic)";
        case TargetPlatform::Windows_MSVC_UCRT:
            return "Windows (MSVC UCRT)";
        case TargetPlatform::Windows_MinGW:
            return "Windows (MinGW)";
        case TargetPlatform::Apple_Darwin:
            return "Apple (Darwin / macOS / iOS)";
        case TargetPlatform::Auto:
        default:
            return "Auto / Generic";
        }
    }

    const char *getTargetOSName(TargetOS os) noexcept {
        switch (os) {
        case TargetOS::Linux:
            return "Linux";
        case TargetOS::Windows:
            return "Windows";
        case TargetOS::Android:
            return "Android";
        case TargetOS::MacOS:
            return "MacOS";
        case TargetOS::Unknown:
        default:
            return "Unknown";
        }
    }

    TargetPlatform parsePlatform(std::string_view str) noexcept {
        if (str == "linux" || str == "glibc")
            return TargetPlatform::Linux_Glibc;
        if (str == "musl")
            return TargetPlatform::Linux_Musl;
        if (str == "android" || str == "bionic")
            return TargetPlatform::Android_Bionic;
        if (str == "mingw")
            return TargetPlatform::Windows_MinGW;
        if (str == "windows" || str == "win32" || str == "ucrt" || str == "msvc") {
            return TargetPlatform::Windows_MSVC_UCRT;
        }
        if (str == "darwin" || str == "apple" || str == "macos")
            return TargetPlatform::Apple_Darwin;
        return TargetPlatform::Auto;
    }

} // namespace traceql
