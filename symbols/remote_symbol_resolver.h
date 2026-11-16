#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

namespace traceql {

    /// @brief Online & manifest-based resolver for unknown / 3rd-party symbols.
    class RemoteSymbolResolver {
      public:
        static RemoteSymbolResolver &instance() noexcept;

        /// @brief Loads a symbol-to-library mapping file (format: "symbol library.so" per line or JSON).
        size_t loadManifestFile(const std::string &manifest_path);

        /// @brief Looks up a symbol in the loaded manifests.
        [[nodiscard]] std::string_view lookup(std::string_view symbol_name) const noexcept;

        /// @brief Formats an online documentation search URL for an unknown symbol.
        [[nodiscard]] std::string formatOnlineLookupUrl(std::string_view symbol_name) const;

        /// @brief Manually stores a resolved symbol into local cache.
        void cacheResolution(std::string_view symbol, std::string_view library);

      private:
        std::unordered_map<std::string, std::string> cache_;
    };

} // namespace traceql
