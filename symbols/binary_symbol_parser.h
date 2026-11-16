#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace traceql {

    /// @brief Binary format type of a scanned library.
    enum class BinaryFormat : uint8_t {
        Unknown = 0,
        ELF64,        ///< Linux / Android 64-bit ELF (.so)
        ELF32,        ///< Linux / Android 32-bit ELF (.so)
        PE32Plus,     ///< Windows 64-bit PE/COFF (.dll / .exe)
        PE32,         ///< Windows 32-bit PE/COFF (.dll / .exe)
        CoffImportLib ///< Windows COFF import library (.lib / .dll.a)
    };

    /// @brief Information about a library parsed directly from disk.
    struct ParsedLibraryInfo {
        std::string file_path;
        std::string library_name;
        BinaryFormat format{BinaryFormat::Unknown};
        size_t exported_symbol_count{0};
    };

    /// @brief Zero-database dynamic symbol registry.
    /// Dynamically parses ELF (.so), PE/COFF (.dll, .exe), and COFF import library (.lib)
    /// export/import tables directly from disk on Linux, Windows, and Android without
    /// any hardcoded library names or symbol tables.
    class DynamicSymbolRegistry {
      public:
        static DynamicSymbolRegistry &instance() noexcept;

        /// @brief Loads all exported/imported symbols from an ELF (.so), PE/COFF (.dll/.exe), or COFF import (.lib)
        /// file.
        bool loadLibrary(const std::string &file_path);

        /// @brief Scans a directory for .so, .dll, .exe, .lib, or .dll.a files.
        size_t scanDirectory(const std::string &dir_path, bool recursive = false);

        /// @brief Automatically discovers and indexes libraries in standard OS/toolchain/SDK directories.
        size_t scanDefaultSystemDirs();

        /// @brief Queries which library exports the given symbol name.
        /// @return Library name or empty string if not found in loaded libraries.
        [[nodiscard]] std::string_view findLibraryForSymbol(std::string_view symbol_name) const noexcept;

        /// @brief Manually registers a symbol mapping (used for remote web query caches or custom manifests).
        void registerSymbol(std::string_view symbol_name, std::string_view library_name);

        /// @brief Clears all dynamically loaded symbols.
        void clear() noexcept;

        /// @brief Returns total number of registered symbols across all parsed libraries.
        [[nodiscard]] size_t totalSymbolCount() const noexcept {
            return symbol_to_library_.size();
        }

        /// @brief Returns list of loaded libraries.
        [[nodiscard]] const std::vector<ParsedLibraryInfo> &getLoadedLibraries() const noexcept {
            return loaded_libraries_;
        }

      private:
        std::unordered_map<std::string, std::string> symbol_to_library_;
        std::unordered_set<std::string> visited_canonical_paths_;
        std::vector<ParsedLibraryInfo> loaded_libraries_;
    };

    /// @brief Low-level parser for extracting export tables from 32-bit and 64-bit ELF files (.so / .o).
    bool parseElfExports(const std::string &file_path, std::vector<std::string> &out_symbols, std::string &out_soname);

    /// @brief Low-level parser for extracting export tables from PE32/PE32+ binaries (.dll / .exe).
    bool parsePeExports(const std::string &file_path, std::vector<std::string> &out_symbols, std::string &out_dllname);

    /// @brief Low-level parser for extracting symbol-to-DLL mappings from COFF import libraries (.lib / .dll.a).
    bool parseCoffImportLib(const std::string &file_path,
                            std::vector<std::pair<std::string, std::string>> &out_symbol_dlls);

} // namespace traceql
