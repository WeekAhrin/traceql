#include "tools/traceql/symbols/binary_symbol_parser.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>
#include <vector>

namespace traceql {

    namespace fs = std::filesystem;

    namespace {

        [[nodiscard]] bool hasSuffixCaseInsensitive(std::string_view str, std::string_view suffix) noexcept {
            if (str.size() < suffix.size())
                return false;
            const std::string_view tail = str.substr(str.size() - suffix.size());
            return std::equal(tail.begin(), tail.end(), suffix.begin(), [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
            });
        }

        [[nodiscard]] bool isSupportedBinaryFilename(const fs::path &p) {
            const std::string filename = p.filename().string();
            return hasSuffixCaseInsensitive(filename, ".so") || filename.find(".so.") != std::string::npos ||
                   hasSuffixCaseInsensitive(filename, ".dll") || hasSuffixCaseInsensitive(filename, ".exe") ||
                   hasSuffixCaseInsensitive(filename, ".lib") || hasSuffixCaseInsensitive(filename, ".dll.a");
        }

        [[nodiscard]] BinaryFormat detectElfFormat(const std::string &file_path) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open())
                return BinaryFormat::Unknown;
            uint8_t ident[6]{};
            if (!file.read(reinterpret_cast<char *>(ident), sizeof(ident))) {
                return BinaryFormat::Unknown;
            }
            if (ident[0] == 0x7F && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F') {
                if (ident[4] == 1)
                    return BinaryFormat::ELF32;
                if (ident[4] == 2)
                    return BinaryFormat::ELF64;
            }
            return BinaryFormat::Unknown;
        }

        [[nodiscard]] BinaryFormat detectPeFormat(const std::string &file_path) {
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open())
                return BinaryFormat::Unknown;

            uint16_t mz = 0;
            if (!file.read(reinterpret_cast<char *>(&mz), sizeof(mz)) || mz != 0x5A4D) {
                return BinaryFormat::Unknown;
            }
            int32_t lfanew = 0;
            file.seekg(60, std::ios::beg);
            if (!file.read(reinterpret_cast<char *>(&lfanew), sizeof(lfanew)) || lfanew <= 0) {
                return BinaryFormat::Unknown;
            }
            uint32_t pe_sig = 0;
            file.seekg(lfanew, std::ios::beg);
            if (!file.read(reinterpret_cast<char *>(&pe_sig), sizeof(pe_sig)) || pe_sig != 0x00004550) {
                return BinaryFormat::Unknown;
            }
            uint16_t opt_magic = 0;
            file.seekg(lfanew + 4 + 20, std::ios::beg);
            if (!file.read(reinterpret_cast<char *>(&opt_magic), sizeof(opt_magic))) {
                return BinaryFormat::Unknown;
            }
            if (opt_magic == 0x20B)
                return BinaryFormat::PE32Plus;
            if (opt_magic == 0x10B)
                return BinaryFormat::PE32;
            return BinaryFormat::Unknown;
        }

    } // namespace

    DynamicSymbolRegistry &DynamicSymbolRegistry::instance() noexcept {
        static DynamicSymbolRegistry s_instance;
        return s_instance;
    }

    void DynamicSymbolRegistry::clear() noexcept {
        symbol_to_library_.clear();
        visited_canonical_paths_.clear();
        loaded_libraries_.clear();
    }

    void DynamicSymbolRegistry::registerSymbol(std::string_view symbol_name, std::string_view library_name) {
        if (!symbol_name.empty() && !library_name.empty()) {
            symbol_to_library_[std::string(symbol_name)] = std::string(library_name);
        }
    }

    std::string_view DynamicSymbolRegistry::findLibraryForSymbol(std::string_view symbol_name) const noexcept {
        auto it = symbol_to_library_.find(std::string(symbol_name));
        if (it != symbol_to_library_.end()) {
            return it->second;
        }
        return {};
    }

    bool DynamicSymbolRegistry::loadLibrary(const std::string &file_path) {
        std::error_code ec;
        const fs::path canon_path = fs::weakly_canonical(file_path, ec);
        const std::string canon_str = ec ? file_path : canon_path.string();
        if (!visited_canonical_paths_.insert(canon_str).second) {
            return false;
        }

        std::vector<std::string> symbols;
        std::string lib_name;
        BinaryFormat format = BinaryFormat::Unknown;

        if (parseElfExports(file_path, symbols, lib_name)) {
            format = detectElfFormat(file_path);
            if (format == BinaryFormat::Unknown)
                format = BinaryFormat::ELF64;
        } else if (parsePeExports(file_path, symbols, lib_name)) {
            format = detectPeFormat(file_path);
            if (format == BinaryFormat::Unknown)
                format = BinaryFormat::PE32Plus;
        } else {
            std::vector<std::pair<std::string, std::string>> import_pairs;
            if (parseCoffImportLib(file_path, import_pairs)) {
                const std::string fallback_name = fs::path(file_path).filename().string();
                for (const auto &[sym, dll] : import_pairs) {
                    const std::string &target_lib = dll.empty() ? fallback_name : dll;
                    symbol_to_library_.try_emplace(sym, target_lib);
                    if (lib_name.empty() && !dll.empty()) {
                        lib_name = dll;
                    }
                }
                if (lib_name.empty()) {
                    lib_name = fallback_name;
                }
                ParsedLibraryInfo info{};
                info.file_path = file_path;
                info.library_name = lib_name;
                info.format = BinaryFormat::CoffImportLib;
                info.exported_symbol_count = import_pairs.size();
                loaded_libraries_.push_back(std::move(info));
                return true;
            }
            return false;
        }

        if (lib_name.empty()) {
            lib_name = fs::path(file_path).filename().string();
        }

        for (const auto &sym : symbols) {
            symbol_to_library_.try_emplace(sym, lib_name);
        }

        ParsedLibraryInfo info{};
        info.file_path = file_path;
        info.library_name = lib_name;
        info.format = format;
        info.exported_symbol_count = symbols.size();
        loaded_libraries_.push_back(std::move(info));

        return true;
    }

    size_t DynamicSymbolRegistry::scanDirectory(const std::string &dir_path, bool recursive) {
        size_t loaded_count = 0;
        std::error_code ec;

        if (!fs::exists(dir_path, ec) || !fs::is_directory(dir_path, ec)) {
            return 0;
        }

        auto process_entry = [&](const fs::path &p) {
            if (fs::is_regular_file(p, ec) && isSupportedBinaryFilename(p)) {
                if (loadLibrary(p.string())) {
                    ++loaded_count;
                }
            }
        };

        if (recursive) {
            for (const auto &entry :
                 fs::recursive_directory_iterator(dir_path, fs::directory_options::skip_permission_denied, ec)) {
                process_entry(entry.path());
            }
        } else {
            for (const auto &entry :
                 fs::directory_iterator(dir_path, fs::directory_options::skip_permission_denied, ec)) {
                process_entry(entry.path());
            }
        }

        return loaded_count;
    }

    size_t DynamicSymbolRegistry::scanDefaultSystemDirs() {
        size_t total = 0;
        std::error_code ec;

        auto scanIfExists = [&](const fs::path &dir, bool recursive) {
            if (fs::exists(dir, ec) && fs::is_directory(dir, ec)) {
                total += scanDirectory(dir.string(), recursive);
            }
        };

        auto scanEnvList = [&](const char *env_name, char sep) {
            if (const char *val = std::getenv(env_name)) {
                std::istringstream ss(val);
                std::string item;
                while (std::getline(ss, item, sep)) {
                    if (!item.empty()) {
                        total += scanDirectory(item, false);
                    }
                }
            }
        };

        // Android NDK / Sysroot discovery
        for (const char *ndk_env : {"ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"}) {
            if (const char *ndk = std::getenv(ndk_env)) {
                const fs::path ndk_root(ndk);
                scanIfExists(ndk_root / "sysroot" / "usr" / "lib", true);
                const fs::path prebuilt = ndk_root / "toolchains" / "llvm" / "prebuilt";
                if (fs::exists(prebuilt, ec) && fs::is_directory(prebuilt, ec)) {
                    for (const auto &host_entry : fs::directory_iterator(prebuilt, ec)) {
                        scanIfExists(host_entry.path() / "sysroot" / "usr" / "lib", true);
                    }
                }
            }
        }

        if (const char *android_sysroot = std::getenv("ANDROID_SYSROOT")) {
            const fs::path sr(android_sysroot);
            scanIfExists(sr / "usr" / "lib", true);
            scanIfExists(sr / "usr" / "lib64", true);
            scanIfExists(sr, false);
        }

        // Generic cross-compilation SYSROOT
        if (const char *sysroot = std::getenv("SYSROOT")) {
            const fs::path sr(sysroot);
            scanIfExists(sr / "usr" / "lib64", false);
            scanIfExists(sr / "usr" / "lib", false);
            scanIfExists(sr / "lib64", false);
            scanIfExists(sr / "lib", false);
        }

        // Windows SDK (.lib import libraries)
        for (const char *winsdk_env : {"WINSDK", "WindowsSdkDir"}) {
            if (const char *sdk = std::getenv(winsdk_env)) {
                const fs::path sdk_root(sdk);
                scanIfExists(sdk_root / "Lib", true);
                scanIfExists(sdk_root, false);
            }
        }

#if defined(_WIN32)
        if (const char *sys_root = std::getenv("SystemRoot")) {
            total += scanDirectory(std::string(sys_root) + "\\System32", false);
            total += scanDirectory(std::string(sys_root) + "\\SysWOW64", false);
        } else {
            total += scanDirectory("C:\\Windows\\System32", false);
            total += scanDirectory("C:\\Windows\\SysWOW64", false);
        }
        scanEnvList("PATH", ';');
        scanEnvList("LIBRARY_PATH", ';');
#else
        scanEnvList("LD_LIBRARY_PATH", ':');
        scanEnvList("LIBRARY_PATH", ':');
        scanEnvList("PATH", ':');
        total += scanDirectory("/lib64", false);
        total += scanDirectory("/usr/lib64", false);
        total += scanDirectory("/lib", false);
        total += scanDirectory("/usr/lib", false);
        total += scanDirectory("/usr/local/lib64", false);
        total += scanDirectory("/usr/local/lib", false);
#endif
        return total;
    }

    // =========================================================================
    // Native ELF Export Parser (Linux & Android 32-bit / 64-bit .so)
    // =========================================================================

#pragma pack(push, 1)
    struct Elf32_Hdr {
        uint8_t e_ident[16];
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_version;
        uint32_t e_entry;
        uint32_t e_phoff;
        uint32_t e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize;
        uint16_t e_phentsize;
        uint16_t e_phnum;
        uint16_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
    };

    struct Elf32_Shdr {
        uint32_t sh_name;
        uint32_t sh_type;
        uint32_t sh_flags;
        uint32_t sh_addr;
        uint32_t sh_offset;
        uint32_t sh_size;
        uint32_t sh_link;
        uint32_t sh_info;
        uint32_t sh_addralign;
        uint32_t sh_entsize;
    };

    struct Elf32_Sym {
        uint32_t st_name;
        uint32_t st_value;
        uint32_t st_size;
        uint8_t st_info;
        uint8_t st_other;
        uint16_t st_shndx;
    };

    struct Elf32_Dyn {
        int32_t d_tag;
        uint32_t d_val;
    };

    struct Elf64_Hdr {
        uint8_t e_ident[16];
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_version;
        uint64_t e_entry;
        uint64_t e_phoff;
        uint64_t e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize;
        uint16_t e_phentsize;
        uint16_t e_phnum;
        uint16_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
    };

    struct Elf64_Shdr {
        uint32_t sh_name;
        uint32_t sh_type;
        uint64_t sh_flags;
        uint64_t sh_addr;
        uint64_t sh_offset;
        uint64_t sh_size;
        uint32_t sh_link;
        uint32_t sh_info;
        uint64_t sh_addralign;
        uint64_t sh_entsize;
    };

    struct Elf64_Sym {
        uint32_t st_name;
        uint8_t st_info;
        uint8_t st_other;
        uint16_t st_shndx;
        uint64_t st_value;
        uint64_t st_size;
    };

    struct Elf64_Dyn {
        int64_t d_tag;
        uint64_t d_val;
    };
#pragma pack(pop)

    template <typename ElfHdr, typename ElfShdr, typename ElfSym, typename ElfDyn>
    static bool parseElfExportsImpl(std::ifstream &file, const std::string &file_path,
                                    std::vector<std::string> &out_symbols, std::string &out_soname) {
        file.seekg(0, std::ios::beg);
        ElfHdr header{};
        if (!file.read(reinterpret_cast<char *>(&header), sizeof(header))) {
            return false;
        }

        if (header.e_shoff == 0 || header.e_shnum == 0 || header.e_shentsize != sizeof(ElfShdr)) {
            return false;
        }

        file.seekg(static_cast<std::streamoff>(header.e_shoff), std::ios::beg);
        std::vector<ElfShdr> shdrs(header.e_shnum);
        if (!file.read(reinterpret_cast<char *>(shdrs.data()),
                       static_cast<std::streamsize>(header.e_shnum) * sizeof(ElfShdr))) {
            return false;
        }

        // Extract DT_SONAME (d_tag == 14) from SHT_DYNAMIC (sh_type == 6) if available
        if (out_soname.empty()) {
            for (const auto &sec : shdrs) {
                if (sec.sh_type == 6 && sec.sh_link < shdrs.size() && sec.sh_entsize == sizeof(ElfDyn) &&
                    sec.sh_size > 0) {
                    const auto &str_sec = shdrs[sec.sh_link];
                    if (str_sec.sh_size == 0)
                        continue;

                    std::vector<char> dynstr(str_sec.sh_size);
                    file.seekg(static_cast<std::streamoff>(str_sec.sh_offset), std::ios::beg);
                    if (!file.read(dynstr.data(), static_cast<std::streamsize>(str_sec.sh_size)))
                        continue;

                    const size_t num_dyn = sec.sh_size / sizeof(ElfDyn);
                    std::vector<ElfDyn> dyns(num_dyn);
                    file.seekg(static_cast<std::streamoff>(sec.sh_offset), std::ios::beg);
                    if (!file.read(reinterpret_cast<char *>(dyns.data()),
                                   static_cast<std::streamsize>(num_dyn * sizeof(ElfDyn)))) {
                        continue;
                    }

                    for (const auto &dyn : dyns) {
                        if (dyn.d_tag == 0)
                            break;                                          // DT_NULL
                        if (dyn.d_tag == 14 && dyn.d_val < dynstr.size()) { // DT_SONAME
                            const char *soname = &dynstr[dyn.d_val];
                            if (soname[0] != '\0') {
                                out_soname = soname;
                            }
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // Look for SHT_DYNSYM (11) and its associated SHT_STRTAB
        for (const auto &sym_sec : shdrs) {
            if (sym_sec.sh_type == 11) {
                if (sym_sec.sh_link >= shdrs.size())
                    continue;
                const auto &str_sec = shdrs[sym_sec.sh_link];

                if (sym_sec.sh_entsize != sizeof(ElfSym) || sym_sec.sh_size == 0 || str_sec.sh_size == 0) {
                    continue;
                }
                const size_t num_symbols = sym_sec.sh_size / sym_sec.sh_entsize;

                std::vector<char> strtab(str_sec.sh_size);
                file.seekg(static_cast<std::streamoff>(str_sec.sh_offset), std::ios::beg);
                if (!file.read(strtab.data(), static_cast<std::streamsize>(str_sec.sh_size)))
                    continue;

                std::vector<ElfSym> syms(num_symbols);
                file.seekg(static_cast<std::streamoff>(sym_sec.sh_offset), std::ios::beg);
                if (!file.read(reinterpret_cast<char *>(syms.data()),
                               static_cast<std::streamsize>(num_symbols * sizeof(ElfSym)))) {
                    continue;
                }

                for (const auto &sym : syms) {
                    const uint8_t bind = sym.st_info >> 4;
                    if ((bind == 1 || bind == 2) && sym.st_shndx != 0 && sym.st_name < strtab.size()) {
                        const char *name = &strtab[sym.st_name];
                        if (name[0] != '\0') {
                            out_symbols.emplace_back(name);
                        }
                    }
                }
                break;
            }
        }

        if (out_soname.empty()) {
            out_soname = fs::path(file_path).filename().string();
        }
        return !out_symbols.empty();
    }

    bool parseElfExports(const std::string &file_path, std::vector<std::string> &out_symbols, std::string &out_soname) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        uint8_t ident[16]{};
        if (!file.read(reinterpret_cast<char *>(ident), sizeof(ident))) {
            return false;
        }

        // Check ELF magic: 0x7F, 'E', 'L', 'F'
        if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
            return false;
        }

        if (ident[4] == 2) {
            return parseElfExportsImpl<Elf64_Hdr, Elf64_Shdr, Elf64_Sym, Elf64_Dyn>(file, file_path, out_symbols,
                                                                                    out_soname);
        }
        if (ident[4] == 1) {
            return parseElfExportsImpl<Elf32_Hdr, Elf32_Shdr, Elf32_Sym, Elf32_Dyn>(file, file_path, out_symbols,
                                                                                    out_soname);
        }
        return false;
    }

    // =========================================================================
    // Native PE/COFF Export Parser (Windows .dll / .exe)
    // =========================================================================

#pragma pack(push, 1)
    struct IMAGE_DOS_HEADER {
        uint16_t e_magic;
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        uint16_t e_res[4];
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        uint16_t e_res2[10];
        int32_t e_lfanew;
    };

    struct IMAGE_SECTION_HEADER {
        uint8_t Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    };

    struct IMAGE_EXPORT_DIRECTORY {
        uint32_t Characteristics;
        uint32_t TimeDateStamp;
        uint16_t MajorVersion;
        uint16_t MinorVersion;
        uint32_t Name;
        uint32_t Base;
        uint32_t NumberOfFunctions;
        uint32_t NumberOfNames;
        uint32_t AddressOfFunctions;
        uint32_t AddressOfNames;
        uint32_t AddressOfNameOrdinals;
    };
#pragma pack(pop)

    static uint32_t rvaToOffset(uint32_t rva, const std::vector<IMAGE_SECTION_HEADER> &sections) {
        for (const auto &sec : sections) {
            const uint32_t span = std::max(sec.VirtualSize, sec.SizeOfRawData);
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + span) {
                const uint32_t delta = rva - sec.VirtualAddress;
                if (delta < sec.SizeOfRawData) {
                    return sec.PointerToRawData + delta;
                }
            }
        }
        return 0;
    }

    bool parsePeExports(const std::string &file_path, std::vector<std::string> &out_symbols, std::string &out_dllname) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        IMAGE_DOS_HEADER dos{};
        if (!file.read(reinterpret_cast<char *>(&dos), sizeof(dos))) {
            return false;
        }
        if (dos.e_magic != 0x5A4D || dos.e_lfanew <= 0) {
            return false;
        }

        file.seekg(dos.e_lfanew, std::ios::beg);
        uint32_t pe_sig = 0;
        if (!file.read(reinterpret_cast<char *>(&pe_sig), sizeof(pe_sig)) || pe_sig != 0x00004550) {
            return false;
        }

        uint16_t num_sections = 0;
        file.seekg(dos.e_lfanew + 4 + 2, std::ios::beg);
        file.read(reinterpret_cast<char *>(&num_sections), sizeof(num_sections));

        uint16_t size_of_opt_hdr = 0;
        file.seekg(dos.e_lfanew + 4 + 16, std::ios::beg);
        file.read(reinterpret_cast<char *>(&size_of_opt_hdr), sizeof(size_of_opt_hdr));

        if (size_of_opt_hdr == 0 || num_sections == 0)
            return false;

        const uint32_t opt_hdr_pos = static_cast<uint32_t>(dos.e_lfanew) + 4 + 20;
        file.seekg(opt_hdr_pos, std::ios::beg);
        uint16_t opt_magic = 0;
        file.read(reinterpret_cast<char *>(&opt_magic), sizeof(opt_magic));

        uint32_t export_dir_rva = 0;
        uint32_t export_dir_size = 0;

        if (opt_magic == 0x20B) {
            file.seekg(opt_hdr_pos + 112, std::ios::beg);
        } else if (opt_magic == 0x10B) {
            file.seekg(opt_hdr_pos + 96, std::ios::beg);
        } else {
            return false;
        }
        file.read(reinterpret_cast<char *>(&export_dir_rva), sizeof(export_dir_rva));
        file.read(reinterpret_cast<char *>(&export_dir_size), sizeof(export_dir_size));

        if (export_dir_rva == 0 || export_dir_size == 0) {
            return false;
        }

        const uint32_t sec_hdr_pos = opt_hdr_pos + size_of_opt_hdr;
        file.seekg(sec_hdr_pos, std::ios::beg);
        std::vector<IMAGE_SECTION_HEADER> sections(num_sections);
        if (!file.read(reinterpret_cast<char *>(sections.data()),
                       static_cast<std::streamsize>(num_sections) * sizeof(IMAGE_SECTION_HEADER))) {
            return false;
        }

        const uint32_t export_file_offset = rvaToOffset(export_dir_rva, sections);
        if (export_file_offset == 0)
            return false;

        file.seekg(export_file_offset, std::ios::beg);
        IMAGE_EXPORT_DIRECTORY exp{};
        if (!file.read(reinterpret_cast<char *>(&exp), sizeof(exp))) {
            return false;
        }

        if (exp.Name != 0) {
            const uint32_t name_offset = rvaToOffset(exp.Name, sections);
            if (name_offset != 0) {
                file.seekg(name_offset, std::ios::beg);
                char c;
                while (file.get(c) && c != '\0' && out_dllname.size() < 256) {
                    out_dllname.push_back(c);
                }
            }
        }

        const uint32_t names_offset = rvaToOffset(exp.AddressOfNames, sections);
        if (names_offset == 0 || exp.NumberOfNames == 0) {
            return false;
        }

        file.seekg(names_offset, std::ios::beg);
        std::vector<uint32_t> name_rvas(exp.NumberOfNames);
        if (!file.read(reinterpret_cast<char *>(name_rvas.data()),
                       static_cast<std::streamsize>(exp.NumberOfNames) * sizeof(uint32_t))) {
            return false;
        }

        for (uint32_t rva : name_rvas) {
            const uint32_t str_offset = rvaToOffset(rva, sections);
            if (str_offset != 0) {
                file.seekg(str_offset, std::ios::beg);
                std::string func_name;
                char c;
                while (file.get(c) && c != '\0' && func_name.size() < 512) {
                    func_name.push_back(c);
                }
                if (!func_name.empty()) {
                    out_symbols.push_back(std::move(func_name));
                }
            }
        }

        return !out_symbols.empty();
    }

    // =========================================================================
    // Native COFF Import Library Parser (Windows .lib / .dll.a)
    // =========================================================================

#pragma pack(push, 1)
    struct ArchiveMemberHeader {
        char Name[16];
        char Date[12];
        char UserID[6];
        char GroupID[6];
        char Mode[8];
        char Size[10];
        char EndHeader[2];
    };

    struct CoffShortImportHeader {
        uint16_t Sig1; // 0x0000 (IMAGE_FILE_MACHINE_UNKNOWN)
        uint16_t Sig2; // 0xFFFF (IMPORT_OBJECT_HDR_SIG2)
        uint16_t Version;
        uint16_t Machine;
        uint32_t TimeDateStamp;
        uint32_t SizeOfData;
        uint16_t OrdinalOrHint;
        uint16_t TypeInfo; // bits 0..1: ImportType, bits 2..4: NameType
    };
#pragma pack(pop)

    static std::string normalizeCoffImportName(std::string_view raw, uint16_t name_type) {
        if (raw.empty())
            return {};
        // 1 = IMPORT_NAME, 2 = IMPORT_NAME_NOPREFIX, 3 = IMPORT_NAME_UNDECORATE
        if (name_type == 2 || name_type == 3) {
            if (raw.front() == '_' || raw.front() == '@' || raw.front() == '?') {
                raw.remove_prefix(1);
            }
            if (name_type == 3) {
                const size_t at = raw.rfind('@');
                if (at != std::string_view::npos && at + 1 < raw.size()) {
                    bool all_digits = true;
                    for (size_t i = at + 1; i < raw.size(); ++i) {
                        if (!std::isdigit(static_cast<unsigned char>(raw[i]))) {
                            all_digits = false;
                            break;
                        }
                    }
                    if (all_digits) {
                        raw = raw.substr(0, at);
                    }
                }
            }
        }
        return std::string(raw);
    }

    bool parseCoffImportLib(const std::string &file_path,
                            std::vector<std::pair<std::string, std::string>> &out_symbol_dlls) {
        std::ifstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        char magic[8]{};
        if (!file.read(magic, sizeof(magic)) || std::memcmp(magic, "!<arch>\n", 8) != 0) {
            return false;
        }

        ArchiveMemberHeader hdr{};
        while (file.read(reinterpret_cast<char *>(&hdr), sizeof(hdr))) {
            if (hdr.EndHeader[0] != '`' || hdr.EndHeader[1] != '\n') {
                break;
            }

            size_t member_size = 0;
            for (char ch : hdr.Size) {
                if (ch >= '0' && ch <= '9') {
                    member_size = member_size * 10 + static_cast<size_t>(ch - '0');
                }
            }

            const std::streampos member_start = file.tellg();
            const bool is_special = (hdr.Name[0] == '/' && (hdr.Name[1] == ' ' || hdr.Name[1] == '/'));

            if (!is_special && member_size >= sizeof(CoffShortImportHeader)) {
                CoffShortImportHeader imp{};
                if (file.read(reinterpret_cast<char *>(&imp), sizeof(imp)) && imp.Sig1 == 0x0000 &&
                    imp.Sig2 == 0xFFFF) {
                    const size_t payload_size = member_size - sizeof(CoffShortImportHeader);
                    if (payload_size > 0 && payload_size <= 4096) {
                        std::string payload(payload_size, '\0');
                        if (file.read(payload.data(), static_cast<std::streamsize>(payload_size))) {
                            const size_t first_nul = payload.find('\0');
                            if (first_nul != std::string::npos && first_nul + 1 < payload.size()) {
                                const std::string_view raw_sym(payload.data(), first_nul);
                                const size_t second_nul = payload.find('\0', first_nul + 1);
                                const std::string_view dll_name =
                                    (second_nul != std::string::npos)
                                        ? std::string_view(payload.data() + first_nul + 1, second_nul - (first_nul + 1))
                                        : std::string_view(payload.data() + first_nul + 1);

                                const uint16_t name_type = (imp.TypeInfo >> 2) & 0x7;
                                std::string sym = normalizeCoffImportName(raw_sym, name_type);
                                if (!sym.empty()) {
                                    out_symbol_dlls.emplace_back(std::move(sym), std::string(dll_name));
                                }
                            }
                        }
                    }
                }
            }

            const size_t padded_size = (member_size + 1) & ~size_t(1);
            file.clear();
            file.seekg(member_start + static_cast<std::streamoff>(padded_size), std::ios::beg);
        }

        return !out_symbol_dlls.empty();
    }

} // namespace traceql
