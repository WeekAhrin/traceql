#include "tools/traceql/analysis/dataset_loader.h"
#include "tools/traceql/patterns/behavior_rule_emitter.h"
#include "tools/traceql/patterns/call_pattern.h"
#include "tools/traceql/plugin/ast_visitor.h"
#include "tools/traceql/symbols/binary_symbol_parser.h"

#if CLANG_PLUGIN_AVAILABLE
#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#if __has_include("llvm/TargetParser/Triple.h")
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#endif

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace traceql {

#if CLANG_PLUGIN_AVAILABLE

    namespace {

        struct PluginOptions {
            bool auto_scan{true};
            std::string emit_patterns_path;
            std::string emit_behavior_rules_path;
            std::string behavior_format{"json"};
            bool behavior_format_explicit{false};
            uint32_t risk_threshold{40};
            double entropy_threshold{6.8};
            std::string target_os{"auto"};
            bool strict_behavior_warn{false};
            std::vector<std::string> dataset_paths;
        };

        bool endsWithInsensitive(std::string_view text, std::string_view suffix) {
            if (text.size() < suffix.size()) {
                return false;
            }
            const std::string_view tail = text.substr(text.size() - suffix.size());
            for (size_t i = 0; i < suffix.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(tail[i])) !=
                    std::tolower(static_cast<unsigned char>(suffix[i]))) {
                    return false;
                }
            }
            return true;
        }

        std::string toLowerAscii(std::string_view text) {
            std::string out;
            out.reserve(text.size());
            for (const unsigned char ch : text) {
                out.push_back(static_cast<char>(std::tolower(ch)));
            }
            return out;
        }

        bool writePatternsWithSummaries(const std::string &path, const CallPatternCollector &collector,
                                        const FunctionSummaryTable &summary_table) {
            nlohmann::json doc = nlohmann::json::parse(collector.toJson(), nullptr, false);
            if (doc.is_discarded() || !doc.is_object()) {
                return collector.writeJsonFile(path);
            }

            std::vector<std::string> func_names;
            func_names.reserve(summary_table.size());
            for (const auto &[name, _] : summary_table.entries()) {
                func_names.push_back(name);
            }
            std::sort(func_names.begin(), func_names.end());

            nlohmann::json summaries_arr = nlohmann::json::array();
            for (const std::string &fn : func_names) {
                const FunctionTaintSummary *s = summary_table.findSummary(fn);
                if (!s)
                    continue;
                nlohmann::json p2p = nlohmann::json::array();
                for (const auto &pair : s->param_to_param) {
                    p2p.push_back(nlohmann::json::array({pair.first, pair.second}));
                }
                summaries_arr.push_back({
                    {"function", fn},
                    {"return_taint_mask", s->return_taint_mask},
                    {"origin_symbol", s->origin_symbol},
                    {"param_sinks", s->param_sinks},
                    {"param_to_return", s->param_to_return},
                    {"param_to_param", std::move(p2p)},
                });
            }
            doc["taint_summaries"] = std::move(summaries_arr);

            std::ofstream out(path);
            if (!out.is_open()) {
                return false;
            }
            out << doc.dump(2) << '\n';
            return out.good();
        }

    } // namespace

    class RuntimeDependencyConsumer final : public clang::ASTConsumer {
      public:
        RuntimeDependencyConsumer(clang::CompilerInstance &CI, PluginOptions options)
            : CI_(CI), options_(std::move(options)),
              diag_id_(CI.getDiagnostics().getCustomDiagID(clang::DiagnosticsEngine::Warning,
                                                           "detected external runtime dependency '%0' (%1) target: "
                                                           "[%2] library: [%3] category: [%4] defined in: [%5] (%6)")),
              behavior_diag_id_(CI.getDiagnostics().getCustomDiagID(
                  clang::DiagnosticsEngine::Warning,
                  "Behavioral risk finding [%0] (severity=%1, risk=%2) in '%3': %4")) {
            const auto &triple = CI.getTarget().getTriple();
            if (triple.isAndroid()) {
                platform_ = TargetPlatform::Android_Bionic;
            } else if (triple.isOSWindows()) {
                platform_ = TargetPlatform::Windows_MSVC_UCRT;
            } else if (triple.isOSLinux()) {
                platform_ = TargetPlatform::Linux_Glibc;
            } else if (triple.isMacOSX()) {
                platform_ = TargetPlatform::Apple_Darwin;
            } else {
                platform_ = TargetPlatform::Auto;
            }
        }

        void HandleTranslationUnit(clang::ASTContext &ctx) override {
            CallPatternCollector collector;
            RuntimeDependencyVisitor visitor(CI_, diag_id_, platform_, &collector);
            visitor.TraverseDecl(ctx.getTranslationUnitDecl());

            if (!options_.emit_patterns_path.empty()) {
                writePatternsWithSummaries(options_.emit_patterns_path, collector, visitor.summaryTable());
            }

            if (!options_.emit_behavior_rules_path.empty() || options_.strict_behavior_warn) {
                std::vector<BehaviorCallObservation> behavior_calls;
                behavior_calls.reserve(collector.records().size());
                for (const auto &rec : collector.records()) {
                    BehaviorCallObservation obs;
                    obs.caller = rec.caller_function;
                    obs.symbol = rec.symbol;
                    obs.library = rec.library;
                    obs.kind = rec.kind;
                    obs.pattern = rec.formatCanonicalPattern();
                    obs.behavior_category = rec.behavior_category;
                    obs.behavior_tags = rec.behavior_tags;
                    obs.arg_literals = rec.arg_literals;
                    obs.risk_score = rec.risk_score;
                    obs.arg_entropy = rec.arg_entropy;
                    obs.has_high_entropy_literal = rec.has_high_entropy_literal;
                    obs.is_indirect_call = rec.is_indirect_call;
                    obs.is_inline_asm = rec.is_inline_asm;
                    obs.resolved_from_symbol = rec.resolved_from_symbol;
                    obs.file = rec.source_file;
                    obs.line = rec.line;
                    obs.column = rec.column;
                    obs.is_auto_init_entrypoint = rec.is_auto_init_entrypoint;
                    obs.entrypoint_kind = rec.entrypoint_kind;
                    if constexpr (requires {
                                      obs.lock_name;
                                      rec.lock_name;
                                  }) {
                        obs.lock_name = rec.lock_name;
                    }
                    if constexpr (requires {
                                      obs.lock_held_prev;
                                      rec.lock_held_prev;
                                  }) {
                        obs.lock_held_prev = rec.lock_held_prev;
                    }
                    if constexpr (requires {
                                      obs.lifetime_kind;
                                      rec.lifetime_kind;
                                  }) {
                        obs.lifetime_kind = rec.lifetime_kind;
                    }
                    behavior_calls.push_back(std::move(obs));
                }

                const auto sequences = collector.buildSequences();
                std::vector<BehaviorSequenceObservation> behavior_sequences;
                behavior_sequences.reserve(sequences.size());
                for (const auto &seq : sequences) {
                    BehaviorSequenceObservation sobs;
                    sobs.caller = seq.caller_function;
                    sobs.chain = seq.call_patterns;
                    sobs.behavior_chain_tags = seq.detected_chains;
                    sobs.sequence_entropy = seq.sequence_entropy;
                    sobs.max_arg_entropy = seq.max_arg_entropy;
                    sobs.caller_risk_score = seq.caller_risk_score;
                    sobs.is_auto_init_entrypoint = seq.is_auto_init_entrypoint;
                    sobs.entrypoint_kind = seq.entrypoint_kind;
                    behavior_sequences.push_back(std::move(sobs));
                }

                DatasetLoader dataset_loader;
                for (const auto &ds_path : options_.dataset_paths) {
                    std::error_code ec;
                    if (std::filesystem::is_directory(ds_path, ec)) {
                        dataset_loader.loadDirectory(ds_path);
                    } else {
                        dataset_loader.loadFile(ds_path);
                    }
                }

                const auto findings = BehaviorRuleEmitter::analyzeFindings(
                    behavior_calls, behavior_sequences, options_.target_os, options_.risk_threshold,
                    options_.entropy_threshold, options_.dataset_paths.empty() ? nullptr : &dataset_loader);

                if (!options_.emit_behavior_rules_path.empty()) {
                    BehaviorRuleFormat format = BehaviorRuleFormat::Json;
                    if (options_.behavior_format == "sigma") {
                        format = BehaviorRuleFormat::SigmaYaml;
                    } else if (options_.behavior_format == "sarif") {
                        format = BehaviorRuleFormat::Sarif;
                    } else if (!options_.behavior_format_explicit) {
                        if (endsWithInsensitive(options_.emit_behavior_rules_path, ".yml") ||
                            endsWithInsensitive(options_.emit_behavior_rules_path, ".yaml")) {
                            format = BehaviorRuleFormat::SigmaYaml;
                        } else if (endsWithInsensitive(options_.emit_behavior_rules_path, ".sarif") ||
                                   endsWithInsensitive(options_.emit_behavior_rules_path, ".sarif.json")) {
                            format = BehaviorRuleFormat::Sarif;
                        }
                    }
                    BehaviorRuleEmitter::writeRulesFile(options_.emit_behavior_rules_path, findings, options_.target_os,
                                                        format);
                }

                if (options_.strict_behavior_warn) {
                    auto &diags = CI_.getDiagnostics();
                    for (const auto &finding : findings) {
                        if (finding.risk_score >= options_.risk_threshold) {
                            diags.Report(behavior_diag_id_)
                                << finding.rule_id << finding.severity << finding.risk_score
                                << (finding.caller.empty() ? std::string("<global>") : finding.caller) << finding.title;
                        }
                    }
                }
            }
        }

      private:
        clang::CompilerInstance &CI_;
        PluginOptions options_;
        unsigned diag_id_{0};
        unsigned behavior_diag_id_{0};
        TargetPlatform platform_{TargetPlatform::Auto};
    };

    class RuntimeDetectorAction final : public clang::PluginASTAction {
      protected:
        std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance &CI, llvm::StringRef) override {
            if (options_.auto_scan && DynamicSymbolRegistry::instance().totalSymbolCount() == 0) {
                DynamicSymbolRegistry::instance().scanDefaultSystemDirs();
            }
            return std::make_unique<RuntimeDependencyConsumer>(CI, options_);
        }

        bool ParseArgs(const clang::CompilerInstance &, const std::vector<std::string> &args) override {
            for (const auto &arg : args) {
                if (arg.rfind("--scan-lib=", 0) == 0) {
                    DynamicSymbolRegistry::instance().loadLibrary(arg.substr(11));
                } else if (arg.rfind("--scan-dir=", 0) == 0) {
                    DynamicSymbolRegistry::instance().scanDirectory(arg.substr(11));
                } else if (arg.rfind("--emit-patterns=", 0) == 0) {
                    options_.emit_patterns_path = arg.substr(16);
                } else if (arg == "--no-auto-scan") {
                    options_.auto_scan = false;
                } else if (arg.rfind("--emit-behavior-rules=", 0) == 0) {
                    options_.emit_behavior_rules_path = arg.substr(22);
                } else if (arg.rfind("--behavior-format=", 0) == 0) {
                    const std::string fmt = toLowerAscii(arg.substr(18));
                    if (fmt == "sigma" || fmt == "yaml") {
                        options_.behavior_format = "sigma";
                    } else if (fmt == "sarif") {
                        options_.behavior_format = "sarif";
                    } else {
                        options_.behavior_format = "json";
                    }
                    options_.behavior_format_explicit = true;
                } else if (arg.rfind("--risk-threshold=", 0) == 0) {
                    const std::string val = arg.substr(17);
                    char *end = nullptr;
                    const unsigned long parsed = std::strtoul(val.c_str(), &end, 10);
                    if (end != val.c_str()) {
                        options_.risk_threshold = static_cast<uint32_t>(parsed);
                    }
                } else if (arg.rfind("--entropy-threshold=", 0) == 0) {
                    const std::string val = arg.substr(20);
                    char *end = nullptr;
                    const double parsed = std::strtod(val.c_str(), &end);
                    if (end != val.c_str()) {
                        options_.entropy_threshold = parsed;
                    }
                } else if (arg.rfind("--target-os=", 0) == 0) {
                    options_.target_os = toLowerAscii(arg.substr(12));
                } else if (arg == "--strict-behavior-warn") {
                    options_.strict_behavior_warn = true;
                } else if (arg.rfind("--load-dataset=", 0) == 0) {
                    options_.dataset_paths.push_back(arg.substr(15));
                } else if (arg.rfind("--load-rules=", 0) == 0) {
                    options_.dataset_paths.push_back(arg.substr(13));
                }
            }
            return true;
        }

        ActionType getActionType() override {
            return CmdlineBeforeMainAction;
        }

      private:
        PluginOptions options_;
    };

    static clang::FrontendPluginRegistry::Add<RuntimeDetectorAction>
        X("traceql", "TraceQL: Detects external runtime, OS, ABI, and behavioral patterns from Clang AST");

#endif // CLANG_PLUGIN_AVAILABLE

} // namespace traceql
