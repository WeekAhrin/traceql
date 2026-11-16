#include "aggregator/project_aggregator.h"

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

    bool endsWithInsensitive(std::string_view text, std::string_view suffix) {
        if (text.size() < suffix.size()) {
            return false;
        }
        const size_t offset = text.size() - suffix.size();
        for (size_t i = 0; i < suffix.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(text[offset + i])) !=
                std::tolower(static_cast<unsigned char>(suffix[i]))) {
                return false;
            }
        }
        return true;
    }

    void printUsage(const char *argv0) {
        std::cerr << "Usage: " << argv0 << " [options] <pattern.json | dir>...\n"
                  << "Options:\n"
                  << "  --emit-patterns=<out.json>             Write merged cross-TU patterns JSON\n"
                  << "  --emit-behavior-rules=<out.{json,yml,sarif}>\n"
                  << "                                         Write cross-TU behavior rules/findings\n"
                  << "  --emit-mermaid=<out.mmd>               Write Mermaid call/taint/lock flowchart\n"
                  << "  --emit-dot=<out.dot>                   Write Graphviz DOT call/taint/lock graph\n"
                  << "  --behavior-format=<json|sigma|sarif>   Override behavior rules output format\n"
                  << "  --load-dataset=<path>                  Load external dataset file or directory\n"
                  << "  --target-os=<auto|windows|linux|android>\n"
                  << "                                         Target OS for behavior analysis (default: auto)\n"
                  << "  --risk-threshold=<N>                   Minimum risk score threshold (default: 40)\n"
                  << "  --entropy-threshold=<F>                Entropy threshold (default: 6.8)\n"
                  << "  -h, --help                             Show this help message\n";
    }

} // namespace

int main(int argc, char **argv) {
    using namespace traceql;

    std::vector<std::string> input_paths;
    std::vector<std::string> dataset_paths;
    std::string emit_patterns_path;
    std::string emit_behavior_rules_path;
    std::string emit_mermaid_path;
    std::string emit_dot_path;
    std::string behavior_format;
    bool behavior_format_explicit = false;
    std::string target_os = "auto";
    uint32_t risk_threshold = 40;
    double entropy_threshold = 6.8;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
        if (arg.starts_with("--emit-patterns=")) {
            emit_patterns_path = std::string(arg.substr(16));
        } else if (arg.starts_with("--emit-behavior-rules=")) {
            emit_behavior_rules_path = std::string(arg.substr(22));
        } else if (arg.starts_with("--emit-mermaid=")) {
            emit_mermaid_path = std::string(arg.substr(15));
        } else if (arg.starts_with("--emit-dot=")) {
            emit_dot_path = std::string(arg.substr(11));
        } else if (arg.starts_with("--behavior-format=")) {
            behavior_format = std::string(arg.substr(18));
            behavior_format_explicit = true;
            if (behavior_format != "json" && behavior_format != "sigma" && behavior_format != "sarif") {
                std::cerr << "Invalid --behavior-format: " << behavior_format << "\n";
                return 1;
            }
        } else if (arg.starts_with("--load-dataset=")) {
            dataset_paths.emplace_back(arg.substr(15));
        } else if (arg.starts_with("--target-os=")) {
            target_os = std::string(arg.substr(12));
        } else if (arg.starts_with("--risk-threshold=")) {
            const std::string val(arg.substr(17));
            char *end_ptr = nullptr;
            const unsigned long parsed = std::strtoul(val.c_str(), &end_ptr, 10);
            if (val.empty() || end_ptr == val.c_str() || *end_ptr != '\0') {
                std::cerr << "Invalid --risk-threshold: " << val << "\n";
                return 1;
            }
            risk_threshold = static_cast<uint32_t>(parsed);
        } else if (arg.starts_with("--entropy-threshold=")) {
            const std::string val(arg.substr(20));
            char *end_ptr = nullptr;
            const double parsed = std::strtod(val.c_str(), &end_ptr);
            if (val.empty() || end_ptr == val.c_str() || *end_ptr != '\0') {
                std::cerr << "Invalid --entropy-threshold: " << val << "\n";
                return 1;
            }
            entropy_threshold = parsed;
        } else if (arg.starts_with("-")) {
            std::cerr << "Unknown option: " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        } else {
            input_paths.emplace_back(arg);
        }
    }

    if (input_paths.empty()) {
        std::cerr << "Error: at least one input .json file or directory is required.\n";
        printUsage(argv[0]);
        return 1;
    }

    ProjectAggregator aggregator;
    size_t loaded_files = 0;

    for (const auto &path : input_paths) {
        std::error_code ec;
        if (std::filesystem::is_directory(path, ec)) {
            loaded_files += aggregator.loadPatternJsonDirectory(path);
        } else {
            if (!aggregator.loadPatternJsonFile(path)) {
                std::cerr << "Warning: failed to load pattern JSON file: " << path << "\n";
            } else {
                ++loaded_files;
            }
        }
    }

    if (loaded_files == 0) {
        std::cerr << "Error: no valid pattern JSON files were loaded.\n";
        return 1;
    }

    if (!emit_patterns_path.empty()) {
        std::ofstream out(emit_patterns_path);
        if (!out.is_open()) {
            std::cerr << "Error: unable to open output file: " << emit_patterns_path << "\n";
            return 1;
        }
        out << aggregator.toMergedPatternsJson();
        if (!out.good()) {
            std::cerr << "Error: failed writing merged patterns JSON to: " << emit_patterns_path << "\n";
            return 1;
        }
    }

    if (!emit_mermaid_path.empty()) {
        std::ofstream out(emit_mermaid_path);
        if (!out.is_open()) {
            std::cerr << "Error: unable to open output file: " << emit_mermaid_path << "\n";
            return 1;
        }
        out << aggregator.toMermaidFlowchart();
        if (!out.good()) {
            std::cerr << "Error: failed writing Mermaid flowchart to: " << emit_mermaid_path << "\n";
            return 1;
        }
    }

    if (!emit_dot_path.empty()) {
        std::ofstream out(emit_dot_path);
        if (!out.is_open()) {
            std::cerr << "Error: unable to open output file: " << emit_dot_path << "\n";
            return 1;
        }
        out << aggregator.toGraphvizDot();
        if (!out.good()) {
            std::cerr << "Error: failed writing Graphviz DOT to: " << emit_dot_path << "\n";
            return 1;
        }
    }

    DatasetLoader dataset_loader;
    for (const auto &ds_path : dataset_paths) {
        std::error_code ec;
        if (std::filesystem::is_directory(ds_path, ec)) {
            dataset_loader.loadDirectory(ds_path);
        } else {
            dataset_loader.loadFile(ds_path);
        }
    }

    const std::vector<BehaviorFinding> findings = aggregator.analyzeProjectFindings(
        target_os, risk_threshold, entropy_threshold, dataset_paths.empty() ? nullptr : &dataset_loader);

    if (!emit_behavior_rules_path.empty()) {
        BehaviorRuleFormat format = BehaviorRuleFormat::Json;
        if (behavior_format == "sigma") {
            format = BehaviorRuleFormat::SigmaYaml;
        } else if (behavior_format == "sarif") {
            format = BehaviorRuleFormat::Sarif;
        } else if (!behavior_format_explicit) {
            if (endsWithInsensitive(emit_behavior_rules_path, ".yml") ||
                endsWithInsensitive(emit_behavior_rules_path, ".yaml")) {
                format = BehaviorRuleFormat::SigmaYaml;
            } else if (endsWithInsensitive(emit_behavior_rules_path, ".sarif") ||
                       endsWithInsensitive(emit_behavior_rules_path, ".sarif.json")) {
                format = BehaviorRuleFormat::Sarif;
            }
        }

        if (!BehaviorRuleEmitter::writeRulesFile(emit_behavior_rules_path, findings, target_os, format)) {
            std::cerr << "Error: failed writing behavior rules to: " << emit_behavior_rules_path << "\n";
            return 1;
        }
    }

    std::cout << "Merged " << loaded_files << " pattern file(s), " << aggregator.rawRecords().size() << " call(s), "
              << findings.size() << " finding(s).\n";
    return 0;
}
