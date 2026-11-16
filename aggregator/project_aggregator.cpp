#include "aggregator/project_aggregator.h"

#include "analysis/lock_analyzer.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace traceql {

    namespace {

        std::string_view trimView(std::string_view sv) {
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) {
                sv.remove_prefix(1);
            }
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) {
                sv.remove_suffix(1);
            }
            return sv;
        }

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

        bool isPseudoCaller(std::string_view caller) {
            return caller.empty() || caller == "<global>" || caller == "<unknown>";
        }

        std::vector<std::string> splitTopLevelComma(std::string_view inner) {
            std::vector<std::string> items;
            inner = trimView(inner);
            if (inner.empty()) {
                return items;
            }

            int paren_depth = 0;
            int angle_depth = 0;
            int bracket_depth = 0;
            size_t start = 0;

            for (size_t i = 0; i < inner.size(); ++i) {
                const char c = inner[i];
                if (c == '(') {
                    ++paren_depth;
                } else if (c == ')' && paren_depth > 0) {
                    --paren_depth;
                } else if (c == '<') {
                    ++angle_depth;
                } else if (c == '>' && angle_depth > 0) {
                    --angle_depth;
                } else if (c == '[') {
                    ++bracket_depth;
                } else if (c == ']' && bracket_depth > 0) {
                    --bracket_depth;
                } else if (c == ',' && paren_depth == 0 && angle_depth == 0 && bracket_depth == 0) {
                    const std::string_view part = trimView(inner.substr(start, i - start));
                    if (!part.empty()) {
                        items.emplace_back(part);
                    }
                    start = i + 1;
                }
            }

            const std::string_view tail = trimView(inner.substr(start));
            if (!tail.empty()) {
                items.emplace_back(tail);
            }
            return items;
        }

        void populateFromSignature(std::string_view signature, CallPatternRecord &rec) {
            signature = trimView(signature);
            if (signature.empty() || signature.back() != ')') {
                return;
            }

            int depth = 0;
            size_t open_paren = std::string_view::npos;
            for (size_t i = signature.size(); i-- > 0;) {
                if (signature[i] == ')') {
                    ++depth;
                } else if (signature[i] == '(') {
                    --depth;
                    if (depth == 0) {
                        open_paren = i;
                        break;
                    }
                }
            }
            if (open_paren == std::string_view::npos) {
                return;
            }

            const std::string_view params_view = signature.substr(open_paren + 1, signature.size() - open_paren - 2);
            const std::vector<std::string> params = splitTopLevelComma(params_view);
            rec.param_types.clear();
            rec.is_variadic = false;
            for (const auto &p : params) {
                if (p == "...") {
                    rec.is_variadic = true;
                } else {
                    rec.param_types.push_back(p);
                }
            }

            const std::string_view prefix = trimView(signature.substr(0, open_paren));
            if (!rec.symbol.empty() && prefix.size() > rec.symbol.size() &&
                prefix.substr(prefix.size() - rec.symbol.size()) == rec.symbol) {
                const std::string_view ret = trimView(prefix.substr(0, prefix.size() - rec.symbol.size()));
                if (!ret.empty()) {
                    rec.return_type = std::string(ret);
                }
            }
        }

        void populateFromPattern(std::string_view pattern, CallPatternRecord &rec) {
            pattern = trimView(pattern);
            const size_t at_pos = pattern.rfind(" @ (");
            if (at_pos == std::string_view::npos || pattern.back() != ')') {
                return;
            }
            const std::string_view args_view = pattern.substr(at_pos + 4, pattern.size() - (at_pos + 4) - 1);
            rec.arg_shapes = splitTopLevelComma(args_view);
        }

        bool parseCallRecordFromJson(const nlohmann::json &obj, CallPatternRecord &rec) {
            if (!obj.is_object()) {
                return false;
            }
            auto strField = [&](const char *key, std::string &out) {
                if (obj.contains(key) && obj[key].is_string()) {
                    out = obj[key].get<std::string>();
                }
            };
            auto boolField = [&](const char *key, bool &out) {
                if (obj.contains(key) && obj[key].is_boolean()) {
                    out = obj[key].get<bool>();
                }
            };
            auto strArrayField = [&](const char *key, std::vector<std::string> &out) {
                if (obj.contains(key) && obj[key].is_array()) {
                    out.clear();
                    for (const auto &el : obj[key]) {
                        if (el.is_string()) {
                            out.push_back(el.get<std::string>());
                        }
                    }
                }
            };

            std::string signature;
            std::string pattern;
            strField("caller", rec.caller_function);
            strField("symbol", rec.symbol);
            strField("mangled_symbol", rec.mangled_symbol);
            strField("library", rec.library);
            strField("category", rec.category);
            strField("kind", rec.kind);
            strField("signature", signature);
            strField("pattern", pattern);
            boolField("all_args_constant", rec.all_args_constant);
            strArrayField("arg_literals", rec.arg_literals);
            strField("file", rec.source_file);
            if (obj.contains("line") && obj["line"].is_number_unsigned()) {
                rec.line = obj["line"].get<unsigned>();
            }
            if (obj.contains("column") && obj["column"].is_number_unsigned()) {
                rec.column = obj["column"].get<unsigned>();
            }
            strField("behavior_category", rec.behavior_category);
            strArrayField("behavior_tags", rec.behavior_tags);
            if (obj.contains("risk_score") && obj["risk_score"].is_number_unsigned()) {
                rec.risk_score = obj["risk_score"].get<uint32_t>();
            }
            if (obj.contains("arg_entropy") && obj["arg_entropy"].is_number()) {
                rec.arg_entropy = obj["arg_entropy"].get<double>();
            }
            boolField("has_high_entropy_literal", rec.has_high_entropy_literal);
            boolField("is_indirect_call", rec.is_indirect_call);
            boolField("is_inline_asm", rec.is_inline_asm);
            boolField("is_auto_init_entrypoint", rec.is_auto_init_entrypoint);
            strField("entrypoint_kind", rec.entrypoint_kind);
            boolField("is_intra_tu_call", rec.is_intra_tu_call);
            boolField("tainted_exec_flow", rec.tainted_exec_flow);
            strField("resolved_from_symbol", rec.resolved_from_symbol);
            strField("behavior_rationale", rec.behavior_rationale);
            strField("lock_name", rec.lock_name);
            strField("lock_held_prev", rec.lock_held_prev);
            strField("lifetime_kind", rec.lifetime_kind);

            if (!signature.empty()) {
                populateFromSignature(signature, rec);
            }
            if (!pattern.empty()) {
                populateFromPattern(pattern, rec);
            }
            return true;
        }

        bool parseTaintSummaryFromJson(const nlohmann::json &obj, std::string &func_name,
                                       FunctionTaintSummary &summary) {
            if (!obj.is_object()) {
                return false;
            }
            if (obj.contains("function") && obj["function"].is_string()) {
                func_name = obj["function"].get<std::string>();
            }
            if (obj.contains("return_taint_mask") && obj["return_taint_mask"].is_number_unsigned()) {
                summary.return_taint_mask = obj["return_taint_mask"].get<uint32_t>();
            }
            if (obj.contains("origin_symbol") && obj["origin_symbol"].is_string()) {
                summary.origin_symbol = obj["origin_symbol"].get<std::string>();
            }
            auto readUintArray = [&](const char *key, std::vector<uint32_t> &out) {
                if (obj.contains(key) && obj[key].is_array()) {
                    out.clear();
                    for (const auto &el : obj[key]) {
                        if (el.is_number_unsigned()) {
                            out.push_back(el.get<uint32_t>());
                        }
                    }
                }
            };
            readUintArray("param_sinks", summary.param_sinks);
            readUintArray("param_to_return", summary.param_to_return);
            if (obj.contains("param_to_param") && obj["param_to_param"].is_array()) {
                summary.param_to_param.clear();
                for (const auto &el : obj["param_to_param"]) {
                    if (el.is_array() && el.size() >= 2 && el[0].is_number_unsigned() && el[1].is_number_unsigned()) {
                        summary.param_to_param.emplace_back(el[0].get<uint32_t>(), el[1].get<uint32_t>());
                    }
                }
            }
            return true;
        }

        void appendUniqueTag(std::vector<std::string> &tags, std::string tag) {
            if (std::find(tags.begin(), tags.end(), tag) == tags.end()) {
                tags.push_back(std::move(tag));
            }
        }

        bool hasTag(const std::vector<std::string> &tags, std::string_view tag) {
            return std::find(tags.begin(), tags.end(), tag) != tags.end();
        }

        std::string escapeMermaidLabel(std::string_view text) {
            std::string out;
            out.reserve(text.size());
            for (const char c : text) {
                if (c == '"') {
                    out.push_back('\'');
                } else if (c == '\n' || c == '\r') {
                    out.push_back(' ');
                } else {
                    out.push_back(c);
                }
            }
            return out;
        }

        std::string escapeDotString(std::string_view text) {
            std::string out;
            out.reserve(text.size());
            for (const char c : text) {
                if (c == '"' || c == '\\') {
                    out.push_back('\\');
                }
                if (c == '\n' || c == '\r') {
                    out.push_back(' ');
                } else {
                    out.push_back(c);
                }
            }
            return out;
        }

        bool isDangerousSinkRecord(const CallPatternRecord &rec) {
            return rec.behavior_category == "MemoryProtection" || rec.behavior_category == "ProcessThreadOp" ||
                   rec.behavior_category == "DirectSyscall" || rec.behavior_category == "IndirectCall" ||
                   rec.behavior_category == "NetworkOrIPC" || rec.behavior_category == "FileOrRegistryIO" ||
                   rec.is_indirect_call || rec.is_inline_asm;
        }

    } // namespace

    bool ProjectAggregator::loadPatternJsonFile(const std::string &path) {
        std::ifstream in(path);
        if (!in.is_open()) {
            return false;
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        return loadPatternJsonContent(ss.str());
    }

    bool ProjectAggregator::loadPatternJsonContent(std::string_view json_content) {
        nlohmann::json doc = nlohmann::json::parse(json_content, nullptr, false);
        if (doc.is_discarded() || !doc.is_object()) {
            return false;
        }

        const bool found_calls = doc.contains("calls") && doc["calls"].is_array();
        const bool found_summaries = doc.contains("taint_summaries") && doc["taint_summaries"].is_array();
        if (!found_calls && !found_summaries) {
            return false;
        }

        std::vector<CallPatternRecord> parsed_records;
        if (found_calls) {
            for (const auto &item : doc["calls"]) {
                CallPatternRecord rec;
                if (!parseCallRecordFromJson(item, rec)) {
                    return false;
                }
                parsed_records.push_back(std::move(rec));
            }
        }

        std::vector<std::pair<std::string, FunctionTaintSummary>> parsed_summaries;
        if (found_summaries) {
            for (const auto &item : doc["taint_summaries"]) {
                std::string func_name;
                FunctionTaintSummary summary;
                if (!parseTaintSummaryFromJson(item, func_name, summary)) {
                    return false;
                }
                if (!func_name.empty()) {
                    parsed_summaries.emplace_back(std::move(func_name), std::move(summary));
                }
            }
        }

        records_.insert(records_.end(), std::make_move_iterator(parsed_records.begin()),
                        std::make_move_iterator(parsed_records.end()));
        for (auto &[func_name, summary] : parsed_summaries) {
            if (summary_table_.findSummary(func_name) == nullptr) {
                summary_names_.push_back(func_name);
            }
            summary_table_.recordSummary(std::move(func_name), std::move(summary));
        }
        return true;
    }

    size_t ProjectAggregator::loadPatternJsonDirectory(const std::string &dir_path) {
        std::error_code ec;
        if (!std::filesystem::exists(dir_path, ec) || !std::filesystem::is_directory(dir_path, ec)) {
            return 0;
        }

        std::vector<std::string> json_files;
        for (const auto &entry : std::filesystem::recursive_directory_iterator(dir_path, ec)) {
            if (ec) {
                break;
            }
            if (!entry.is_regular_file(ec)) {
                continue;
            }
            const std::string path_str = entry.path().string();
            if (endsWithInsensitive(path_str, ".json")) {
                json_files.push_back(path_str);
            }
        }

        std::sort(json_files.begin(), json_files.end());

        size_t loaded_count = 0;
        for (const auto &file_path : json_files) {
            if (loadPatternJsonFile(file_path)) {
                ++loaded_count;
            }
        }
        return loaded_count;
    }

    void ProjectAggregator::clear() noexcept {
        records_.clear();
        summary_table_.clear();
        summary_names_.clear();
    }

    CallPatternCollector ProjectAggregator::buildMergedCollector() const {
        return buildMergedCollectorImpl(nullptr);
    }

    CallPatternCollector ProjectAggregator::buildMergedCollectorImpl(const DatasetLoader *dataset) const {
        std::unordered_set<std::string> defined_callers;
        defined_callers.reserve(records_.size());

        std::unordered_set<std::string> ast_arg_literals;
        std::unordered_map<std::string, std::unordered_set<std::string>> ast_calls_by_caller;
        LockAnalyzer lock_analyzer;

        for (const auto &rec : records_) {
            if (!isPseudoCaller(rec.caller_function)) {
                defined_callers.insert(rec.caller_function);
            }

            if (!rec.kind.starts_with("ir_")) {
                for (const auto &lit : rec.arg_literals) {
                    ast_arg_literals.insert(lit);
                }
            }
            if ((rec.kind == "call" || rec.kind == "pointer_ref" || rec.kind == "intra_tu_call") &&
                !rec.caller_function.empty() && !rec.symbol.empty()) {
                ast_calls_by_caller[rec.caller_function].insert(rec.symbol);
            }

            if (!rec.lock_held_prev.empty() && !rec.lock_name.empty()) {
                LockOrderEdge edge;
                edge.first_lock = rec.lock_held_prev;
                edge.second_lock = rec.lock_name;
                edge.caller = rec.caller_function;
                edge.file = rec.source_file;
                edge.line = rec.line;
                lock_analyzer.recordEdge(std::move(edge));
            }
        }

        std::unordered_map<std::string, uint32_t> caller_taint_masks;
        constexpr uint32_t kExecSourceMask =
            static_cast<uint32_t>(TaintKind::MemoryAlloc) | static_cast<uint32_t>(TaintKind::DynamicResolve) |
            static_cast<uint32_t>(TaintKind::HighEntropyBlob) | static_cast<uint32_t>(TaintKind::StackString);

        CallPatternCollector collector;
        for (const auto &rec : records_) {
            CallPatternRecord merged_rec = rec;
            if (!merged_rec.symbol.empty() && defined_callers.find(merged_rec.symbol) != defined_callers.end()) {
                merged_rec.is_intra_tu_call = true;
            }

            // Differential AST vs -O2 IR analysis:
            // 1) ir_folded_string with literal absent from AST and matching DatasetLoader
            if (merged_rec.kind == "ir_folded_string" && dataset != nullptr && !merged_rec.arg_literals.empty()) {
                std::vector<std::string> delta_literals;
                for (const auto &lit : merged_rec.arg_literals) {
                    if (ast_arg_literals.find(lit) == ast_arg_literals.end()) {
                        delta_literals.push_back(lit);
                    }
                }
                if (!delta_literals.empty() && !dataset->matchIndicators(delta_literals).empty()) {
                    appendUniqueTag(merged_rec.behavior_tags, "ast_vs_ir_delta");
                    merged_rec.risk_score = std::max<uint32_t>(merged_rec.risk_score, 80u);
                }
            }

            // 2) ir_resolved_indirect_call not seen as a direct AST call in same caller
            if (merged_rec.kind == "ir_resolved_indirect_call" && merged_rec.risk_score >= 55 &&
                !merged_rec.symbol.empty()) {
                const auto caller_it = ast_calls_by_caller.find(merged_rec.caller_function);
                const bool seen_in_ast = caller_it != ast_calls_by_caller.end() &&
                                         caller_it->second.find(merged_rec.symbol) != caller_it->second.end();
                if (!seen_in_ast) {
                    appendUniqueTag(merged_rec.behavior_tags, "ast_vs_ir_delta");
                    merged_rec.risk_score = std::max<uint32_t>(merged_rec.risk_score, 80u);
                }
            }

            const FunctionTaintSummary *callee_summary =
                merged_rec.symbol.empty() ? nullptr : summary_table_.findSummary(merged_rec.symbol);
            const std::string &caller = merged_rec.caller_function;

            if (!isPseudoCaller(caller)) {
                uint32_t &caller_mask = caller_taint_masks[caller];

                const bool is_sink_callee = (callee_summary != nullptr && !callee_summary->param_sinks.empty()) ||
                                            isDangerousSinkRecord(merged_rec);

                if (caller_mask != 0 && is_sink_callee) {
                    if ((caller_mask & kExecSourceMask) != 0) {
                        merged_rec.tainted_exec_flow = true;
                    }
                    appendUniqueTag(merged_rec.behavior_tags, "cross_tu_taint_summary");
                    if (merged_rec.behavior_category.empty() || merged_rec.behavior_category == "Benign") {
                        merged_rec.behavior_category = "MemoryProtection";
                    }
                    merged_rec.risk_score = std::max<uint32_t>(merged_rec.risk_score, 65);
                }

                if (callee_summary != nullptr && callee_summary->return_taint_mask != 0) {
                    caller_mask |= callee_summary->return_taint_mask;
                } else if (merged_rec.behavior_category == "MemoryAllocation") {
                    caller_mask |= static_cast<uint32_t>(TaintKind::MemoryAlloc);
                } else if (merged_rec.behavior_category == "DynamicResolution") {
                    caller_mask |= static_cast<uint32_t>(TaintKind::DynamicResolve);
                }
            }

            collector.add(std::move(merged_rec));
        }

        // Cross-TU Lock-Order Inversion synthesis
        for (const auto &inv : lock_analyzer.detectInversions()) {
            CallPatternRecord inv_rec;
            inv_rec.kind = "lock_order_inversion";
            inv_rec.symbol = inv.lock_a + " <-> " + inv.lock_b;
            inv_rec.caller_function = inv.caller_ab + " / " + inv.caller_ba;
            inv_rec.source_file = inv.file_ab;
            inv_rec.lock_held_prev = inv.lock_a;
            inv_rec.lock_name = inv.lock_b;
            inv_rec.behavior_category = "ThreadSafety";
            inv_rec.behavior_tags.push_back("lock_order_inversion");
            inv_rec.risk_score = 75;
            collector.add(std::move(inv_rec));
        }

        return collector;
    }

    std::string ProjectAggregator::toMergedPatternsJson() const {
        std::string json = buildMergedCollector().toJson();
        if (summary_table_.size() == 0) {
            return json;
        }

        nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
        if (doc.is_discarded() || !doc.is_object()) {
            return json;
        }

        nlohmann::json summaries_arr = nlohmann::json::array();
        for (const auto &name : summary_names_) {
            const FunctionTaintSummary *s = summary_table_.findSummary(name);
            if (s == nullptr) {
                continue;
            }
            nlohmann::json p2p = nlohmann::json::array();
            for (const auto &pair : s->param_to_param) {
                p2p.push_back(nlohmann::json::array({pair.first, pair.second}));
            }
            summaries_arr.push_back({
                {"function", name},
                {"return_taint_mask", s->return_taint_mask},
                {"origin_symbol", s->origin_symbol},
                {"param_sinks", s->param_sinks},
                {"param_to_return", s->param_to_return},
                {"param_to_param", std::move(p2p)},
            });
        }
        doc["taint_summaries"] = std::move(summaries_arr);
        return doc.dump(2) + "\n";
    }

    std::string ProjectAggregator::toMermaidFlowchart() const {
        const CallPatternCollector collector = buildMergedCollector();
        static constexpr size_t kMaxEdges = 500;

        std::unordered_map<std::string, std::string> node_ids;
        auto getNodeId = [&](const std::string &name) -> std::string {
            auto [it, inserted] = node_ids.emplace(name, std::string{});
            if (inserted) {
                it->second = "n" + std::to_string(node_ids.size() - 1);
            }
            return it->second;
        };

        struct GraphEdge {
            std::string from;
            std::string to;
            bool tainted{false};
            bool is_lock{false};
        };
        std::vector<GraphEdge> edges;
        std::unordered_set<std::string> seen_edges;

        auto addEdge = [&](std::string from, std::string to, bool tainted, bool is_lock) {
            if (edges.size() >= kMaxEdges || from.empty() || to.empty()) {
                return;
            }
            const std::string key = from + '\x1f' + to + '\x1f' + (tainted ? 'T' : 'N') + (is_lock ? 'L' : 'C');
            if (seen_edges.insert(key).second) {
                getNodeId(from);
                getNodeId(to);
                edges.push_back({std::move(from), std::move(to), tainted, is_lock});
            }
        };

        LockAnalyzer lock_analyzer;
        for (const auto &rec : collector.records()) {
            if (!rec.lock_held_prev.empty() && !rec.lock_name.empty()) {
                LockOrderEdge lock_edge;
                lock_edge.first_lock = rec.lock_held_prev;
                lock_edge.second_lock = rec.lock_name;
                lock_edge.caller = rec.caller_function;
                lock_edge.file = rec.source_file;
                lock_edge.line = rec.line;
                lock_analyzer.recordEdge(std::move(lock_edge));
            }

            if (isPseudoCaller(rec.caller_function) || rec.symbol.empty() || rec.kind == "lock_order_inversion") {
                continue;
            }

            const bool is_tainted = rec.tainted_exec_flow || hasTag(rec.behavior_tags, "cross_tu_taint_summary");
            const bool is_non_benign = !rec.behavior_category.empty() && rec.behavior_category != "Benign";
            const bool is_interesting = is_non_benign || rec.is_intra_tu_call || is_tainted || rec.is_indirect_call ||
                                        rec.kind == "virtual_call" || rec.kind == "ir_resolved_indirect_call";
            if (is_interesting) {
                addEdge(rec.caller_function, rec.symbol, is_tainted, false);
            }
        }

        for (const auto &name : summary_names_) {
            const FunctionTaintSummary *s = summary_table_.findSummary(name);
            if (s != nullptr && !s->origin_symbol.empty() && s->origin_symbol != name) {
                addEdge(name, s->origin_symbol, true, false);
            }
        }

        for (const auto &lock_edge : lock_analyzer.edges()) {
            addEdge(lock_edge.first_lock, lock_edge.second_lock, false, true);
        }

        std::ostringstream out;
        out << "flowchart LR\n";
        // Emit deterministic node declarations in insertion order via vector
        std::vector<std::pair<std::string, std::string>> ordered_nodes(node_ids.begin(), node_ids.end());
        std::sort(ordered_nodes.begin(), ordered_nodes.end(),
                  [](const auto &a, const auto &b) { return a.second < b.second; });
        for (const auto &[label, id] : ordered_nodes) {
            out << "  " << id << "[\"" << escapeMermaidLabel(label) << "\"]\n";
        }
        for (const auto &e : edges) {
            const std::string &from_id = node_ids.at(e.from);
            const std::string &to_id = node_ids.at(e.to);
            if (e.is_lock) {
                out << "  " << from_id << " -.->|lock| " << to_id << "\n";
            } else if (e.tainted) {
                out << "  " << from_id << " -->|tainted| " << to_id << "\n";
            } else {
                out << "  " << from_id << " --> " << to_id << "\n";
            }
        }
        return out.str();
    }

    std::string ProjectAggregator::toGraphvizDot() const {
        const CallPatternCollector collector = buildMergedCollector();
        static constexpr size_t kMaxEdges = 500;

        struct GraphEdge {
            std::string from;
            std::string to;
            bool tainted{false};
            bool is_lock{false};
        };
        std::vector<GraphEdge> edges;
        std::unordered_set<std::string> seen_edges;

        auto addEdge = [&](std::string from, std::string to, bool tainted, bool is_lock) {
            if (edges.size() >= kMaxEdges || from.empty() || to.empty()) {
                return;
            }
            const std::string key = from + '\x1f' + to + '\x1f' + (tainted ? 'T' : 'N') + (is_lock ? 'L' : 'C');
            if (seen_edges.insert(key).second) {
                edges.push_back({std::move(from), std::move(to), tainted, is_lock});
            }
        };

        LockAnalyzer lock_analyzer;
        for (const auto &rec : collector.records()) {
            if (!rec.lock_held_prev.empty() && !rec.lock_name.empty()) {
                LockOrderEdge lock_edge;
                lock_edge.first_lock = rec.lock_held_prev;
                lock_edge.second_lock = rec.lock_name;
                lock_edge.caller = rec.caller_function;
                lock_edge.file = rec.source_file;
                lock_edge.line = rec.line;
                lock_analyzer.recordEdge(std::move(lock_edge));
            }

            if (isPseudoCaller(rec.caller_function) || rec.symbol.empty() || rec.kind == "lock_order_inversion") {
                continue;
            }

            const bool is_tainted = rec.tainted_exec_flow || hasTag(rec.behavior_tags, "cross_tu_taint_summary");
            const bool is_non_benign = !rec.behavior_category.empty() && rec.behavior_category != "Benign";
            const bool is_interesting = is_non_benign || rec.is_intra_tu_call || is_tainted || rec.is_indirect_call ||
                                        rec.kind == "virtual_call" || rec.kind == "ir_resolved_indirect_call";
            if (is_interesting) {
                addEdge(rec.caller_function, rec.symbol, is_tainted, false);
            }
        }

        for (const auto &name : summary_names_) {
            const FunctionTaintSummary *s = summary_table_.findSummary(name);
            if (s != nullptr && !s->origin_symbol.empty() && s->origin_symbol != name) {
                addEdge(name, s->origin_symbol, true, false);
            }
        }

        for (const auto &lock_edge : lock_analyzer.edges()) {
            addEdge(lock_edge.first_lock, lock_edge.second_lock, false, true);
        }

        std::ostringstream out;
        out << "digraph TraceQL {\n";
        out << "  rankdir=LR;\n";
        out << "  node [shape=box, fontname=\"monospace\"];\n";
        for (const auto &e : edges) {
            out << "  \"" << escapeDotString(e.from) << "\" -> \"" << escapeDotString(e.to) << "\"";
            if (e.is_lock) {
                out << " [label=\"lock\", style=\"dashed\", color=\"orange\"]";
            } else if (e.tainted) {
                out << " [label=\"tainted\", color=\"red\", penwidth=2.0]";
            }
            out << ";\n";
        }
        out << "}\n";
        return out.str();
    }

    std::vector<BehaviorFinding> ProjectAggregator::analyzeProjectFindings(std::string_view target_os,
                                                                           uint32_t risk_threshold,
                                                                           double entropy_threshold,
                                                                           const DatasetLoader *dataset) const {
        const CallPatternCollector collector = buildMergedCollectorImpl(dataset);

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
            obs.tainted_exec_flow = rec.tainted_exec_flow;
            obs.lock_name = rec.lock_name;
            obs.lock_held_prev = rec.lock_held_prev;
            obs.lifetime_kind = rec.lifetime_kind;
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

        return BehaviorRuleEmitter::analyzeFindings(behavior_calls, behavior_sequences, target_os, risk_threshold,
                                                    entropy_threshold, dataset);
    }

} // namespace traceql
