#include "../base/fixpoint_solver.h"

#include <algorithm>
#include <queue>
#include <unordered_map>
#include <unordered_set>

namespace traceql {

    std::vector<std::vector<std::string>> TarjanFixpointSolver::computeSccs(const std::vector<CallEdge> &edges) const {
        std::unordered_map<std::string, std::vector<std::string>> adj;
        std::unordered_set<std::string> nodes_set;
        for (const auto &e : edges) {
            if (e.caller.empty() || e.callee.empty()) {
                continue;
            }
            adj[e.caller].push_back(e.callee);
            nodes_set.insert(e.caller);
            nodes_set.insert(e.callee);
        }

        std::vector<std::string> nodes(nodes_set.begin(), nodes_set.end());
        std::sort(nodes.begin(), nodes.end());

        uint32_t next_index = 0;
        std::unordered_map<std::string, uint32_t> index_map;
        std::unordered_map<std::string, uint32_t> lowlink_map;
        std::unordered_set<std::string> on_stack;
        std::vector<std::string> stack;
        std::vector<std::vector<std::string>> sccs;

        auto strongconnect = [&](auto &self, const std::string &v) -> void {
            index_map[v] = next_index;
            lowlink_map[v] = next_index;
            ++next_index;
            stack.push_back(v);
            on_stack.insert(v);

            if (const auto it = adj.find(v); it != adj.end()) {
                for (const auto &w : it->second) {
                    if (index_map.find(w) == index_map.end()) {
                        self(self, w);
                        lowlink_map[v] = std::min(lowlink_map[v], lowlink_map[w]);
                    } else if (on_stack.find(w) != on_stack.end()) {
                        lowlink_map[v] = std::min(lowlink_map[v], index_map[w]);
                    }
                }
            }

            if (lowlink_map[v] == index_map[v]) {
                std::vector<std::string> comp;
                while (!stack.empty()) {
                    std::string w = std::move(stack.back());
                    stack.pop_back();
                    on_stack.erase(w);
                    const bool done = (w == v);
                    comp.push_back(std::move(w));
                    if (done) {
                        break;
                    }
                }
                sccs.push_back(std::move(comp));
            }
        };

        for (const auto &n : nodes) {
            if (index_map.find(n) == index_map.end()) {
                strongconnect(strongconnect, n);
            }
        }
        return sccs;
    }

    void TarjanFixpointSolver::solveSummaries(const std::vector<CallEdge> &edges, FunctionSummaryTable &table) const {
        const auto sccs = computeSccs(edges);

        std::unordered_map<std::string, std::vector<std::string>> callees_of;
        std::unordered_map<std::string, std::vector<std::string>> callers_of;
        for (const auto &e : edges) {
            if (e.caller.empty() || e.callee.empty()) {
                continue;
            }
            callees_of[e.caller].push_back(e.callee);
            callers_of[e.callee].push_back(e.caller);
        }

        for (const auto &scc : sccs) {
            std::unordered_set<std::string> scc_set(scc.begin(), scc.end());
            std::queue<std::string> worklist;
            std::unordered_set<std::string> in_queue;
            for (const auto &fn : scc) {
                if (in_queue.insert(fn).second) {
                    worklist.push(fn);
                }
            }

            constexpr size_t kMaxIterations = 1024;
            size_t iters = 0;
            while (!worklist.empty() && iters++ < kMaxIterations) {
                const std::string fn = worklist.front();
                worklist.pop();
                in_queue.erase(fn);

                const FunctionTaintSummary *cur_ptr = table.findSummary(fn);
                FunctionTaintSummary updated = cur_ptr ? *cur_ptr : FunctionTaintSummary{};
                const uint32_t old_mask = updated.return_taint_mask;

                if (const auto cit = callees_of.find(fn); cit != callees_of.end()) {
                    for (const auto &callee : cit->second) {
                        const FunctionTaintSummary *callee_sum = table.findSummary(callee);
                        if (!callee_sum) {
                            continue;
                        }
                        if (callee_sum->return_taint_mask != 0 && !updated.param_to_return.empty()) {
                            updated.return_taint_mask |= callee_sum->return_taint_mask;
                            if (updated.origin_symbol.empty()) {
                                updated.origin_symbol = callee_sum->origin_symbol;
                            }
                        }
                    }
                }

                if (updated.return_taint_mask != old_mask) {
                    table.recordSummary(fn, updated);
                    if (const auto pit = callers_of.find(fn); pit != callers_of.end()) {
                        for (const auto &caller : pit->second) {
                            if (scc_set.count(caller) && in_queue.insert(caller).second) {
                                worklist.push(caller);
                            }
                        }
                    }
                }
            }
        }
    }

} // namespace traceql
