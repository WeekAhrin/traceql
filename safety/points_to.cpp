#include "../safety/points_to.h"

#include <algorithm>
#include <queue>
#include <unordered_set>

namespace traceql {

    const std::vector<uintptr_t> PointsToGraph::kEmpty{};

    bool PointsToGraph::insertPointee(uintptr_t ptr, uintptr_t target) {
        if (ptr == 0 || target == 0) {
            return false;
        }
        auto &vec = pts_[ptr];
        if (std::find(vec.begin(), vec.end(), target) != vec.end()) {
            return false;
        }
        vec.push_back(target);
        return true;
    }

    void PointsToGraph::addAddrOf(uintptr_t ptr, uintptr_t target) {
        insertPointee(ptr, target);
    }

    void PointsToGraph::addCopy(uintptr_t dst, uintptr_t src) {
        if (dst == 0 || src == 0 || dst == src) {
            return;
        }
        auto &adj = copy_edges_[src];
        if (std::find(adj.begin(), adj.end(), dst) == adj.end()) {
            adj.push_back(dst);
        }
    }

    void PointsToGraph::addStore(uintptr_t dst_ptr, uintptr_t src) {
        if (dst_ptr == 0 || src == 0) {
            return;
        }
        store_edges_.push_back(ComplexEdge{dst_ptr, src});
    }

    void PointsToGraph::addLoad(uintptr_t dst, uintptr_t src_ptr) {
        if (dst == 0 || src_ptr == 0) {
            return;
        }
        load_edges_.push_back(ComplexEdge{dst, src_ptr});
    }

    void PointsToGraph::solve() {
        std::queue<uintptr_t> worklist;
        std::unordered_set<uintptr_t> in_queue;
        auto push_node = [&](uintptr_t n) {
            if (in_queue.insert(n).second) {
                worklist.push(n);
            }
        };

        for (const auto &[ptr, targets] : pts_) {
            if (!targets.empty()) {
                push_node(ptr);
            }
        }

        constexpr size_t kMaxIterations = 10000;
        size_t iters = 0;
        while (!worklist.empty() && iters++ < kMaxIterations) {
            const uintptr_t n = worklist.front();
            worklist.pop();
            in_queue.erase(n);

            const auto pts_it = pts_.find(n);
            if (pts_it == pts_.end()) {
                continue;
            }
            const std::vector<uintptr_t> n_pts = pts_it->second;

            if (const auto copy_it = copy_edges_.find(n); copy_it != copy_edges_.end()) {
                for (uintptr_t dst : copy_it->second) {
                    bool changed = false;
                    for (uintptr_t t : n_pts) {
                        changed |= insertPointee(dst, t);
                    }
                    if (changed) {
                        push_node(dst);
                    }
                }
            }

            for (const auto &st : store_edges_) {
                if (st.a == n) {
                    for (uintptr_t t : n_pts) {
                        addCopy(t, st.b);
                        if (const auto src_it = pts_.find(st.b); src_it != pts_.end() && !src_it->second.empty()) {
                            push_node(st.b);
                        }
                    }
                }
            }

            for (const auto &ld : load_edges_) {
                if (ld.b == n) {
                    for (uintptr_t t : n_pts) {
                        addCopy(ld.a, t);
                        if (const auto t_it = pts_.find(t); t_it != pts_.end() && !t_it->second.empty()) {
                            push_node(t);
                        }
                    }
                }
            }
        }
    }

    const std::vector<uintptr_t> &PointsToGraph::pointsTo(uintptr_t ptr) const {
        if (const auto it = pts_.find(ptr); it != pts_.end()) {
            return it->second;
        }
        return kEmpty;
    }

    void PointsToGraph::clear() {
        pts_.clear();
        copy_edges_.clear();
        store_edges_.clear();
        load_edges_.clear();
    }

} // namespace traceql
