#include "analysis/lock_analyzer.h"

#include <map>
#include <utility>

namespace traceql {

    void LockAnalyzer::recordEdge(LockOrderEdge edge) {
        if (edge.first_lock.empty() || edge.second_lock.empty() || edge.first_lock == edge.second_lock) {
            return;
        }
        edges_.push_back(std::move(edge));
    }

    std::vector<LockInversionFinding> LockAnalyzer::detectInversions() const {
        using EdgeKey = std::pair<std::string, std::string>;
        std::map<EdgeKey, const LockOrderEdge *> directed_edges;

        for (const auto &edge : edges_) {
            if (edge.first_lock.empty() || edge.second_lock.empty() || edge.first_lock == edge.second_lock) {
                continue;
            }
            directed_edges.emplace(EdgeKey{edge.first_lock, edge.second_lock}, &edge);
        }

        std::vector<LockInversionFinding> findings;
        for (const auto &[key, edge_ab] : directed_edges) {
            const auto &[lock_a, lock_b] = key;
            if (!(lock_a < lock_b)) {
                continue;
            }
            const auto rev_it = directed_edges.find(EdgeKey{lock_b, lock_a});
            if (rev_it == directed_edges.end()) {
                continue;
            }
            const LockOrderEdge *edge_ba = rev_it->second;
            LockInversionFinding finding;
            finding.lock_a = lock_a;
            finding.lock_b = lock_b;
            finding.caller_ab = edge_ab->caller;
            finding.caller_ba = edge_ba->caller;
            finding.file_ab = edge_ab->file;
            finding.file_ba = edge_ba->file;
            findings.push_back(std::move(finding));
        }

        return findings;
    }

    void LockAnalyzer::clear() {
        edges_.clear();
    }

} // namespace traceql
