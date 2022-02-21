#ifndef DAG_HPP
#define DAG_HPP
/*
 * dag - c++ header-only Directed Acyclic Graph library
 *
 * Copyright (C) 2021 Pollere LLC.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 *  You may contact Pollere LLC at info@pollere.net.
 *
 *  This is not intended as production code.
 */

#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <vector>

template <typename N>
struct DAG {
    std::set<N> nodes_;
    std::map<N, std::set<N>> links_;

    using Path = std::vector<N>;
    using PathSet = std::set<Path>;
    using NodeSet = std::set<N>;

    constexpr auto& nodes() const noexcept { return nodes_; }
    constexpr auto& links() const noexcept { return links_; }

    constexpr auto& links(const N& n) const { return links_.at(n); }
    constexpr bool linked(const N& src, const N& dst) const { return links_.at(src).contains(dst); }

    constexpr DAG<N>& add(N n) {
        nodes_.insert(n);
        links_[n];
        return *this;
    }
    constexpr DAG<N>& add(const N& src, const N& dst) {
        if (src != dst) {
            add(src);
            add(dst);
            links_[src].insert(dst);
        }
        return *this;
    }
    constexpr DAG<N>& add(const std::vector<N>& p) {
        // add the entire path 'p'
        for (size_t i = 1; i < p.size(); i++) {
            add(p[i-1], p[i]);
        }
        return *this;
    }

    constexpr NodeSet sinks() const {
        NodeSet s{};
        for (const N& n : nodes_) {
            if (links_.at(n).size() == 0) {
                s.emplace(n);
            }
        }
        return s;
    }
    constexpr NodeSet sources() const { return reverse().sinks(); }
    constexpr bool isSink(const N& node) const noexcept { return sinks().contains(node); }
    constexpr bool isSource(const N& node) const noexcept { return sources().contains(node); }

    constexpr void paths(const N& src, const N& dst, Path& cur, PathSet& ps) const {
        cur.emplace_back(src);
        if (src == dst && cur.size() > 1) {
            ps.emplace(cur);
        } else {
            for (auto& nxt : links_.at(src)) {
                paths(nxt, dst, cur, ps);
            }
        }
        cur.pop_back();
    }
    // return all paths from src to dst
    constexpr PathSet paths(const N& src, const N& dst) const {
        PathSet ps{};
        if (nodes_.contains(src) && nodes_.contains(dst)) {
            Path cur{};
            paths(src, dst, cur, ps);
        }
        return ps;
    }
    constexpr DAG<N> reverse() const {
        DAG<N> rev;
        for (const N& n : nodes_) {
            for (const auto& succ : links_.at(n)) {
                rev.add(succ, n);
            }
        }
        return rev;
    }
    constexpr friend bool operator<=>(const DAG& g1, const DAG& g2) noexcept {
        return g1.links_ <=> g2.links_;
    }
    constexpr friend bool operator==(const DAG& g1, const DAG& g2) noexcept {
        return g1.links_ == g2.links_;
    }

    // DAG algorithms
    using nodeInfo = std::map<N,int>;
    using dfsFunc = std::function<int(const N&)>;

    // DFS recursion
    constexpr bool dfs(N cur, N strt, nodeInfo& visit, dfsFunc f) const {
        for (const auto succ : links_.at(cur)) {
            if (succ == strt) {
                // found a loop
                return false;
            }
            if (visit[succ] == 0) {
                if (! dfs(succ, strt, visit, f)) {
                    return false;
                }
            }
        }
        visit[cur] = f(cur);
        return true;
    }

    // construct a topological ordering of the DAG
    constexpr std::vector<N> topo() const {
        nodeInfo visit{};
        auto num = nodes_.size();
        dfsFunc f = [&num](auto /*n*/) mutable { return --num; };
        for (const auto node : nodes_) {
            if (visit[node] == 0) {
                if (! dfs(node, node, visit, f)) {
                    // graph isn't a DAG
                    break;
                }
            }
        }
        // return a vector of nodes in topo order.
        std::vector<N> to(visit.size());
        for (const auto& [n, d] : visit) {
            to[d] = n;
        }
        return to;
    }

    // get each node's out-degree
    constexpr std::multimap<int,N> outDegree() const {
        nodeInfo visit{};
        for (const auto node : nodes_) {
            if (visit[node] == 0) {
                if (! dfs(node, node, visit,
                          [this](auto n){return links_[n].size()+1;})) {
                    // graph isn't a DAG
                    break;
                }
            }
        }
        // return multimap of nodes ordered by out degree
        std::multimap<int,N> dm{};
        for (const auto& [n, d] : visit) {
            dm.emplace(d, n);
        }
        return dm;
    }
};

// print DAG in dot format
template <typename N>
inline std::ostream& operator<<(std::ostream& f, const DAG<N>& g) {
    f << "digraph mygraph {\n";
    for (const N& src : g.nodes()) {
        const auto& l = g.links().at(src);
        if (l.size() > 0) {
            for (const auto& dst : l) {
                f << "  \"" << src << "\" -> \"" << dst << "\";\n";
            }
        } else {
            f << "  \"" << src << "\";\n";
        }
    }
    f << "}\n";
    return f;
}

template <typename N>
inline std::ostream& operator<<(std::ostream& f, const std::set<N>& s) {
    f << '{';
    for (const auto& n : s) {
        f << " \"" << n << '"';
    }
    f << " }\n";
    return f;
}
template <typename N>
inline std::ostream& operator<<(std::ostream& f, const std::vector<N>& p) {
    if (p.size() == 0) {
        f << "(none)\n";
        return f;
    }
    for (size_t i = 0; i < p.size(); i++) {
        if (i > 0) {
            f << " -> ";
        }
        f << '"' << p.at(i) << '"';
    }
    f << '\n';
    return f;
}
template <typename N>
inline std::ostream& operator<<(std::ostream& f, const std::set<std::vector<N>>& s) {
    for (const auto& p : s) {
        f << p;
    }
    return f;
}

#endif /*DAG_HPP*/
