#include "engine.h"

#include <algorithm>
#include <regex>

#include "pyregex.h"

namespace capa {

namespace {

// Build a Result node for a leaf feature.
Result feature_result(const Feature& feat, bool success, AddressSet locations) {
    Result r;
    r.success = success;
    r.node_is_statement = false;
    r.feature = feat;
    r.locations = std::move(locations);
    return r;
}

Result eval_substring(const Feature& feat, const FeatureSet& features) {
    std::map<std::string, AddressSet> matches;
    for (const auto& [f, locs] : features) {
        if (f.type != FeatureType::String) continue;
        if (f.s.find(feat.s) != std::string::npos) {
            auto& dst = matches[f.s];
            dst.insert(locs.begin(), locs.end());
        }
    }
    Result r;
    r.node_is_statement = false;
    r.feature = feat;
    if (!matches.empty()) {
        r.success = true;
        r.captures.reserve(matches.size());
        // `matches` is a std::map, so this moves them out already sorted by string.
        for (auto& [str, locs] : matches) {
            r.locations.insert(locs.begin(), locs.end());
            r.captures.emplace_back(str, std::move(locs));
        }
    }
    return r;
}

// capa.features.common.Regex.evaluate. The pattern is Python's, compiled with re.DOTALL
// (and re.IGNORECASE for /i); see pyregex.h for how it is carried over to std::regex. A
// pattern std::regex cannot express matches nothing -- the rule loader has already said so.
Result eval_regex(const Feature& feat, const FeatureSet& features) {
    const std::regex* re = compile_capa_regex(feat.s);
    std::map<std::string, AddressSet> matches;
    if (re) {
        for (const auto& [f, locs] : features) {
            if (f.type != FeatureType::String) continue;
            if (std::regex_search(f.s, *re)) {
                auto& dst = matches[f.s];
                dst.insert(locs.begin(), locs.end());
            }
        }
    }
    Result r;
    r.node_is_statement = false;
    r.feature = feat;
    if (!matches.empty()) {
        r.success = true;
        r.captures.reserve(matches.size());
        // `matches` is a std::map, so this moves them out already sorted by string.
        for (auto& [str, locs] : matches) {
            r.locations.insert(locs.begin(), locs.end());
            r.captures.emplace_back(str, std::move(locs));
        }
    }
    return r;
}

// capa's Bytes.evaluate and OS.evaluate stop at the *first* qualifying feature of the
// scope's feature set and report only its locations. "First" is Python dict order: the
// order features were first inserted, which the capabilities walk makes the order they
// were first seen -- functions, blocks and instructions in ascending address. A hash map
// has no such order, so the equivalent is chosen explicitly: the qualifying feature seen
// earliest, i.e. with the lowest location (features with no location last, then by
// value, so the choice never depends on hashing).
const AddressSet* first_seen(const AddressSet* best, const Feature*& best_feature, const Feature& f,
                             const AddressSet& locs) {
    auto earlier = [&]() {
        if (!best) return true;
        if (locs.empty() != best->empty()) return !locs.empty();
        if (!locs.empty() && *locs.begin() != *best->begin()) return *locs.begin() < *best->begin();
        return f.s < best_feature->s;
    };
    if (!earlier()) return best;
    best_feature = &f;
    return &locs;
}

Result eval_bytes(const Feature& feat, const FeatureSet& features) {
    const AddressSet* best = nullptr;
    const Feature* best_feature = nullptr;
    for (const auto& [f, locs] : features) {
        if (f.type != FeatureType::Bytes) continue;
        // extracted value startswith the rule's bytes value
        if (f.s.size() >= feat.s.size() && f.s.compare(0, feat.s.size(), feat.s) == 0)
            best = first_seen(best, best_feature, f, locs);
    }
    if (best) return feature_result(feat, true, *best);
    return feature_result(feat, false, {});
}

Result eval_os(const Feature& feat, const FeatureSet& features) {
    const AddressSet* best = nullptr;
    const Feature* best_feature = nullptr;
    for (const auto& [f, locs] : features) {
        if (f.type != FeatureType::OS) continue;
        if (feat.s == OS_ANY || f.s == OS_ANY || feat.s == f.s) best = first_seen(best, best_feature, f, locs);
    }
    if (best) return feature_result(feat, true, *best);
    return feature_result(feat, false, {});
}

}  // namespace

Result eval_feature(const Feature& feat, const FeatureSet& features, bool /*short_circuit*/) {
    switch (feat.type) {
        case FeatureType::Substring:
            return eval_substring(feat, features);
        case FeatureType::Regex:
            return eval_regex(feat, features);
        case FeatureType::Bytes:
            return eval_bytes(feat, features);
        case FeatureType::OS:
            return eval_os(feat, features);
        default:
            break;
    }
    // direct membership
    auto it = features.find(feat);
    if (it != features.end()) {
        return feature_result(feat, true, it->second);
    }
    return feature_result(feat, false, {});
}

Result eval_statement(const Statement& stmt, const FeatureSet& features, bool short_circuit) {
    Result r;
    r.node_is_statement = true;
    r.stmt = &stmt;

    switch (stmt.type) {
        case StatementType::And: {
            if (short_circuit) {
                for (const auto& child : stmt.children) {
                    Result cr = eval_node(child, features, short_circuit);
                    bool ok = cr.success;
                    r.children.push_back(std::move(cr));
                    if (!ok) {
                        r.success = false;
                        return r;
                    }
                }
                r.success = true;
            } else {
                r.success = true;
                for (const auto& child : stmt.children) {
                    Result cr = eval_node(child, features, short_circuit);
                    if (!cr.success) r.success = false;
                    r.children.push_back(std::move(cr));
                }
            }
            return r;
        }
        case StatementType::Or: {
            if (short_circuit) {
                for (const auto& child : stmt.children) {
                    Result cr = eval_node(child, features, short_circuit);
                    bool ok = cr.success;
                    r.children.push_back(std::move(cr));
                    if (ok) {
                        r.success = true;
                        return r;
                    }
                }
                r.success = false;
            } else {
                r.success = false;
                for (const auto& child : stmt.children) {
                    Result cr = eval_node(child, features, short_circuit);
                    if (cr.success) r.success = true;
                    r.children.push_back(std::move(cr));
                }
            }
            return r;
        }
        case StatementType::Not: {
            Result cr = eval_node(stmt.children.at(0), features, short_circuit);
            r.success = !cr.success;
            r.children.push_back(std::move(cr));
            return r;
        }
        case StatementType::Some: {
            int satisfied = 0;
            if (short_circuit) {
                for (const auto& child : stmt.children) {
                    Result cr = eval_node(child, features, short_circuit);
                    if (cr.success) ++satisfied;
                    r.children.push_back(std::move(cr));
                    if (satisfied >= stmt.count) {
                        r.success = true;
                        return r;
                    }
                }
                // capa.engine.Some: the threshold is only tested after a child has been
                // evaluated, so a short-circuit `optional:` with no children is false --
                // and match() only keeps a rule whose short-circuit evaluation succeeds.
                r.success = false;
            } else {
                for (const auto& child : stmt.children) {
                    Result cr = eval_node(child, features, short_circuit);
                    if (cr.success) ++satisfied;
                    r.children.push_back(std::move(cr));
                }
                r.success = satisfied >= stmt.count;
            }
            return r;
        }
        case StatementType::Range: {
            auto it = features.find(stmt.range_child);
            std::size_t count = (it != features.end()) ? it->second.size() : 0;
            if (stmt.range_min == 0 && count == 0) {
                r.success = true;
                return r;
            }
            r.success = (static_cast<std::uint64_t>(stmt.range_min) <= count) &&
                        (count <= stmt.range_max);
            if (it != features.end()) r.locations = it->second;
            return r;
        }
        case StatementType::Subscope:
            // must have been lowered by extract_subscope_rules before matching
            r.success = false;
            return r;
    }
    r.success = false;
    return r;
}

Result eval_node(const Node& node, const FeatureSet& features, bool short_circuit) {
    if (node.is_statement) {
        return eval_statement(*node.stmt, features, short_circuit);
    }
    return eval_feature(node.feature, features, short_circuit);
}

namespace {

// The feature kinds whose matched value is not in the rule. A rule carries the pattern;
// only the trace carries the string it hit, so this is the one leaf a reader cannot
// reconstruct from the rule text beside the match.
bool is_string_like(FeatureType t) {
    return t == FeatureType::String || t == FeatureType::Substring ||
           t == FeatureType::Regex;
}

// Pre-order over the successful part of the tree, remembering the best candidate of each
// tier. Stops as soon as tier 1 is settled, which is the common case and the cheap one.
void collect_evidence_candidates(const Result& node, const Result*& string_like,
                                 const Result*& located, const Result*& global,
                                 const Result*& range) {
    if (!node.success || string_like) return;
    if (!node.node_is_statement) {
        if (is_string_like(node.feature.type)) {
            string_like = &node;
        } else if (node.feature.is_global()) {
            if (!global) global = &node;
        } else if (!located) {
            located = &node;
        }
        // Feature nodes have no children, `match:` included -- and a nested rule's
        // evidence is its own match's, not this one's.
        return;
    }
    if (node.stmt && node.stmt->type == StatementType::Range && !range) range = &node;
    for (const Result& c : node.children)
        collect_evidence_candidates(c, string_like, located, global, range);
}

// Truncate on a UTF-8 boundary, so capping a string cannot turn a document the JSON
// serializer accepts into one it rejects. Bytes that are not UTF-8 to begin with are left
// alone; they were already the caller's problem, and moving the cut does not fix them.
std::size_t capped_length(const std::string& s) {
    if (s.size() <= kMaxCapturedBytes) return s.size();
    std::size_t n = kMaxCapturedBytes;
    while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xc0) == 0x80) --n;
    return n;
}

}  // namespace

const Result* find_evidence_leaf(const Result& tree) {
    const Result* string_like = nullptr;
    const Result* located = nullptr;
    const Result* global = nullptr;
    const Result* range = nullptr;
    collect_evidence_candidates(tree, string_like, located, global, range);
    if (string_like) return string_like;
    if (located) return located;
    if (global) return global;
    return range;
}

EvidenceKind evidence_kind_of(const Result& node) {
    EvidenceKind k;
    k.feature = node.node_is_statement ? node.stmt->range_child : node.feature;
    if (!node.captures.empty()) {
        // captures is sorted by string, so "the first" is the same one on every run.
        const std::string& raw = node.captures.front().first;
        const std::size_t n = capped_length(raw);
        k.captured.assign(raw, 0, n);
        k.captured_truncated = n < raw.size();
    }
    return k;
}

void index_rule_matches(FeatureSet& features, const std::string& name,
                        const std::vector<std::string>& namespaces,
                        const AddressSet& locations) {
    auto& rule_locs = features[Feature::matched_rule(name)];
    rule_locs.insert(locations.begin(), locations.end());
    for (const auto& ns : namespaces) {
        auto& ns_locs = features[Feature::matched_rule(ns)];
        ns_locs.insert(locations.begin(), locations.end());
    }
}

std::pair<FeatureSet, MatchResults> match(const std::vector<const MatchableRule*>& rules,
                                          const FeatureSet& features, const Address& addr) {
    FeatureSet fs = features;  // copy; keep this function pure w.r.t. caller
    MatchResults results;

    for (const MatchableRule* rule : rules) {
        if (!rule->root) continue;
        Result res = eval_node(*rule->root, fs, /*short_circuit=*/true);
        if (res.success) {
            // re-evaluate without short-circuit to collect the full result tree
            res = eval_node(*rule->root, fs, /*short_circuit=*/false);
            AddressSet loc{addr};
            results[rule->name].emplace_back(addr, std::make_unique<Result>(std::move(res)));
            index_rule_matches(fs, rule->name, rule->namespaces, loc);
        }
    }
    return {std::move(fs), std::move(results)};
}

}  // namespace capa
