// Rules layer for capa-cpp.
//
// Ports capa/rules/__init__.py: Scope/Scopes, YAML rule parsing (build_statements /
// build_feature / parse_feature / parse_description / parse_int / parse_range /
// parse_bytes / count(...) / com/...), feature-for-scope validation, subscope
// extraction, dependency checking, topological ordering, namespace indexing, the query
// optimizer (capa/optimizer.py), and per-scope partitioning (RuleSet).
//
// RuleSet::match uses capa's feature index (RuleSet._index_rules_by_feature /
// RuleSet._match) to evaluate only candidate rules; RuleSet::match_naive is the plain
// engine.match over every rule of the scope, kept for paranoid testing -- the two must
// always agree, exactly as capa's `paranoid=True` asserts.
#pragma once

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "engine.h"

namespace YAML {
class Node;
}

namespace capa {

// ---- Scope <-> string ----
std::string scope_to_string(Scope s);
std::optional<Scope> scope_from_string(const std::string& s);  // nullopt if unknown

bool is_static_scope(Scope s);
bool is_dynamic_scope(Scope s);

struct Scopes {
    std::optional<Scope> static_scope;
    std::optional<Scope> dynamic_scope;

    bool contains(Scope s) const {
        return (static_scope && *static_scope == s) || (dynamic_scope && *dynamic_scope == s);
    }
};

// Raised when a rule cannot be parsed (mirrors capa InvalidRule).
struct InvalidRule {
    std::string message;
};

struct Rule {
    std::string name;
    Scopes scopes;
    Node root;  // the top-level statement tree

    // meta (fields used by matching + renderers)
    std::string namespace_;
    std::vector<std::string> authors;
    std::string description;
    std::vector<std::string> attack;      // raw "att&ck" strings
    std::vector<std::string> mbc;         // raw "mbc" strings
    std::vector<std::string> references;
    std::vector<std::string> examples;
    bool is_lib = false;
    bool is_subscope = false;
    std::string parent;  // capa/parent for subscope rules

    // `maec/<key>` meta, keyed without the prefix ("analysis-conclusion", ...): the
    // result document's RuleMetadata.maec. Only the keys the rule sets.
    std::map<std::string, std::string> maec;

    // capa/path and capa/nursery, which capa's loader adds to every rule it reads from
    // a file. Empty / false for a rule that did not come from one.
    std::string path;
    bool nursery = false;

    std::string definition;  // raw YAML source (the result document's `source`)

    // namespace prefixes, e.g. "c2/file-transfer" -> {"c2/file-transfer", "c2"}
    std::vector<std::string> namespace_prefixes() const;

    // engine view (root pointer is stable while this Rule lives)
    MatchableRule matchable() const;

    // Parse one rule from YAML text. Throws InvalidRule on failure.
    static Rule from_yaml(const std::string& yaml_text);

    // Rule.from_dict: parse an already-loaded document of the form `{rule: {meta, features}}`.
    // `definition` becomes the rule's source text.
    static Rule from_yaml_node(const YAML::Node& doc, const std::string& definition);
};

// capa.rules.build_feature over a textual value, as capa's tests use it for
// "key: value" fixture strings ("mnemonic: mov", "count(basic blocks): 7", ...): a
// Feature, a Range for count(...), or an `or:` for com/... The value is taken as a
// string, never typed as YAML would type it, and not validated against any scope.
Node build_feature_from_text(const std::string& key, const std::string& value);

class RuleSet {
public:
    RuleSet() = default;  // empty; assign from load_*. Move is safe: internal pointers
                          // live in vector/map buffers that survive moves.
    explicit RuleSet(std::vector<std::shared_ptr<Rule>> rules);

    // Match the rules for `scope` against `features` at `addr`, using capa's feature
    // index to evaluate only candidate rules. `features` is mutated during matching
    // (match features are added so dependent rules can match) but restored to its
    // original contents before returning, so callers may keep using it.
    MatchResults match(Scope scope, FeatureSet& features, const Address& addr) const;

    // The same answer from the naive matcher: every rule of the scope, in topological
    // order (capa.engine.match). For tests; see `paranoid` in capa's RuleSet.match.
    MatchResults match_naive(Scope scope, const FeatureSet& features, const Address& addr) const;

    // capa's `paranoid=True`: every match() also runs match_naive and records any
    // disagreement between the two. For tests; slow.
    void set_paranoid(bool on) { paranoid_ = on; }
    const std::vector<std::string>& paranoid_failures() const { return paranoid_failures_; }

    const std::vector<const MatchableRule*>& rules_for_scope(Scope scope) const;

    std::shared_ptr<Rule> get(const std::string& name) const;
    bool contains(const std::string& name) const { return by_name_.count(name) != 0; }

    // Direct dependency rule-names of a rule (namespaces expanded). Used by the
    // span-of-calls dedup logic. Empty set if the rule is unknown.
    std::set<std::string> dependencies_of(const std::string& name) const;
    std::size_t size() const { return by_name_.size(); }
    std::size_t source_rule_count() const { return source_rule_count_; }

    const std::vector<std::shared_ptr<Rule>>& all_rules() const { return rules_; }

    // namespace -> rules (each prefix), for dependency expansion + rendering.
    const std::unordered_map<std::string, std::vector<std::shared_ptr<Rule>>>&
    rules_by_namespace() const {
        return by_namespace_;
    }

    // Load every rule under a directory tree, the way capa's get_rules does: only
    // `.yml` files, and nothing under a path containing `.git` (capa-rules keeps CI
    // workflows in .github/). A rule that fails to parse is skipped with a warning --
    // capa itself refuses to run at all -- and the warnings say which. Throws
    // InvalidRule when no rule loads.
    static RuleSet load_from_directory(const std::string& dir);

    // The same over several paths, each a rule file or a directory (capa's `-r` may
    // be given more than once).
    static RuleSet load_from_paths(const std::vector<std::string>& paths);

private:
    // Per-scope: topologically-ordered rules plus capa's feature index, so match()
    // only evaluates the few candidate rules whose selective feature is present.
    struct ScopeIndex {
        std::vector<MatchableRule> matchables;      // topo order; index == position
        std::vector<const MatchableRule*> ptrs;     // same, as pointers
        std::unordered_map<std::string, int> index_by_name;
        // hashable selective feature -> rule indices that require it
        std::unordered_map<Feature, std::vector<int>> rules_by_feature;
        // rule index -> regex/substring features to scan against String features
        std::vector<std::pair<int, std::vector<Feature>>> string_rules;
        // rules that could not be indexed (rare); always treated as candidates
        std::vector<int> always_rules;
    };

    void build_scope_index(Scope scope, const std::vector<std::shared_ptr<Rule>>& ordered,
                           std::unordered_map<std::string, int>& scores_by_rule);
    MatchResults match_indexed(const ScopeIndex& si, FeatureSet& features,
                               const Address& addr) const;

    std::vector<std::shared_ptr<Rule>> rules_;  // owns all rules (incl. subscope rules)
    std::unordered_map<std::string, std::shared_ptr<Rule>> by_name_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<Rule>>> by_namespace_;

    std::map<Scope, ScopeIndex> scope_index_;

    std::size_t source_rule_count_ = 0;

    bool paranoid_ = false;
    mutable std::vector<std::string> paranoid_failures_;
};

}  // namespace capa
