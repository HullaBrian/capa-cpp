// Matching engine for capa-cpp.
//
// Ports capa/engine.py: the Statement tree (And/Or/Not/Some/Range/Subscope),
// Result, the FeatureSet, index_rule_matches, and the naive `match` routine.
//
// Feature evaluation is implemented here as free functions (eval_feature) so that
// feature.h can stay data-only and avoid a circular dependency.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "address.h"
#include "feature.h"

namespace capa {

// ---- scopes (subset needed by the engine/rendering; full enum in rules.h) ----
enum class Scope {
    FILE,
    PROCESS,
    THREAD,
    SPAN_OF_CALLS,
    CALL,
    FUNCTION,
    BASIC_BLOCK,
    INSTRUCTION,
    GLOBAL,
    UNSUPPORTED,
};

struct Statement;

// A Node is either a structural Statement or a leaf Feature.
struct Node {
    bool is_statement = false;
    std::shared_ptr<Statement> stmt;  // valid iff is_statement
    Feature feature;                  // valid iff !is_statement

    static Node of_statement(std::shared_ptr<Statement> s) {
        Node n;
        n.is_statement = true;
        n.stmt = std::move(s);
        return n;
    }
    static Node of_feature(Feature f) {
        Node n;
        n.is_statement = false;
        n.feature = std::move(f);
        return n;
    }
};

enum class StatementType { And, Or, Not, Some, Range, Subscope };

struct Statement {
    StatementType type;
    std::string description;

    std::vector<Node> children;  // And/Or: N; Not: 1; Some: N

    int count = 0;  // Some: threshold (0 == optional)

    // Range:
    Feature range_child;
    std::int64_t range_min = 0;
    std::uint64_t range_max = ~0ull;  // (1<<64)-1

    // Subscope (present only before extract_subscope_rules lowers it away):
    Scope subscope = Scope::CALL;
};

// dict[Feature, set[Address]]
using FeatureSet = std::unordered_map<Feature, AddressSet>;

// Result of evaluating a Node against a FeatureSet. Retains the node identity and
// child results so renderers can walk the match tree.
struct Result {
    bool success = false;

    bool node_is_statement = false;
    const Statement* stmt = nullptr;  // when node_is_statement
    Feature feature;                  // when !node_is_statement

    std::vector<Result> children;
    AddressSet locations;

    // For regex/substring: the concrete strings that matched -> their locations,
    // sorted by string so iteration order matches the std::map this used to be.
    //
    // A vector rather than a map because only regex and substring features ever fill
    // it, and MSVC's std::map allocates its sentinel node in the default constructor
    // -- so every other node in every match tree paid a heap allocation for a
    // container it never used. A match tree has one node per rule node per match, and
    // a whole dump's worth of them is a large fraction of a scan's memory.
    using Capture = std::pair<std::string, AddressSet>;
    std::vector<Capture> captures;

    explicit operator bool() const { return success; }
};

// ---- evaluation ----
Result eval_node(const Node& node, const FeatureSet& features, bool short_circuit);
Result eval_feature(const Feature& feat, const FeatureSet& features, bool short_circuit);
Result eval_statement(const Statement& stmt, const FeatureSet& features, bool short_circuit);

// ---- matching ----

// A rule as the engine needs to see it: a root node plus the identity used when
// its match is indexed back into the feature set (name + every namespace prefix).
struct MatchableRule {
    std::string name;
    std::vector<std::string> namespaces;  // e.g. {"c2/file-transfer", "c2"}
    const Node* root = nullptr;           // points into the owning Rule (stable)
};

// The half of an evidence leaf that repeats across matches: which feature held, and the
// concrete string it captured.
//
// Separated from the locations, and interned, because a rule that matches 600,000 times
// almost always matches on the same feature and the same string every one of them -- the
// process search path that satisfies a `powershell` regex is the same 260 characters at
// every call in the trace. Shared, a rule's leaves cost one of these; copied, they cost
// one per match, and a Feature alone is 184 bytes.
struct EvidenceKind {
    Feature feature;
    // Non-empty only for regex/substring, where the pattern is in the rule and the string
    // it matched is in the trace. Capped: see kMaxCapturedBytes.
    std::string captured;
    bool captured_truncated = false;
};

// The one leaf of a match tree worth keeping when the tree itself is not: which feature
// completed the match, and where that feature actually was -- which for a span-of-calls
// rule is not the address the match is filed under, and the difference is the point.
struct EvidenceLeaf {
    std::shared_ptr<const EvidenceKind> kind;
    AddressSet locations;
};

// How much of a captured string is kept. The search path in the motivating trace is
// already 260 characters and a matched string can be far longer, so one pathological
// string is not allowed to reintroduce the size problem the leaf exists to avoid.
inline constexpr std::size_t kMaxCapturedBytes = 256;

// The evidence for one match: why the rule held here.
//
// `tree` is the whole story and is held behind a pointer because on a large trace it is
// the exception rather than the rule. `--max-match-trees` keeps a few hundred per rule
// and stubs the rest, and an inline Result charged every one of the hundreds of thousands
// of stubs the full 264 bytes -- 184 of it a Feature that a stub does not have. Behind a
// pointer the stored element is 48 bytes rather than 296, and only a retained tree pays
// an allocation.
//
// A null `tree` *is* the stub: see is_truncated_match() in match_retention.h.
//
// `leaf` is the one node of that tree a reader cannot reconstruct from the rule text, kept
// only when `--match-evidence` asks for it. It is taken before the tree is dropped, so it
// survives a stub -- which is the whole reason it is a separate member rather than
// something a renderer could work out from what it was handed.
struct MatchEvidence {
    std::unique_ptr<Result> tree;
    std::unique_ptr<EvidenceLeaf> leaf;

    MatchEvidence() = default;
    // Implicit, so the matcher keeps saying `emplace_back(addr, make_unique<Result>(...))`.
    MatchEvidence(std::unique_ptr<Result> t) : tree(std::move(t)) {}

    // The pointer-like spelling the tree had when it was the whole of this type.
    explicit operator bool() const { return tree != nullptr; }
    const Result& operator*() const { return *tree; }
    const Result* operator->() const { return tree.get(); }
    const Result* get() const { return tree.get(); }
};

// The leaf of `tree` that best explains why the rule held, or null when nothing in it
// qualifies. Failed branches are not descended into: a non-short-circuit evaluation keeps
// the children an `or` rejected, and they did not contribute to this match.
//
// Preference order, and it is load-bearing that it is deterministic -- two runs over one
// trace must choose the same node:
//   1. the first successful string/substring/regex feature in pre-order, since that is
//      the one whose matched value is nowhere in the rule;
//   2. failing that, the first successful feature that is about this match -- anything
//      but `os:` / `arch:` / `format:`, which hold identically at every match in the run
//      and so explain none of them. Most rules open with one, and taken in plain
//      pre-order it would be the answer for nearly every match in the document;
//   3. failing that, one of those global features after all, which is at least true;
//   4. failing that, the first successful `count(...)`, whose feature lives on the
//      statement rather than in a child -- a rule that is nothing but a range would
//      otherwise have no evidence at all.
// A `match:` feature is a leaf like any other and is not descended into: a nested rule's
// evidence belongs to that rule's own match.
const Result* find_evidence_leaf(const Result& tree);

// The feature and capture of `node`, as chosen by find_evidence_leaf. `node` may be a
// feature node or a successful range statement; the capture is the first of the node's,
// in the sorted order eval_regex/eval_substring produce, capped at kMaxCapturedBytes.
// A node's own locations are the leaf's locations either way: a feature node holds the
// addresses the feature was seen at, and a range statement holds those of the feature it
// counted.
EvidenceKind evidence_kind_of(const Result& node);

// mapping from rule name -> list of (match location, evidence)
using MatchResults = std::map<std::string, std::vector<std::pair<Address, MatchEvidence>>>;

// Record that `name` (+ its namespaces) matched at the given locations, by adding
// MatchedRule features into `features` in place. Ports engine.index_rule_matches.
void index_rule_matches(FeatureSet& features, const std::string& name,
                        const std::vector<std::string>& namespaces,
                        const AddressSet& locations);

// Naive top-down matcher. Ports engine.match: rules must be topologically ordered
// by dependency. Returns the augmented feature set and the matches.
std::pair<FeatureSet, MatchResults> match(const std::vector<const MatchableRule*>& rules,
                                          const FeatureSet& features, const Address& addr);

}  // namespace capa
