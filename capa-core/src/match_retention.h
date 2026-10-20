// How many whole match trees are worth keeping per rule.
//
// A Result is a recursive tree with a std::vector of children and a std::set of locations
// at every node, and the dynamic walk keeps one per match. That is fine until a rule
// matches a lot: on a two-million-call slice of a media-player trace, `create or open
// file` matched 639,945 times, and the 644,931 trees across all rules are most of what
// the matcher holds -- and far more than what renders it can survive, since -j serializes
// every one of them into a document it then dumps to a string.
//
// Nothing reads past the first few. ttd-timeline.py binds the tree and discards it
// (`for addr, _tree in entry["matches"]`); ttd-report.py takes only len(matches); the text
// renderers print one tree per rule. So keep the first `max_trees` in full and replace the
// rest with a stub that carries the node identity and nothing else.
//
// What a stub must NOT cost:
//   - the match count, which ttd-report.py reads -- so a stub still occupies its slot
//   - the match address, which ttd-timeline.py resolves against its call index -- so the
//     (Address, Result) pair is kept intact and only the Result is emptied
//   - the subrule classification, which capability_rules() derives by walking every tree
//     for `match:` features. That walk would see only the kept trees, so the names are
//     collected here instead, from every tree, before any of them is thrown away.
#pragma once

#include <cstddef>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "engine.h"

namespace capa {

class MatchRetention {
public:
    // Keep every tree. Distinct from 0, which keeps none -- what `--matches-only` wants,
    // since a document that will not print a single tree has no reason to hold one.
    // `--max-match-trees 0` reads as "no limit" on the command line and main.cpp maps it
    // here; inside the matcher the count means what it says.
    static constexpr std::size_t kKeepAll = std::numeric_limits<std::size_t>::max();

    // `keep_leaves` is `--match-evidence`: take one leaf out of every tree before
    // deciding whether to keep the tree, so a stubbed match still says which feature
    // completed it. Off, nothing here changes and no leaf is allocated.
    explicit MatchRetention(std::size_t max_trees, bool keep_leaves = false)
        : max_trees_(max_trees), keep_leaves_(keep_leaves) {}

    // Records the `match:` names anywhere in `evidence` and, when asked, its evidence
    // leaf; then returns it with its tree either kept or dropped, according to how many
    // trees `rule` has already kept. `kept` is the number of entries already stored for
    // this rule.
    //
    // Idempotent: a match is merged call-to-thread-to-process, so the same evidence
    // passes through here several times, and the second pass must not undo the first.
    MatchEvidence retain(const std::string& rule, MatchEvidence&& evidence, std::size_t kept);

    // Every rule named by a `match:` feature in any successful tree, kept or stubbed.
    const std::unordered_set<std::string>& subrule_matches() const { return subrules_; }

    // rule -> how many of its trees were replaced by stubs. Empty when nothing was.
    const std::map<std::string, std::size_t>& truncated() const { return truncated_; }

    bool enabled() const { return max_trees_ != kKeepAll; }
    std::size_t max_trees() const { return max_trees_; }

private:
    void note_subrules(const Result& result);
    std::unique_ptr<EvidenceLeaf> make_leaf(const Result& tree);

    std::size_t max_trees_;
    bool keep_leaves_;
    std::unordered_set<std::string> subrules_;
    std::map<std::string, std::size_t> truncated_;

    // The interned halves of the leaves handed out so far, keyed by the feature that held
    // and by the *uncapped* string it captured -- so a hit costs two hashes and no
    // allocation, which on a rule with 600,000 matches is the difference that makes
    // keeping a leaf per match affordable at all. See EvidenceKind.
    std::unordered_map<Feature, std::unordered_map<std::string, std::shared_ptr<const EvidenceKind>>>
        kinds_;
};

// True for a match whose evidence retain() dropped. Renderers use it to say so rather
// than showing a match that appears to have held for no reason.
//
// A null tree is the whole representation: there is no emptied-out Result to recognise, so
// this cannot be confused with a real node and costs nothing to store. A match whose tree
// was dropped may still carry an evidence leaf, which is a different question and does not
// make it any less truncated.
inline bool is_truncated_match(const MatchEvidence& evidence) { return !evidence.tree; }

}  // namespace capa
