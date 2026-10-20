// Which extracted features can possibly matter to a ruleset.
//
// The dynamic backend emits a `number` feature for every integer argument of every call
// -- pointers, handles, sizes, timestamps -- and the walk in capabilities.cpp unions each
// call's features into a thread-wide and then a process-wide FeatureSet. Those sets
// therefore grow one entry per *distinct argument value in the trace*, which on a large
// recording is tens of millions of keys, each an unordered_map node plus a std::set. That
// is what makes peak memory a function of trace length rather than of ruleset size, and it
// is the single largest allocation in the program.
//
// Almost none of it can ever be read. A feature is only observable through the handful of
// ways engine.cpp evaluates one, and most of those are exact lookups:
//
//   eval_feature's default branch   features.find(feat)      -- exact identity
//   Range (count(...))              features.find(range_child) -- exact identity
//   eval_substring / eval_regex     scan every String feature
//   eval_bytes                      scan every Bytes feature
//   eval_os                         scan every OS feature
//
// So a feature whose exact identity appears nowhere in any rule, and which is not one of
// the scanned kinds, cannot change any result. Dropping it before it reaches an
// accumulator is not an approximation -- it is unobservable by construction.
//
// This deliberately does NOT reuse RuleSet's ScopeIndex::rules_by_feature. That index
// keeps only each rule's *most selective* feature set and returns nothing for `not:`,
// `optional:` and `count(min 0)` subtrees, because it exists to pick candidate rules
// cheaply. Filtering against it would drop a feature sitting under a `not:` and flip that
// `not:` from false to true. The walk here prunes nothing.
#pragma once

#include <cstddef>
#include <memory>
#include <regex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "engine.h"
#include "feature.h"

namespace capa {

class RuleSet;

class FeatureFilter {
public:
    // Collects every leaf feature and every count() operand in every rule, with no
    // pruning at all. Includes subscope and library rules: those are exactly what a
    // user-facing rule's `match:` features point at.
    static FeatureFilter from_ruleset(const RuleSet& ruleset);

    // False only when nothing in the ruleset can observe this feature.
    bool keep(const Feature& feature) const;

    // Turns the filter into a no-op, for --no-feature-filter parity runs.
    void disable() { enabled_ = false; }
    bool enabled() const { return enabled_; }

    std::size_t exact_count() const { return exact_.size(); }
    std::size_t substring_count() const { return substrings_.size(); }
    std::size_t regex_count() const { return regexes_.size(); }

private:
    void collect(const Node& node);
    void add_leaf(const Feature& feature);
    bool keep_string(const std::string& value) const;

    std::unordered_set<Feature> exact_;
    std::vector<std::string> substrings_;
    // Borrowed from compile_capa_regex's cache, which lives as long as the program.
    std::vector<const std::regex*> regexes_;

    // A string is tested against every substring and regex in the ruleset, which is ~250
    // and ~700 of them. Distinct strings repeat heavily across a trace, so the answer is
    // worth remembering; the map is bounded by the number of distinct strings, not calls.
    mutable std::unordered_map<std::string, bool> string_memo_;

    bool enabled_ = true;
};

}  // namespace capa
