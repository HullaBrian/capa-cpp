// Dynamic capabilities driver for capa-cpp.
//
// Ports capa/capabilities/dynamic.py (+ find_file_capabilities from common.py):
// walks process -> thread -> call, matching rules at each scope and bubbling both
// features and rule matches upward, plus the sliding-window SpanOfCallsMatcher.
//
// Backend-neutral: it drives any DynamicFeatureExtractor -- the TTD backend, or a
// freeze file through NullDynamicFeatureExtractor.
#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <unordered_set>

#include "engine.h"
#include "feature_filter.h"
#include "match_retention.h"
#include "feature_extractor.h"
#include "rules.h"

namespace capa {

struct Capabilities {
    // rule name -> list of (location, match result); one scope per rule, so no overlap.
    MatchResults matches;

    // feature counts, for verbose metadata
    std::size_t file_feature_count = 0;
    // per-process feature counts, in process order
    std::vector<std::pair<Address, std::size_t>> process_feature_counts;

    // Whether the counts above were taken after the ruleset feature filter ran. They are
    // then a count of the features that could matter, not of everything extracted, and a
    // reader comparing them against a capa run must know which.
    bool feature_counts_filtered = false;

    // Every rule named by a `match:` feature in any tree, collected while the trees were
    // still whole. Renderers use this instead of walking `matches`, which after tree
    // capping no longer holds all of them.
    std::unordered_set<std::string> subrule_matches;

    // rule -> trees replaced by stubs, for the diagnostic that says so.
    std::map<std::string, std::size_t> truncated_matches;

    // Diagnostics for the CAPA_CPP_TIMING probe. A scope's feature set is a map from
    // feature to the set of addresses it was seen at, and on a long trace it is the
    // second is what grows: one entry per occurrence, not per distinct feature. Knowing
    // which of the two a run is spending its memory on is the difference between
    // tuning the filter and changing how locations are stored.
    std::size_t peak_scope_features = 0;   // distinct features in the largest scope
    std::size_t peak_scope_locations = 0;  // their total recorded addresses
};

// `filter` decides which extracted features survive the merge into thread, process and
// file scope; pass a disabled one to reproduce the unfiltered behaviour exactly.
// `max_match_trees` caps how many whole match trees are kept per rule
// (MatchRetention::kKeepAll for no cap, 0 to keep none). The matches themselves, their
// count and their addresses are unaffected; see match_retention.h.
// `keep_evidence_leaves` (`--match-evidence`) keeps one leaf out of every tree, capped or
// not, so a match can say which feature completed it after its tree is gone.
// `top_level_calls` (`--top-level-calls`) matches only calls made outside every other recorded
// call on their thread: the calls the program made, not the ones an API made while carrying one
// out. See find_thread_capabilities.
//
// `span_size` is capa.capabilities.dynamic.SPAN_SIZE; only tests change it.
inline constexpr std::size_t DEFAULT_SPAN_SIZE = 20;

Capabilities find_dynamic_capabilities(const RuleSet& ruleset,
                                       const DynamicFeatureExtractor& extractor,
                                       const FeatureFilter& filter, std::size_t max_match_trees,
                                       bool keep_evidence_leaves = false,
                                       bool top_level_calls = false,
                                       std::size_t span_size = DEFAULT_SPAN_SIZE);

}  // namespace capa
