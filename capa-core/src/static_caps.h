// Static capabilities driver for capa-cpp.
//
// Ports capa/capabilities/static.py: walk function -> basic block -> instruction,
// matching rules at each scope and bubbling features/matches upward, then match
// file-scope rules over the accumulated lower-scope matches.
//
// Backend-neutral: it drives any StaticFeatureExtractor, so both the Zydis backend
// (static/extractor.h) and the IDA backend (ida/extractor.h) go through it.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "engine.h"
#include "feature_filter.h"
#include "feature_extractor.h"
#include "rules.h"

namespace capa {

// A function the extractor identified as library code and the driver therefore skipped.
struct LibraryFunction {
    Address address;
    std::string name;
};

// Per-function analysis metadata, for the ResultDocument's layout and
// feature_counts sections (capa loader.compute_static_layout). Library functions the
// driver skipped are not listed.
struct FunctionInfo {
    Address address;
    std::size_t feature_count = 0;              // size of the function-scope FeatureSet
    std::vector<Address> matched_basic_blocks;  // blocks a rule matched at, sorted
};

struct StaticCapabilities {
    MatchResults matches;  // merged across instruction/bb/function/file scopes
    std::size_t function_count = 0;
    std::size_t feature_count = 0;
    std::vector<LibraryFunction> library_functions;
    std::vector<FunctionInfo> functions;  // in get_functions() order
};

// `filter` drops features no rule can read as they bubble up from instruction to basic
// block to function scope, which is what keeps a region's feature sets a function of the
// ruleset rather than of how much code the region holds. Pass a disabled one (or one the
// extractor was not also given) to keep everything.
StaticCapabilities find_static_capabilities(const RuleSet& ruleset,
                                            const StaticFeatureExtractor& extractor,
                                            const FeatureFilter& filter);

}  // namespace capa
