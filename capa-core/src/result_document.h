// Result-document metadata for any backend.
//
// Ports the parts of capa/loader.py that describe an analysis rather than perform it:
// collect_metadata (hashes, format/arch/os from the global features, extractor name,
// rule paths, feature counts, library functions) and compute_static_layout /
// compute_dynamic_layout (which functions/blocks, or processes/threads/calls, the
// document names). The renderers in render.h serialize what these build.
#pragma once

#include <string>
#include <vector>

#include "capabilities.h"
#include "feature_extractor.h"
#include "render.h"
#include "rules.h"
#include "static_caps.h"

namespace capa::render {

// capa resolves every path it writes into the document: Path.resolve().as_posix().
std::string capa_path(const std::string& path);

// `input_format` is what meta.analysis.format falls back to when the extractor has no
// format feature, as capa falls back to the input format it was given ("freeze", ...).
Doc build_static_doc(const RuleSet& ruleset, const StaticFeatureExtractor& extractor,
                     const StaticCapabilities& caps, const std::string& extractor_name,
                     const std::vector<std::string>& rule_paths,
                     const std::string& input_format = "unknown");

// `with_layout` off skips the matched-call walk and marks the document `layout_omitted`
// (a capa-cpp extension, for `--matches-only`).
Doc build_dynamic_doc(const RuleSet& ruleset, const DynamicFeatureExtractor& extractor,
                      const Capabilities& caps, const std::string& extractor_name,
                      const std::vector<std::string>& rule_paths, bool with_layout = true,
                      const std::string& input_format = "unknown");

}  // namespace capa::render
