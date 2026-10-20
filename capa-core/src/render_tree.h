// Match-tree text rendering for capa-cpp.
//
// This is the indented "and: / or: / api: CreateFileA @ 0x401000" view capa's
// vverbose renderer prints under each matched rule. It is split out of render.cpp
// because it needs nothing but a RuleSet and a MatchResults — no extractor, no
// result document — so both the CLI's `-vv` output and the IDA plugin's detail pane
// can use it.
#pragma once

#include <string>

#include "address.h"
#include "engine.h"
#include "rules.h"

namespace capa::render {

// Everything the tree walk needs: the rules (to recognize and expand `match:`
// references) and all matches (to find the referenced rule's own match tree).
struct MatchCtx {
    const RuleSet& ruleset;
    const MatchResults& matches;
};

// capa's short address form: "0x401000", "process{pid:4,tid:8,call:12}", "global", ...
std::string format_address(const Address& a);

// Render `res` and its successful descendants as indented text, starting at `indent`
// levels (2 spaces each). Failed nodes are skipped, `match:` references to real rules
// are expanded inline, and subscope rules are rendered as their scope block —
// the same splicing capa's vverbose does.
std::string render_match_tree(const MatchCtx& ctx, const Result& res, int indent = 0);

// The same, for a match whose evidence may not have been kept (`--max-match-trees`):
// a null one renders as a line saying so rather than as nothing.
std::string render_match_tree(const MatchCtx& ctx, const MatchEvidence& evidence,
                              int indent = 0);

}  // namespace capa::render
