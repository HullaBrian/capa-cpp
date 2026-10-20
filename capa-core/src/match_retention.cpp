#include "match_retention.h"

#include <utility>

namespace capa {

namespace {
// Stands in for "this leaf captured nothing", so the interner's inner key can always be a
// reference. A ternary with a `std::string()` on one side is a prvalue, and would copy the
// capture on every match -- the one allocation the lookup exists to avoid.
const std::string kNoCapture;
}  // namespace

void MatchRetention::note_subrules(const Result& result) {
    // Deliberately the same shape as render.cpp's collect_subrule_matches: descend into
    // every child whether or not its parent held, and record only the leaves that did.
    // A failed `and` still carries the successful children it evaluated before the one
    // that failed, and one of those can be the `match:` that makes a rule a subrule.
    if (!result.node_is_statement && result.feature.type == FeatureType::MatchedRule &&
        result.success)
        subrules_.insert(result.feature.s);
    for (const Result& child : result.children) note_subrules(child);
}

std::unique_ptr<EvidenceLeaf> MatchRetention::make_leaf(const Result& tree) {
    const Result* node = find_evidence_leaf(tree);
    if (!node) return nullptr;

    // Looked up on the uncapped string, which is what the tree holds: the capped copy is
    // built only when this feature and this string are seen for the first time.
    auto& by_capture = kinds_[node->node_is_statement ? node->stmt->range_child : node->feature];
    const std::string& captured =
        node->captures.empty() ? kNoCapture : node->captures.front().first;
    auto it = by_capture.find(captured);
    if (it == by_capture.end())
        it = by_capture.emplace(captured, std::make_shared<const EvidenceKind>(
                                              evidence_kind_of(*node)))
                 .first;

    auto leaf = std::make_unique<EvidenceLeaf>();
    leaf->kind = it->second;
    leaf->locations = node->locations;
    return leaf;
}

MatchEvidence MatchRetention::retain(const std::string& rule, MatchEvidence&& evidence,
                                     std::size_t kept) {
    // Unconditionally, and before any decision to discard: capability_rules() needs the
    // union over *every* tree, not over the ones that survived.
    if (evidence) note_subrules(*evidence);

    // Likewise before the discard, and only once: on the second pass the tree may already
    // be gone, and the leaf taken on the first is the one that has to survive.
    if (keep_leaves_ && evidence && !evidence.leaf) evidence.leaf = make_leaf(*evidence);

    if (!enabled() || kept < max_trees_) return std::move(evidence);

    ++truncated_[rule];
    // Freed here rather than emptied: the point of the cap is that the tree stops
    // occupying memory, and the caller keeps the slot, the address and the leaf regardless.
    evidence.tree.reset();
    return std::move(evidence);
}

}  // namespace capa
