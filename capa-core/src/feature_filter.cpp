#include "feature_filter.h"

#include "engine.h"
#include "pyregex.h"
#include "rules.h"

namespace capa {

FeatureFilter FeatureFilter::from_ruleset(const RuleSet& ruleset) {
    FeatureFilter filter;
    for (const std::shared_ptr<Rule>& rule : ruleset.all_rules()) {
        if (rule) filter.collect(rule->root);
    }
    return filter;
}

void FeatureFilter::collect(const Node& node) {
    if (!node.is_statement) {
        add_leaf(node.feature);
        return;
    }
    if (node.stmt == nullptr) return;
    // count(api(VirtualAlloc)): 2 or more keeps the counted feature on the statement
    // rather than as a child node, and Range looks it up by exact identity.
    if (node.stmt->type == StatementType::Range) add_leaf(node.stmt->range_child);
    for (const Node& child : node.stmt->children) collect(child);
}

void FeatureFilter::add_leaf(const Feature& feature) {
    switch (feature.type) {
        case FeatureType::Substring:
            substrings_.push_back(feature.s);
            return;
        case FeatureType::Regex:
            // The same compiled pattern eval_regex uses. One that does not compile
            // matches nothing there, so it can keep no string alive here either.
            if (const std::regex* compiled = compile_capa_regex(feature.s))
                regexes_.push_back(compiled);
            return;
        default:
            exact_.insert(feature);
            return;
    }
}

bool FeatureFilter::keep_string(const std::string& value) const {
    auto memo = string_memo_.find(value);
    if (memo != string_memo_.end()) return memo->second;

    bool wanted = false;
    for (const std::string& needle : substrings_) {
        if (value.find(needle) != std::string::npos) {
            wanted = true;
            break;
        }
    }
    if (!wanted) {
        for (const std::regex* pattern : regexes_) {
            // MSVC's std::regex is a backtracking engine with a complexity ceiling, and it
            // throws rather than reporting no-match when a long string pushes a pattern
            // past it. That happens here and not in eval_regex because this tries every
            // pattern in the ruleset against every string, where the engine only ever
            // evaluates the patterns of rules its index already made candidates.
            //
            // A throw means "cannot tell", and the only safe reading of that is to keep
            // the string: dropping one a rule might have matched would change a result,
            // which is the one thing this filter must never do.
            try {
                if (std::regex_search(value, *pattern)) {
                    wanted = true;
                    break;
                }
            } catch (const std::regex_error&) {
                wanted = true;
                break;
            }
        }
    }
    string_memo_.emplace(value, wanted);
    return wanted;
}

bool FeatureFilter::keep(const Feature& feature) const {
    if (!enabled_) return true;

    switch (feature.type) {
        // Scanned in bulk rather than looked up, so every one of them is observable no
        // matter what the rules say. There are three OS/arch/format features in total and
        // the dynamic backend emits no Bytes at all, so keeping them costs nothing.
        case FeatureType::Bytes:
        case FeatureType::OS:
        case FeatureType::Arch:
        case FeatureType::Format:
            return true;

        // Injected during matching by index_rule_matches, not by an extractor, and
        // bounded by the number of rules. Dropping one would break the dependent rule
        // that is waiting for it.
        case FeatureType::MatchedRule:
            return true;

        // No extractor produces these -- they are the rule side of eval_substring /
        // eval_regex -- but a set that somehow held one is not ours to discard.
        case FeatureType::Substring:
        case FeatureType::Regex:
            return true;

        // Reachable exactly (`string: "..."`) *and* by scan (`substring:` / `regex:`),
        // so an exact-value test alone would be unsound.
        case FeatureType::String:
            return exact_.count(feature) != 0 || keep_string(feature.s);

        // Everything else -- api, number, offset, mnemonic, operand[n].*, import,
        // export, section, function-name, characteristic, property, class, namespace,
        // basic block -- is only ever reached through features.find(), by eval_feature's
        // default branch or by Range. If no rule names this exact value, nothing can ask.
        default:
            return exact_.count(feature) != 0;
    }
}

}  // namespace capa
