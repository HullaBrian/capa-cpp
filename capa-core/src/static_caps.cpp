#include "static_caps.h"

#include <iterator>
#include <set>
#include <utility>

namespace capa {

namespace {

// index each match in `matches` back into `features` as MatchedRule features, so
// higher-scope / dependent rules can match on them (capa.engine.index_rule_matches).
void index_matches_into(const RuleSet& ruleset, FeatureSet& features,
                        const MatchResults& matches) {
    for (const auto& [name, results] : matches) {
        auto rule = ruleset.get(name);
        std::vector<std::string> ns =
            rule ? rule->namespace_prefixes() : std::vector<std::string>{};
        AddressSet locs;
        for (const auto& [addr, res] : results) locs.insert(addr);
        index_rule_matches(features, name, ns, locs);
    }
}

void merge_features(FeatureSet& dst, const FeatureSet& src, const FeatureFilter& filter) {
    // Filtered on the way up, for the same reason the dynamic walk filters: an
    // instruction contributes a `number`/`offset` feature per operand, and a
    // module-sized region has millions of distinct ones that no rule can name. See
    // feature_filter.h for why dropping them cannot change a match.
    for (const auto& [f, locs] : src) {
        if (!filter.keep(f)) continue;
        dst[f].insert(locs.begin(), locs.end());
    }
}

// Moved, not copied: evidence is uniquely owned, and every caller here is draining a
// scope's results on the way up and has no further use for them.
void merge_matches(MatchResults& dst, MatchResults&& src) {
    for (auto& [name, results] : src) {
        auto& d = dst[name];
        d.insert(d.end(), std::make_move_iterator(results.begin()),
                 std::make_move_iterator(results.end()));
    }
    src.clear();
}

struct ScopeCaps {
    FeatureSet features;
    MatchResults matches;
};

ScopeCaps find_instruction_capabilities(const RuleSet& ruleset,
                                        const StaticFeatureExtractor& ex,
                                        const FunctionHandle& fh, const BBHandle& bbh,
                                        const InsnHandle& ih) {
    FeatureSet features;
    for (const auto& [feat, addr] : ex.extract_insn_features(fh, bbh, ih))
        features[feat].insert(addr);
    for (const auto& [feat, addr] : ex.extract_global_features()) features[feat].insert(addr);

    MatchResults matches = ruleset.match(Scope::INSTRUCTION, features, ih.address);
    index_matches_into(ruleset, features, matches);
    return {std::move(features), std::move(matches)};
}

struct BbCaps {
    FeatureSet features;
    MatchResults bb_matches;
    MatchResults insn_matches;
};

BbCaps find_basic_block_capabilities(const RuleSet& ruleset, const StaticFeatureExtractor& ex,
                                     const FunctionHandle& fh, const BBHandle& bbh,
                                     const FeatureFilter& filter) {
    FeatureSet features;
    MatchResults insn_matches;

    for (const InsnHandle& ih : ex.get_instructions(fh, bbh)) {
        ScopeCaps ic = find_instruction_capabilities(ruleset, ex, fh, bbh, ih);
        merge_features(features, ic.features, filter);
        merge_matches(insn_matches, std::move(ic.matches));
    }

    for (const auto& [feat, addr] : ex.extract_basic_block_features(fh, bbh))
        features[feat].insert(addr);
    for (const auto& [feat, addr] : ex.extract_global_features()) features[feat].insert(addr);

    MatchResults matches = ruleset.match(Scope::BASIC_BLOCK, features, bbh.address);
    index_matches_into(ruleset, features, matches);
    return {std::move(features), std::move(matches), std::move(insn_matches)};
}

struct CodeCaps {
    MatchResults function_matches;
    MatchResults bb_matches;
    MatchResults insn_matches;
    std::size_t feature_count = 0;
};

CodeCaps find_code_capabilities(const RuleSet& ruleset, const StaticFeatureExtractor& ex,
                                const FunctionHandle& fh, const FeatureFilter& filter) {
    FeatureSet function_features;
    MatchResults bb_matches, insn_matches;

    for (const BBHandle& bbh : ex.get_basic_blocks(fh)) {
        BbCaps bc = find_basic_block_capabilities(ruleset, ex, fh, bbh, filter);
        merge_features(function_features, bc.features, filter);
        merge_matches(bb_matches, std::move(bc.bb_matches));
        merge_matches(insn_matches, std::move(bc.insn_matches));
    }

    for (const auto& [feat, addr] : ex.extract_function_features(fh))
        function_features[feat].insert(addr);
    for (const auto& [feat, addr] : ex.extract_global_features())
        function_features[feat].insert(addr);

    MatchResults function_matches = ruleset.match(Scope::FUNCTION, function_features, fh.address);
    return {std::move(function_matches), std::move(bb_matches), std::move(insn_matches),
            function_features.size()};
}

// find_file_capabilities (capabilities/common.py), static flavor.
struct FileCaps {
    MatchResults matches;
    std::size_t feature_count = 0;
};

FileCaps find_file_capabilities(const RuleSet& ruleset, const StaticFeatureExtractor& ex,
                                const FeatureSet& function_and_lower,
                                const FeatureFilter& filter) {
    FeatureSet file_features;
    for (const auto& [feat, addr] : ex.extract_file_features()) {
        if (addr.is_no_address())
            file_features.try_emplace(feat);
        else
            file_features[feat].insert(addr);
    }
    for (const auto& [feat, addr] : ex.extract_global_features()) {
        if (addr.is_no_address())
            file_features.try_emplace(feat);
        else
            file_features[feat].insert(addr);
    }
    merge_features(file_features, function_and_lower, filter);
    std::size_t count = file_features.size();

    MatchResults matches = ruleset.match(Scope::FILE, file_features, Address::no_address());
    return {std::move(matches), count};
}

}  // namespace

StaticCapabilities find_static_capabilities(const RuleSet& ruleset,
                                            const StaticFeatureExtractor& ex,
                                            const FeatureFilter& filter) {
    MatchResults all_function, all_bb, all_insn;
    StaticCapabilities caps;

    std::vector<FunctionHandle> functions = ex.get_functions();
    for (const FunctionHandle& fh : functions) {
        if (ex.is_library_function(fh.address)) {
            caps.library_functions.push_back({fh.address, ex.get_function_name(fh.address)});
            continue;
        }
        CodeCaps cc = find_code_capabilities(ruleset, ex, fh, filter);

        // layout: the basic blocks within this function that a rule matched at.
        AddressSet bbs;
        for (const auto& [name, results] : cc.bb_matches)
            for (const auto& [addr, res] : results) bbs.insert(addr);
        caps.functions.push_back(
            {fh.address, cc.feature_count, std::vector<Address>(bbs.begin(), bbs.end())});

        merge_matches(all_function, std::move(cc.function_matches));
        merge_matches(all_bb, std::move(cc.bb_matches));
        merge_matches(all_insn, std::move(cc.insn_matches));
    }

    // feature set of all function-and-lower matches, so file-scope rules can match on them.
    FeatureSet function_and_lower;
    for (const MatchResults* mr : {&all_function, &all_bb, &all_insn}) {
        for (const auto& [name, results] : *mr) {
            AddressSet locs;
            for (const auto& [addr, res] : results) locs.insert(addr);
            auto rule = ruleset.get(name);
            std::vector<std::string> ns =
                rule ? rule->namespace_prefixes() : std::vector<std::string>{};
            index_rule_matches(function_and_lower, name, ns, locs);
        }
    }

    FileCaps file_caps = find_file_capabilities(ruleset, ex, function_and_lower, filter);

    caps.function_count = functions.size();
    caps.feature_count = file_caps.feature_count;
    // Move rather than copy: a match tree is a recursive Result with a std::set and a
    // std::map at every node, so copying the four scopes into one map briefly doubles
    // the memory a whole region's matches occupy. On a large module that is hundreds
    // of megabytes for no reason -- the sources are dead the moment this loop ends.
    for (MatchResults* mr : {&all_insn, &all_bb, &all_function, &file_caps.matches}) {
        for (auto& [name, results] : *mr) {
            auto& d = caps.matches[name];
            d.insert(d.end(), std::make_move_iterator(results.begin()),
                     std::make_move_iterator(results.end()));
        }
        mr->clear();
    }
    return caps;
}

}  // namespace capa
