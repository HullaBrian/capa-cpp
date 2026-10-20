#include "capabilities.h"

#include "match_retention.h"

#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iterator>
#include <optional>
#include <set>
#include <utility>

namespace capa {

namespace {

// index each match in `matches` back into `features` as MatchedRule features, so
// higher-scope / dependent rules can match on them.
void index_matches_into(const RuleSet& ruleset, FeatureSet& features,
                        const MatchResults& matches) {
    for (const auto& [name, results] : matches) {
        auto rule = ruleset.get(name);
        std::vector<std::string> ns = rule ? rule->namespace_prefixes() : std::vector<std::string>{};
        for (const auto& [addr, res] : results) {
            AddressSet loc{addr};
            index_rule_matches(features, name, ns, loc);
        }
    }
}

void merge_features(FeatureSet& dst, FeatureSet&& src, const FeatureFilter& filter) {
    // Moved, not copied. A match tree is not the only thing this walk duplicates: every
    // call contributes a FeatureSet whose keys are largely new -- the dynamic extractor
    // emits a `number` feature per integer argument, so pointers and handles arrive as
    // one fresh key each -- and copying them means allocating a second map node and a
    // second std::set for a container whose source dies on the next line.
    if (dst.empty() && !filter.enabled()) {
        dst = std::move(src);
        return;
    }
    for (auto& [f, locs] : src) {
        // The filter is what keeps this map a function of the ruleset rather than of the
        // trace: without it every distinct pointer value an API was ever called with
        // becomes a permanent key here. See feature_filter.h for why dropping them
        // cannot change a result.
        if (!filter.keep(f)) continue;
        auto [it, inserted] = dst.try_emplace(f, std::move(locs));
        // std::set::merge splices nodes across; it allocates nothing and leaves the
        // source empty, which is all this ever wanted from an insert.
        if (!inserted) it->second.merge(locs);
    }
    src.clear();
}

void merge_matches(MatchResults& dst, MatchResults&& src, MatchRetention& retention) {
    // Same reasoning as static_caps.cpp: a Result is a recursive tree carrying a
    // std::set at every node, and the dynamic walk copies the whole corpus up three
    // levels -- call to thread, thread to process, process to the final map -- so a
    // trace's matches are briefly resident three times over for no reason at all.
    for (auto& [name, results] : src) {
        auto& d = dst[name];
        // Deliberately no reserve(): the call-to-thread merge arrives one result at a
        // time, and reserving size()+1 each time pins capacity to the exact size and
        // reallocates on every single append -- quadratic, and each realloc moves a
        // vector of match trees. push_back's geometric growth is what this wants.
        for (auto& [addr, evidence] : results) {
            // The pair keeps its slot and its address whatever happens to the tree, so
            // the match count and every location stay exact; see match_retention.h.
            d.emplace_back(addr, retention.retain(name, std::move(evidence), d.size()));
        }
    }
    src.clear();
}

struct CallCapabilities {
    FeatureSet features;
    MatchResults matches;
};

CallCapabilities find_call_capabilities(const RuleSet& ruleset,
                                        const DynamicFeatureExtractor& extractor,
                                        const ProcessHandle& ph, const ThreadHandle& th,
                                        const CallHandle& ch) {
    FeatureSet features;
    for (const auto& [f, addr] : extractor.extract_call_features(ph, th, ch))
        features[f].insert(addr);
    for (const auto& [f, addr] : extractor.extract_global_features())
        features[f].insert(addr);

    MatchResults matches = ruleset.match(Scope::CALL, features, ch.address);
    index_matches_into(ruleset, features, matches);
    return {std::move(features), std::move(matches)};
}

// sliding window over the last SPAN_SIZE calls (capa SpanOfCallsMatcher)
class SpanOfCallsMatcher {
public:
    SpanOfCallsMatcher(const RuleSet& ruleset, std::size_t span_size)
        : ruleset_(ruleset), span_size_(span_size) {}

    void next(const CallHandle& ch, const FeatureSet& call_features) {
        if (window_.size() == span_size_) {
            FeatureSet overflowing = std::move(window_.front());
            window_.pop_front();
            for (const auto& [f, vas] : overflowing) {
                // ignore global features repeatedly added/removed (single NO_ADDRESS)
                if (vas.size() == 1 && vas.begin()->is_no_address()) continue;
                auto it = current_.find(f);
                if (it == current_.end()) continue;
                for (const auto& a : vas) it->second.erase(a);
                if (it->second.empty()) current_.erase(it);
            }
        }

        window_.push_back(call_features);
        for (const auto& [f, vas] : call_features) {
            auto& d = current_[f];
            d.insert(vas.begin(), vas.end());
        }

        MatchResults matches = ruleset_.match(Scope::SPAN_OF_CALLS, current_, ch.address);

        // suppress rules already emitted in the immediately preceding span, unless a
        // newly-encountered rule depends on the suppressed one.
        std::set<std::string> newly;
        for (const auto& [name, _r] : matches)
            if (!last_span_matches_.count(name)) newly.insert(name);

        std::set<std::string> suppressed = last_span_matches_;
        for (const auto& nr : newly)
            for (const auto& dep : ruleset_.dependencies_of(nr)) suppressed.erase(dep);

        // Moved, not copied: evidence is owned by a unique_ptr now, and the trees this
        // span produced have no other reader. The names are read again below, which a
        // move of the values leaves untouched.
        for (auto& [name, results] : matches) {
            if (suppressed.count(name)) continue;
            auto& d = matches_[name];
            d.insert(d.end(), std::make_move_iterator(results.begin()),
                     std::make_move_iterator(results.end()));
        }

        last_span_matches_.clear();
        for (const auto& [name, _r] : matches) last_span_matches_.insert(name);
    }

    // Hands over what it accumulated; the matcher is finished with by then. A copy is no
    // longer possible anyway now that evidence is uniquely owned.
    MatchResults take_matches() { return std::move(matches_); }

private:
    const RuleSet& ruleset_;
    std::size_t span_size_;
    std::deque<FeatureSet> window_;
    FeatureSet current_;
    std::set<std::string> last_span_matches_;
    MatchResults matches_;
};

struct ThreadCapabilities {
    FeatureSet features;
    MatchResults thread_matches;
    MatchResults span_matches;
    MatchResults call_matches;
};

ThreadCapabilities find_thread_capabilities(const RuleSet& ruleset,
                                            const DynamicFeatureExtractor& extractor,
                                            const ProcessHandle& ph, const ThreadHandle& th,
                                            const FeatureFilter& filter,
                                            MatchRetention& retention, bool top_level_calls,
                                            std::size_t span_size) {
    FeatureSet features;
    MatchResults call_matches;
    SpanOfCallsMatcher span_matcher(ruleset, span_size);

    // Return position of the top-level call running at the current point, if any. A TTD
    // report holds every call a thread made, including the ones an API made while carrying
    // out a call from the program. capa's dynamic rules are written against sandbox logs of
    // the program's calls, and a span counts calls: the nested ones push apart the pair a rule
    // needs (the sample's socket and connect, say) and add findings about Windows' own work.
    // A call that never returned encloses nothing, so one lost return cannot silence the rest
    // of a thread.
    std::optional<std::pair<std::uint64_t, std::uint64_t>> open;

    const std::size_t call_count = extractor.call_count(ph, th);
    for (std::size_t idx = 0; idx < call_count; ++idx) {
        const CallHandle ch = extractor.call_at(ph, th, idx);
        if (top_level_calls) {
            if (const auto span = extractor.get_call_span(ph, th, ch)) {
                if (open && *open <= span->position) open.reset();
                if (open) continue;  // made inside another recorded call
                open = span->return_position;
            }
        }
        CallCapabilities cc = find_call_capabilities(ruleset, extractor, ph, th, ch);
        // The span matcher keeps its own copy for the sliding window, so it goes first
        // and the thread-wide merge -- the one whose keys are nearly all new -- gets the
        // move. The two are independent; only the order of the last use matters.
        span_matcher.next(ch, cc.features);
        merge_matches(call_matches, std::move(cc.matches), retention);
        merge_features(features, std::move(cc.features), filter);
    }

    for (const auto& [f, addr] : extractor.extract_thread_features(ph, th)) features[f].insert(addr);
    for (const auto& [f, addr] : extractor.extract_global_features()) features[f].insert(addr);

    MatchResults matches = ruleset.match(Scope::THREAD, features, th.address);
    index_matches_into(ruleset, features, matches);

    return {std::move(features), std::move(matches), span_matcher.take_matches(),
            std::move(call_matches)};
}

struct ProcessCapabilities {
    MatchResults process_matches;
    MatchResults thread_matches;
    MatchResults span_matches;
    MatchResults call_matches;
    std::size_t feature_count = 0;
    std::size_t location_count = 0;  // diagnostic; see Capabilities::peak_scope_locations
};

// How many addresses a scope's feature set is holding, across every feature in it.
std::size_t count_locations(const FeatureSet& features) {
    std::size_t n = 0;
    for (const auto& [f, locs] : features) n += locs.size();
    return n;
}

ProcessCapabilities find_process_capabilities(const RuleSet& ruleset,
                                              const DynamicFeatureExtractor& extractor,
                                              const ProcessHandle& ph,
                                              const FeatureFilter& filter,
                                              MatchRetention& retention, bool top_level_calls,
                                              std::size_t span_size) {
    FeatureSet process_features;
    MatchResults thread_matches, span_matches, call_matches;

    for (const auto& th : extractor.get_threads(ph)) {
        ThreadCapabilities tc =
            find_thread_capabilities(ruleset, extractor, ph, th, filter, retention,
                                     top_level_calls, span_size);
        merge_features(process_features, std::move(tc.features), filter);
        merge_matches(thread_matches, std::move(tc.thread_matches), retention);
        merge_matches(span_matches, std::move(tc.span_matches), retention);
        merge_matches(call_matches, std::move(tc.call_matches), retention);
    }

    for (const auto& [f, addr] : extractor.extract_process_features(ph)) process_features[f].insert(addr);
    for (const auto& [f, addr] : extractor.extract_global_features()) process_features[f].insert(addr);

    MatchResults process_matches = ruleset.match(Scope::PROCESS, process_features, ph.address);

    const std::size_t features = process_features.size();
    const std::size_t locations = count_locations(process_features);
    return {std::move(process_matches), std::move(thread_matches), std::move(span_matches),
            std::move(call_matches), features, locations};
}

// find_file_capabilities from capabilities/common.py
struct FileCapabilities {
    MatchResults matches;
    std::size_t feature_count = 0;
};

FileCapabilities find_file_capabilities(const RuleSet& ruleset,
                                        const DynamicFeatureExtractor& extractor,
                                        FeatureSet&& function_features,
                                        const FeatureFilter& filter) {
    FeatureSet file_features;
    for (const auto& [f, addr] : extractor.extract_file_features()) {
        if (addr.is_no_address()) {
            file_features.try_emplace(f);  // ensure present with empty location set
        } else {
            file_features[f].insert(addr);
        }
    }
    for (const auto& [f, addr] : extractor.extract_global_features()) {
        if (addr.is_no_address())
            file_features.try_emplace(f);
        else
            file_features[f].insert(addr);
    }

    merge_features(file_features, std::move(function_features), filter);
    // capa counts file features AFTER merging in the process-and-lower match features.
    std::size_t count = file_features.size();

    MatchResults matches = ruleset.match(Scope::FILE, file_features, Address::no_address());
    return {std::move(matches), count};
}

}  // namespace

Capabilities find_dynamic_capabilities(const RuleSet& ruleset,
                                       const DynamicFeatureExtractor& extractor,
                                       const FeatureFilter& filter,
                                       std::size_t max_match_trees,
                                       bool keep_evidence_leaves,
                                       bool top_level_calls,
                                       std::size_t span_size) {
    MatchRetention retention(max_match_trees, keep_evidence_leaves);
    MatchResults all_process, all_thread, all_span, all_call;
    Capabilities caps;

    for (const auto& ph : extractor.get_processes()) {
        ProcessCapabilities pc =
            find_process_capabilities(ruleset, extractor, ph, filter, retention, top_level_calls,
                                      span_size);
        caps.process_feature_counts.emplace_back(ph.address, pc.feature_count);
        caps.peak_scope_features = std::max(caps.peak_scope_features, pc.feature_count);
        caps.peak_scope_locations = std::max(caps.peak_scope_locations, pc.location_count);
        merge_matches(all_process, std::move(pc.process_matches), retention);
        merge_matches(all_thread, std::move(pc.thread_matches), retention);
        merge_matches(all_span, std::move(pc.span_matches), retention);
        merge_matches(all_call, std::move(pc.call_matches), retention);
    }

    // build the feature set of all process-and-lower matches, so file-scope rules can
    // match: on them.
    FeatureSet process_and_lower;
    for (const MatchResults* mr : {&all_process, &all_thread, &all_span, &all_call}) {
        for (const auto& [name, results] : *mr) {
            AddressSet locations;
            for (const auto& [addr, res] : results) locations.insert(addr);
            auto rule = ruleset.get(name);
            std::vector<std::string> ns =
                rule ? rule->namespace_prefixes() : std::vector<std::string>{};
            index_rule_matches(process_and_lower, name, ns, locations);
        }
    }

    FileCapabilities file_caps =
        find_file_capabilities(ruleset, extractor, std::move(process_and_lower), filter);
    caps.file_feature_count = file_caps.feature_count;
    caps.feature_counts_filtered = filter.enabled();

    // Merge all matches (each rule lives in exactly one scope, so no key collisions).
    // Moved rather than copied, and each source cleared as it is drained: this is the
    // last of the three levels that used to duplicate the whole match corpus, and it is
    // the one where the corpus is largest. Everything here has already passed through
    // retention on the way up.
    for (MatchResults* mr : {&all_call, &all_span, &all_thread, &all_process}) {
        for (auto& [name, results] : *mr) {
            auto& d = caps.matches[name];
            d.insert(d.end(), std::make_move_iterator(results.begin()),
                     std::make_move_iterator(results.end()));
        }
        mr->clear();
    }

    // File-scope matches are produced after the last merge, so they are the one set that
    // has not been through retention. It matters for more than the cap: a file-scope rule
    // is mostly `match:` features naming the process- and call-scope rules that make it
    // up, and those names are how a renderer knows not to list a subrule as a capability
    // of its own. Collected from every other scope but not this one, the set was missing
    // exactly the rules most likely to be in it.
    merge_matches(caps.matches, std::move(file_caps.matches), retention);

    caps.subrule_matches = retention.subrule_matches();
    caps.truncated_matches = retention.truncated();
    return caps;
}

}  // namespace capa
