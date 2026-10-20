#include "result_document.h"

#include <algorithm>
#include <filesystem>
#include <system_error>

#include "match_retention.h"

namespace capa::render {

namespace {

// format / arch / os from the global features: the first of each, else "unknown".
void global_metadata(const std::vector<FeaturePair>& globals, Doc& doc, const std::string& input_format) {
    std::string format, arch, os;
    for (const auto& [f, addr] : globals) {
        if (f.type == FeatureType::Format && format.empty()) format = f.s;
        if (f.type == FeatureType::Arch && arch.empty()) arch = f.s;
        if (f.type == FeatureType::OS && os.empty()) os = f.s;
    }
    doc.format = format.empty() ? input_format : format;
    doc.arch = arch.empty() ? "unknown" : arch;
    doc.os = os.empty() ? "unknown" : os;
}

std::vector<std::string> resolved(const std::vector<std::string>& paths) {
    std::vector<std::string> out;
    for (const auto& p : paths) out.push_back(capa_path(p));
    return out;
}

// Every call address any node of `res` was located at (compute_dynamic_layout's
// result_rec).
void collect_calls(const Result& res, std::vector<Address>& out) {
    for (const Address& a : res.locations)
        if (a.type == AddressType::CALL) out.push_back(a);
    for (const Result& c : res.children) collect_calls(c, out);
}

}  // namespace

std::string capa_path(const std::string& path) {
    std::error_code ec;
    std::filesystem::path p = std::filesystem::weakly_canonical(std::filesystem::absolute(path, ec), ec);
    if (ec) return std::filesystem::path(path).generic_string();
    return p.generic_string();
}

Doc build_static_doc(const RuleSet& ruleset, const StaticFeatureExtractor& extractor,
                     const StaticCapabilities& caps, const std::string& extractor_name,
                     const std::vector<std::string>& rule_paths, const std::string& input_format) {
    Doc doc;
    doc.flavor = Flavor::Static;
    doc.extractor_name = extractor_name;
    doc.hashes = extractor.get_sample_hashes();
    global_metadata(extractor.extract_global_features(), doc, input_format);
    doc.rule_paths = resolved(rule_paths);
    doc.base_address = extractor.get_base_address();

    doc.file_feature_count = caps.feature_count;
    for (const FunctionInfo& f : caps.functions) doc.scope_feature_counts.emplace_back(f.address, f.feature_count);
    for (const LibraryFunction& lib : caps.library_functions) doc.library_functions.emplace_back(lib.address, lib.name);

    // compute_static_layout: the blocks any basic-block-scoped rule (subscope rules
    // included) matched at, grouped under their functions, in the extractor's order.
    AddressSet matched_bbs;
    for (const auto& [name, results] : caps.matches) {
        auto rule = ruleset.get(name);
        if (!rule || !rule->scopes.contains(Scope::BASIC_BLOCK)) continue;
        for (const auto& [addr, res] : results) matched_bbs.insert(addr);
    }
    if (!matched_bbs.empty()) {
        for (const FunctionHandle& fh : extractor.get_functions()) {
            StaticFunction f{fh.address, {}, {}};
            for (const BBHandle& bbh : extractor.get_basic_blocks(fh))
                if (matched_bbs.count(bbh.address)) f.matched_basic_blocks.push_back(bbh.address);
            if (!f.matched_basic_blocks.empty()) doc.static_layout.push_back(std::move(f));
        }
    }
    return doc;
}

Doc build_dynamic_doc(const RuleSet&, const DynamicFeatureExtractor& extractor,
                      const Capabilities& caps, const std::string& extractor_name,
                      const std::vector<std::string>& rule_paths, bool with_layout,
                      const std::string& input_format) {
    Doc doc;
    doc.flavor = Flavor::Dynamic;
    doc.extractor_name = extractor_name;
    doc.hashes = extractor.get_sample_hashes();
    global_metadata(extractor.extract_global_features(), doc, input_format);
    doc.rule_paths = resolved(rule_paths);

    doc.file_feature_count = caps.file_feature_count;
    doc.scope_feature_counts = caps.process_feature_counts;
    doc.feature_counts_filtered = caps.feature_counts_filtered;

    if (!with_layout) {
        doc.layout_omitted = true;
        doc.matches_only = true;
        return doc;
    }

    // compute_dynamic_layout: every call any match tree was located at. A tree that
    // `--max-match-trees` dropped is represented by its match address, the one location
    // still known for it.
    //
    // Collected and sorted in bulk rather than inserted one at a time: the addresses
    // arrive grouped by rule and so in no particular order overall, and hundreds of
    // thousands of positioned inserts into a flat container is quadratic.
    std::vector<Address> matched;
    for (const auto& [name, results] : caps.matches)
        for (const auto& [addr, evidence] : results) {
            if (evidence)
                collect_calls(*evidence, matched);
            else if (addr.type == AddressType::CALL)
                matched.push_back(addr);
        }
    std::sort(matched.begin(), matched.end());
    matched.erase(std::unique(matched.begin(), matched.end()), matched.end());

    for (const auto& ph : extractor.get_processes()) {
        DynProcess proc{ph.address, {}, {}};
        for (const auto& th : extractor.get_threads(ph)) {
            DynThread thread{th.address, {}};
            // Indexed rather than materialized: the walk keeps at most the few calls that
            // a rule matched at.
            const std::size_t calls = extractor.call_count(ph, th);
            for (std::size_t idx = 0; idx < calls; ++idx) {
                const CallHandle ch = extractor.call_at(ph, th, idx);
                if (!std::binary_search(matched.begin(), matched.end(), ch.address)) continue;
                thread.matched_calls.push_back({ch.address, extractor.get_call_name(ph, th, ch)});
            }
            if (!thread.matched_calls.empty()) proc.matched_threads.push_back(std::move(thread));
        }
        if (!proc.matched_threads.empty()) {
            proc.name = extractor.get_process_name(ph);
            doc.dyn_layout.push_back(std::move(proc));
        }
    }
    return doc;
}

}  // namespace capa::render
