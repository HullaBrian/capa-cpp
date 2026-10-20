#include "analysis.h"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <exception>
#include <map>
#include <set>

#include "ida/extractor.h"
#include "plugin.h"
#include "rules.h"
#include "settings.h"
#include "static_caps.h"

using nlohmann::json;

namespace idacapa {

namespace {

// ---------------------------------------------------------------------------
// progress + cancellation
// ---------------------------------------------------------------------------

// A StaticFeatureExtractor that wraps the real one and lets the user abort. The
// driver has no cancellation hook of its own, so the throw unwinds out of it; the
// caches it mutates are per-run and thrown away with the extractor.
struct Cancelled {};

class ProgressExtractor : public capa::StaticFeatureExtractor {
public:
    explicit ProgressExtractor(const capa::ida::IdaExtractor& inner) : inner_(inner) {}

    capa::Address get_base_address() const override { return inner_.get_base_address(); }
    const capa::SampleHashes& get_sample_hashes() const override {
        return inner_.get_sample_hashes();
    }
    const std::vector<capa::FeaturePair>& extract_global_features() const override {
        return inner_.extract_global_features();
    }
    std::vector<capa::FeaturePair> extract_file_features() const override {
        return inner_.extract_file_features();
    }

    std::vector<capa::FunctionHandle> get_functions() const override {
        std::vector<capa::FunctionHandle> fns = inner_.get_functions();
        total_ = fns.size();
        return fns;
    }

    std::vector<capa::FeaturePair> extract_function_features(
        const capa::FunctionHandle& fh) const override {
        // Called once per function, at the end of that function's walk: the natural
        // place to report progress and check for a cancel.
        ++done_;
        if (user_cancelled()) throw Cancelled{};
        char buf[128];
        qsnprintf(buf, sizeof(buf), "capa: analysing function %llu of %llu ...",
                  static_cast<unsigned long long>(done_),
                  static_cast<unsigned long long>(total_));
        replace_wait_box("%s", buf);
        return inner_.extract_function_features(fh);
    }

    std::vector<capa::BBHandle> get_basic_blocks(const capa::FunctionHandle& fh) const override {
        return inner_.get_basic_blocks(fh);
    }
    std::vector<capa::FeaturePair> extract_basic_block_features(
        const capa::FunctionHandle& fh, const capa::BBHandle& bbh) const override {
        return inner_.extract_basic_block_features(fh, bbh);
    }
    std::vector<capa::InsnHandle> get_instructions(const capa::FunctionHandle& fh,
                                                   const capa::BBHandle& bbh) const override {
        return inner_.get_instructions(fh, bbh);
    }
    std::vector<capa::FeaturePair> extract_insn_features(
        const capa::FunctionHandle& fh, const capa::BBHandle& bbh,
        const capa::InsnHandle& ih) const override {
        return inner_.extract_insn_features(fh, bbh, ih);
    }

    bool is_library_function(const capa::Address& a) const override {
        return inner_.is_library_function(a);
    }
    std::string get_function_name(const capa::Address& a) const override {
        return inner_.get_function_name(a);
    }

private:
    const capa::ida::IdaExtractor& inner_;
    mutable std::size_t total_ = 0;
    mutable std::size_t done_ = 0;
};

// ---------------------------------------------------------------------------
// display strings (capa/ida/plugin/{model,item}.py)
// ---------------------------------------------------------------------------

std::string fmt(const char* format, ...) {
    char buf[512];
    va_list va;
    va_start(va, format);
    qvsnprintf(buf, sizeof(buf), format, va);
    va_end(va);
    return buf;
}

// IDA's own name for an address: "loc_401000". At least eight hex digits, as capa's
// "loc_%08X" gives, but never truncated — a 64-bit image base would otherwise render a
// block at 0x140001000 as loc_40001000, an address that does not exist.
std::string loc_name(ea_t ea) {
    char buf[32];
    qsnprintf(buf, sizeof(buf), "loc_%08llX", static_cast<unsigned long long>(ea));
    return buf;
}

// capa's helpers.get_disasm_line(): the disassembly text, forced even for data.
std::string disasm_for_details(ea_t ea) {
    qstring line;
    if (!generate_disasm_line(&line, ea, GENDSM_FORCE_CODE)) return {};
    qstring plain;
    tag_remove(&plain, line);
    return plain.c_str();
}

// capa's CapaExplorerByteViewItem: 32 bytes at the location, hex, space separated.
std::string bytes_for_details(ea_t ea) {
    std::vector<std::uint8_t> buf(32);
    ssize_t got = get_bytes(buf.data(), static_cast<ssize_t>(buf.size()), ea);
    if (got <= 0) return {};
    static const char* digits = "0123456789ABCDEF";
    std::string out;
    for (ssize_t i = 0; i < got; ++i) {
        if (i) out.push_back(' ');
        out.push_back(digits[buf[i] >> 4]);
        out.push_back(digits[buf[i] & 0xf]);
    }
    return out;
}

// capa_doc_feature_to_display(): "key(value)", "key(value = description)" or "key".
std::string feature_to_display(const capa::Feature& f) {
    const std::string key = f.get_name_str();
    const std::string value = f.get_value_str();
    if (value.empty()) return key;
    if (!f.description.empty()) return key + "(" + value + " = " + f.description + ")";
    return key + "(" + value + ")";
}

ea_t ea_of(const capa::Address& a) {
    return a.type == capa::AddressType::ABSOLUTE || a.type == capa::AddressType::FILE_OFFSET
               ? static_cast<ea_t>(a.value)
               : BADADDR;
}

// ---------------------------------------------------------------------------
// tree building (model.py::render_capa_doc_*)
// ---------------------------------------------------------------------------

struct TreeBuilder {
    // render_capa_doc_feature(): one row for one feature at one location. The item
    // class capa picks decides what goes in the Details column and whether the row is
    // one of the highlightable ones.
    ResultNode feature_node(const capa::Result& res, const capa::Feature& f,
                            const capa::Address& loc, const std::string& display) {
        ResultNode n;
        n.kind = NodeKind::Feature;
        n.info = display;
        n.address = ea_of(loc);

        switch (f.type) {
            case capa::FeatureType::Characteristic: {
                if (f.s == "embedded pe") {  // ByteViewItem
                    n.details = bytes_for_details(n.address);
                    n.highlightable = n.address != BADADDR;
                } else if (f.s == "loop" || f.s == "recursive call" || f.s == "tight loop") {
                    n.address = BADADDR;  // plain FeatureItem: no location shown
                } else {  // InstructionViewItem
                    n.details = disasm_for_details(n.address);
                    n.highlightable = n.address != BADADDR;
                }
                break;
            }
            case capa::FeatureType::MatchedRule:
                n.kind = NodeKind::RuleMatch;
                n.address = BADADDR;
                break;

            case capa::FeatureType::Regex:
            case capa::FeatureType::Substring: {
                // StringViewItem: the Details column shows the string that matched at
                // this location, which lives in the result's captures.
                for (const auto& [capture, addrs] : res.captures) {
                    if (addrs.count(loc)) {
                        n.details = "\"" + capture + "\"";
                        break;
                    }
                }
                n.highlightable = n.address != BADADDR;
                break;
            }
            case capa::FeatureType::BasicBlock:
                n.kind = NodeKind::BasicBlock;
                n.info = "basic block(" + loc_name(n.address) + ")";
                break;

            case capa::FeatureType::Bytes:
            case capa::FeatureType::API:
            case capa::FeatureType::Mnemonic:
            case capa::FeatureType::Number:
            case capa::FeatureType::Offset:
            case capa::FeatureType::OperandNumber:
            case capa::FeatureType::OperandOffset:
                n.details = disasm_for_details(n.address);
                n.highlightable = n.address != BADADDR;
                break;

            case capa::FeatureType::Section:
                n.details = bytes_for_details(n.address);
                n.highlightable = n.address != BADADDR;
                break;

            case capa::FeatureType::String:
                n.details = "\"" + f.s + "\"";
                n.highlightable = n.address != BADADDR;
                break;

            case capa::FeatureType::Import:
            case capa::FeatureType::Export:
            case capa::FeatureType::FunctionName:
                break;  // location, no preview

            case capa::FeatureType::Arch:
            case capa::FeatureType::OS:
            case capa::FeatureType::Format:
                n.address = BADADDR;  // global: no location
                break;

            default:
                break;
        }
        return n;
    }

    // render_capa_doc_feature_node(): one location renders inline, several nest under
    // a parent row carrying the feature's display text.
    ResultNode feature_subtree(const capa::Result& res, const capa::Feature& f) {
        const std::string display = feature_to_display(f);

        if (res.locations.size() == 1)
            return feature_node(res, f, *res.locations.begin(), display);

        ResultNode parent;
        parent.kind = f.type == capa::FeatureType::MatchedRule ? NodeKind::RuleMatch
                                                               : NodeKind::Feature;
        parent.info = display;
        if (f.type != capa::FeatureType::MatchedRule)
            for (const capa::Address& loc : res.locations)  // std::set: already sorted
                parent.children.push_back(feature_node(res, f, loc, display));
        return parent;
    }

    // render_capa_doc_statement_node()
    ResultNode statement_node(const capa::Result& res, const capa::Statement& s) {
        ResultNode n;
        n.kind = NodeKind::Statement;

        switch (s.type) {
            case capa::StatementType::And: n.info = "and"; break;
            case capa::StatementType::Or: n.info = "or"; break;
            case capa::StatementType::Not: n.info = "not"; break;
            case capa::StatementType::Some:
                n.info = s.count == 0 ? "optional" : fmt("%d or more", s.count);
                break;
            case capa::StatementType::Subscope:
                n.kind = NodeKind::Subscope;
                n.info = "subscope(" + capa::scope_to_string(s.subscope) + ")";
                break;
            case capa::StatementType::Range: {
                // range is almost a hybrid of statement and feature: a feature repeated
                // a number of times, so its own children are that feature's locations.
                std::string display = "count(" + feature_to_display(s.range_child) + "): ";
                const std::uint64_t umax = ~0ull;
                if (static_cast<std::uint64_t>(s.range_min) == s.range_max)
                    display += std::to_string(s.range_min);
                else if (s.range_min == 0)
                    display += std::to_string(s.range_max) + " or fewer";
                else if (s.range_max == umax)
                    display += std::to_string(s.range_min) + " or more";
                else
                    display += "between " + std::to_string(s.range_min) + " and " +
                               std::to_string(s.range_max);
                if (!s.description.empty()) display += " (" + s.description + ")";

                n.kind = NodeKind::Feature;
                n.info = display;
                for (const capa::Address& loc : res.locations)
                    n.children.push_back(
                        feature_node(res, s.range_child, loc, feature_to_display(s.range_child)));
                return n;
            }
        }

        if (!s.description.empty()) n.info += " (" + s.description + ")";
        return n;
    }

    // render_capa_doc_match(): failed branches are not shown, and an `optional` with
    // no successful children is nothing at all.
    bool match_node(const capa::Result& res, ResultNode& out) {
        if (!res.success) return false;

        if (res.node_is_statement && res.stmt->type == capa::StatementType::Some &&
            res.stmt->count == 0) {
            bool any = false;
            for (const capa::Result& c : res.children)
                if (c.success) { any = true; break; }
            if (!any) return false;
        }

        out = res.node_is_statement ? statement_node(res, *res.stmt)
                                    : feature_subtree(res, res.feature);

        for (const capa::Result& child : res.children) {
            ResultNode n;
            if (match_node(child, n)) out.children.push_back(std::move(n));
        }
        return true;
    }
};

std::string scope_name(const capa::Rule& rule) {
    if (rule.scopes.static_scope) return capa::scope_to_string(*rule.scopes.static_scope);
    if (rule.scopes.dynamic_scope) return capa::scope_to_string(*rule.scopes.dynamic_scope);
    return "file";
}

}  // namespace

// ---------------------------------------------------------------------------
// serialization
// ---------------------------------------------------------------------------

namespace {

json node_to_json(const ResultNode& n) {
    json j;
    j["k"] = static_cast<int>(n.kind);
    j["i"] = n.info;
    if (!n.details.empty()) j["d"] = n.details;
    if (n.address != BADADDR) j["a"] = static_cast<std::uint64_t>(n.address);
    if (n.highlightable) j["h"] = true;
    if (!n.children.empty()) {
        json arr = json::array();
        for (const ResultNode& c : n.children) arr.push_back(node_to_json(c));
        j["c"] = std::move(arr);
    }
    return j;
}

ResultNode node_from_json(const json& j) {
    ResultNode n;
    n.kind = static_cast<NodeKind>(j.value("k", 0));
    n.info = j.value("i", "");
    n.details = j.value("d", "");
    n.address = j.contains("a") ? static_cast<ea_t>(j["a"].get<std::uint64_t>()) : BADADDR;
    n.highlightable = j.value("h", false);
    for (const json& c : j.value("c", json::array())) n.children.push_back(node_from_json(c));
    return n;
}

}  // namespace

std::string ResultsDoc::to_json() const {
    json j;
    j["version"] = RESULTS_CACHE_VERSION;
    j["rules_dir"] = rules_dir;
    j["skipped_note"] = skipped_note;
    j["function_count"] = function_count;
    j["feature_count"] = feature_count;
    j["rules_loaded"] = rules_loaded;
    j["match_count"] = match_count;
    json arr = json::array();
    for (const ResultNode& r : rules) arr.push_back(node_to_json(r));
    j["rules"] = std::move(arr);
    return j.dump();
}

ResultsDoc ResultsDoc::from_json(const std::string& text) {
    ResultsDoc doc;
    if (text.empty()) return doc;
    json j;
    try {
        j = json::parse(text);
    } catch (const std::exception&) {
        return doc;  // corrupt: ignored
    }

    // A cache from an older build parses fine but describes a different structure, so
    // reading it would silently yield a tree of empty nodes. Only a version we wrote
    // ourselves is trustworthy.
    if (j.value("version", 0) != RESULTS_CACHE_VERSION) {
        msg("capa: ignoring cached results written by a different version of the plugin; "
            "re-run the analysis.\n");
        return doc;
    }

    doc.valid = true;
    doc.rules_dir = j.value("rules_dir", "");
    doc.skipped_note = j.value("skipped_note", "");
    doc.function_count = j.value("function_count", std::size_t{0});
    doc.feature_count = j.value("feature_count", std::size_t{0});
    doc.rules_loaded = j.value("rules_loaded", std::size_t{0});
    doc.match_count = j.value("match_count", std::size_t{0});
    for (const json& jr : j.value("rules", json::array()))
        doc.rules.push_back(node_from_json(jr));

    // Belt and braces on top of the version check. A cache whose node shape differs
    // still parses as perfectly valid JSON -- every key lookup simply misses and every
    // field comes back empty, which reaches the user as a window full of nameless
    // rows. A rule node with no name cannot be right, so treat the whole cache as
    // unreadable rather than show it.
    for (const ResultNode& r : doc.rules) {
        if (r.info.empty()) {
            msg("capa: cached results are unreadable (a rule row has no name); "
                "discarding them, re-run the analysis.\n");
            return ResultsDoc{};
        }
    }
    return doc;
}

// ---------------------------------------------------------------------------
// "show results by function"
// ---------------------------------------------------------------------------

std::string strip_match_count(const std::string& label) {
    static const std::string suffix = " matches)";
    if (label.size() <= suffix.size()) return label;
    if (label.compare(label.size() - suffix.size(), suffix.size(), suffix) != 0) return label;
    std::size_t open = label.rfind(" (");
    return open == std::string::npos ? label : label.substr(0, open);
}

ResultsDoc group_by_function(const ResultsDoc& doc) {
    ResultsDoc out;
    out.valid = doc.valid;
    out.rules_dir = doc.rules_dir;
    out.function_count = doc.function_count;
    out.feature_count = doc.feature_count;
    out.rules_loaded = doc.rules_loaded;
    out.match_count = doc.match_count;

    // The explorer files rules into folders by `details`, which normally holds the
    // namespace. Grouping by function means handing it the function's name there
    // instead — same tree machinery, different shelving — and splitting each rule into
    // one node per function so a rule that matched in three of them appears in three
    // folders, carrying only that function's matches.
    std::vector<std::pair<ea_t, ResultNode>> grouped;

    for (const ResultNode& rule : doc.rules) {
        // The rule's label counts its matches across the whole program; each split-off
        // node lists only one function's, so the count is recomputed below.
        const std::string bare_name = strip_match_count(rule.info);

        std::map<ea_t, ResultNode> per_func;
        for (const ResultNode& scope : rule.children) {
            if (scope.address == BADADDR) continue;
            ea_t fea = capa::ida::func_start_of(scope.address);
            if (fea == BADADDR) continue;  // match is not inside a defined function

            auto it = per_func.find(fea);
            if (it == per_func.end()) {
                ResultNode r = rule;
                r.children.clear();
                r.info = bare_name;
                r.details = "function(" + capa::ida::get_ea_name(fea) + ")";
                it = per_func.emplace(fea, std::move(r)).first;
            }
            it->second.children.push_back(scope);
        }
        for (auto& [fea, node] : per_func) {
            if (node.children.size() > 1)
                node.info = bare_name + " (" + std::to_string(node.children.size()) + " matches)";
            grouped.emplace_back(fea, std::move(node));
        }
    }

    std::sort(grouped.begin(), grouped.end(), [](const auto& a, const auto& b) {
        if (a.first != b.first) return a.first < b.first;
        return a.second.info < b.second.info;
    });
    for (auto& [fea, node] : grouped) out.rules.push_back(std::move(node));
    return out;
}

// ---------------------------------------------------------------------------
// analysis
// ---------------------------------------------------------------------------

bool database_is_dotnet() {
    // A managed assembly imports exactly one thing from mscoree.dll (_CorExeMain or
    // _CorDllMain), which is the cheapest reliable tell from inside IDA.
    uint n = get_import_module_qty();
    for (uint i = 0; i < n; ++i) {
        qstring modname;
        if (!get_import_module_name(&modname, static_cast<int>(i))) continue;
        std::string lower = modname.c_str();
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == "mscoree.dll" || lower == "mscoree") return true;
    }
    return false;
}

bool database_is_supported(std::string& why_not) {
    filetype_t ft = inf_get_filetype();
    if (ft != f_PE && ft != f_ELF && ft != f_BIN && ft != f_COFF) {
        why_not = "capa supports PE, ELF, COFF and raw binary files only.";
        return false;
    }
    if (!capa::ida::is_metapc()) {
        why_not = "capa's IDA backend supports x86 and x86-64 only (processor is '" +
                  std::string(inf_get_procname().c_str()) + "').";
        return false;
    }
    if (!capa::ida::is_64bit() && !capa::ida::is_32bit()) {
        why_not = "capa's IDA backend supports 32- and 64-bit code only.";
        return false;
    }
    return true;
}

bool run_analysis(const std::string& rules_dir, ResultsDoc& out, std::string& error) {
    error.clear();
    out = ResultsDoc{};
    out.rules_dir = rules_dir;

    msg("capa: analysis starting (build %s)\n", BUILD_STAMP);
    show_wait_box("capa: loading rules ...");
    struct WaitBoxGuard {
        ~WaitBoxGuard() { hide_wait_box(); }
    } guard;

    capa::RuleSet ruleset;
    try {
        ruleset = capa::RuleSet::load_from_directory(rules_dir);
    } catch (const capa::InvalidRule& e) {
        error = "could not load rules: " + e.message;
        return false;
    } catch (const std::exception& e) {
        error = std::string("could not load rules: ") + e.what();
        return false;
    }
    out.rules_loaded = ruleset.source_rule_count();

    if (user_cancelled()) return false;
    replace_wait_box("capa: extracting features ...");

    capa::StaticCapabilities caps;
    try {
        // Inside the try: the constructor does real work — global features, the import
        // and extern tables — any of which can throw, and an exception escaping here
        // would unwind into IDA's action dispatch instead of being reported.
        capa::ida::IdaExtractor extractor(/*skip_system_modules=*/!scan_system_modules());
        ProgressExtractor progress(extractor);
        // Built from the loaded rules, so the extracted features that no rule can look at
        // are dropped as they are merged upward. Every other caller of this entry point
        // does the same; see feature_filter.h for why it cannot change a result.
        const capa::FeatureFilter filter = capa::FeatureFilter::from_ruleset(ruleset);
        caps = capa::find_static_capabilities(ruleset, progress, filter);
        out.function_count = caps.function_count;
        out.feature_count = caps.feature_count;

        // Say what was left out. A filter that quietly drops most of a 200-module
        // database is indistinguishable from a broken analysis, so it has to announce
        // itself — and the list is what tells the user whether it classified right.
        //
        // The reverse matters just as much: if the filter is on but there is no module
        // list to apply it to, nothing is filtered, and without a word about it that
        // is indistinguishable from the filter working.
        if (!scan_system_modules() && extractor.modules().empty()) {
            // The segment names are the only other thing a classification could key
            // off, so print them: it turns "the filter does nothing" from a mystery
            // into a bug report someone can act on.
            std::string names;
            const std::vector<capa::ida::SegInfo> segs = capa::ida::get_segments();
            for (std::size_t i = 0; i < segs.size() && i < 12; ++i)
                names += (i ? ", " : "") + segs[i].name;
            if (segs.size() > 12) names += fmt(", +%d more", static_cast<int>(segs.size() - 12));
            msg("capa: %d segment(s): %s\n", static_cast<int>(segs.size()), names.c_str());
        }
        if (!scan_system_modules() && !extractor.modules().empty() &&
            extractor.skipped_system_functions() == 0)
            msg("capa: the module list classified nothing as a system module, so every "
                "function was scanned.\n");
        if (extractor.skipped_system_functions() > 0) {
            const std::vector<std::string> mods = extractor.skipped_system_modules();
            std::string names;
            for (std::size_t i = 0; i < mods.size() && i < 6; ++i)
                names += (i ? ", " : "") + mods[i];
            if (mods.size() > 6) names += fmt(", +%d more", static_cast<int>(mods.size() - 6));
            out.skipped_note =
                fmt("skipped %d function(s) in %d system module(s): %s",
                    static_cast<int>(extractor.skipped_system_functions()),
                    static_cast<int>(mods.size()), names.c_str());
            msg("capa: %s\n", out.skipped_note.c_str());
            msg("capa: to include them, tick Edit > Plugins > CAPA C++ > \"Scan Windows "
                "system modules\" and analyze again.\n");
        }
    } catch (const Cancelled&) {
        return false;  // user's choice; no error message
    } catch (const std::exception& e) {
        error = std::string("analysis failed: ") + e.what();
        return false;
    }

    replace_wait_box("capa: building results ...");

    // User-facing rules only, sorted by (namespace, name) — capa's capability_rules().
    std::vector<std::shared_ptr<capa::Rule>> shown;
    for (const auto& [name, results] : caps.matches) {
        auto rule = ruleset.get(name);
        if (!rule) continue;
        if (rule->is_subscope) continue;                            // synthetic helpers
        if (rule->is_lib) continue;                                 // supporting rules
        if (rule->namespace_.rfind("internal/", 0) == 0) continue;  // capa internals
        shown.push_back(rule);
    }
    std::sort(shown.begin(), shown.end(), [](const auto& a, const auto& b) {
        if (a->namespace_ != b->namespace_) return a->namespace_ < b->namespace_;
        return a->name < b->name;
    });

    TreeBuilder builder;
    for (const auto& rule : shown) {
        const auto& results = caps.matches.at(rule->name);

        ResultNode rule_node;
        rule_node.kind = NodeKind::Rule;
        rule_node.info = results.size() > 1
                             ? fmt("%s (%d matches)", rule->name.c_str(),
                                   static_cast<int>(results.size()))
                             : rule->name;
        rule_node.details = rule->namespace_;

        const std::string scope = scope_name(*rule);
        for (const auto& [addr, res] : results) {
            // The scope node sits between the rule and its match tree — except at file
            // scope, where the match hangs directly off the rule.
            ResultNode* parent = &rule_node;
            ResultNode scope_node;
            if (scope != "file") {
                ea_t ea = ea_of(addr);
                scope_node.address = ea;
                if (scope == "function") {
                    scope_node.kind = NodeKind::Function;
                    scope_node.info = "function(" + capa::ida::get_ea_name(ea) + ")";
                } else if (scope == "basic block") {
                    scope_node.kind = NodeKind::BasicBlock;
                    scope_node.info = "basic block(" + loc_name(ea) + ")";
                } else {
                    scope_node.kind = NodeKind::Instruction;
                    scope_node.info = "instruction(" + loc_name(ea) + ")";
                }
                rule_node.children.push_back(std::move(scope_node));
                parent = &rule_node.children.back();
            }

            // A match carries its evidence behind a pointer, and the pointer can be null
            // when the tree was capped. The static path never caps, so this is a guard
            // rather than a case the tree view has to render.
            ResultNode match;
            if (res && builder.match_node(*res, match))
                parent->children.push_back(std::move(match));
        }

        out.rules.push_back(std::move(rule_node));
    }
    out.match_count = out.rules.size();
    out.valid = true;

    return true;
}

}  // namespace idacapa
