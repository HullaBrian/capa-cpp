// capa's data-driven matcher tests (tests/fixtures/matcher), run against capa-cpp.
//
// Ports tests/test_match_fixtures.py: each fixture is a handful of rules, a feature
// listing, and the exact matches capa reports for them. The rules are loaded the way
// capa's runner loads them (Rule.from_dict, after filling in the unstated scope as
// `unsupported`), the listing becomes a null extractor, and the capabilities drivers run
// over it with capa's "paranoid" check on -- every scope's indexed match must agree with
// the naive matcher -- exactly as the upstream test does.
#include "tests.h"

#include <filesystem>
#include <fstream>
#include <sstream>

#include <yaml-cpp/yaml.h>

#include "capabilities.h"
#include "dsl.h"
#include "feature_filter.h"
#include "match_retention.h"
#include "rules.h"
#include "static_caps.h"

namespace capa::tests {

namespace fs = std::filesystem;

namespace {

using Expected = std::map<std::string, std::vector<Address>>;

// A YAML scalar written as an integer (PyYAML would load it as int).
bool is_plain_int(const YAML::Node& n) {
    if (!n.IsScalar() || n.Tag() != "?") return false;
    try {
        dsl::parse_int0(n.Scalar());
        return true;
    } catch (const dsl::DslError&) {
        return false;
    }
}

Address parse_expected(const YAML::Node& spec, bool dynamic, const std::map<std::uint64_t, Address>& calls_by_id) {
    static const std::regex call_id(R"(call\((\d+)\))");
    if (dynamic) {
        if (is_plain_int(spec)) {
            auto it = calls_by_id.find(static_cast<std::uint64_t>(dsl::parse_int0(spec.Scalar()).v));
            if (it != calls_by_id.end()) return it->second;
        }
        std::smatch m;
        const std::string s = spec.Scalar();
        if (std::regex_match(s, m, call_id)) {
            auto it = calls_by_id.find(std::stoull(m[1]));
            if (it == calls_by_id.end()) throw dsl::DslError("unknown dynamic fixture call ID: " + s);
            return it->second;
        }
    }
    return dsl::parse_address(spec.Scalar());
}

// _normalize_rule_doc + the {"rule": ...} wrapper.
YAML::Node normalize_rule(const YAML::Node& rule_doc, const std::string& flavor) {
    static const std::set<std::string> meta_keys = {"name",    "namespace", "description", "scopes",
                                                    "authors", "att&ck",    "mbc",         "lib"};
    const bool synthesized = !rule_doc["meta"];
    YAML::Node meta;
    if (!synthesized) {
        meta = YAML::Clone(rule_doc["meta"]);
    } else {
        meta = YAML::Node(YAML::NodeType::Map);
        for (const auto& kv : rule_doc) {
            const std::string key = kv.first.as<std::string>();
            if (meta_keys.count(key)) meta[key] = YAML::Clone(kv.second);
        }
    }
    const YAML::Node& view = meta;  // const lookups never insert
    YAML::Node scopes = view["scopes"] ? YAML::Node(meta["scopes"]) : YAML::Node(YAML::NodeType::Map);
    const YAML::Node& sview = scopes;
    if (flavor == "static" && !sview["dynamic"]) scopes["dynamic"] = "unsupported";
    if (flavor == "dynamic" && !sview["static"]) scopes["static"] = "unsupported";
    meta["scopes"] = scopes;

    YAML::Node rule(YAML::NodeType::Map);
    rule["meta"] = meta;
    for (const auto& kv : rule_doc) {
        const std::string key = kv.first.as<std::string>();
        if (key == "meta" || (synthesized && meta_keys.count(key))) continue;
        rule[key] = YAML::Clone(kv.second);
    }
    YAML::Node wrapped(YAML::NodeType::Map);
    wrapped["rule"] = rule;
    return wrapped;
}

std::string join_addresses(const std::vector<Address>& v) {
    std::string out = "[";
    for (std::size_t i = 0; i < v.size(); ++i) out += (i ? ", " : "") + v[i].repr();
    return out + "]";
}

std::string describe(const Expected& m) {
    std::string out = "{";
    bool first = true;
    for (const auto& [name, addrs] : m) {
        out += std::string(first ? "" : ", ") + name + ": " + join_addresses(addrs);
        first = false;
    }
    return out + "}";
}

// One fixture. Throws on a malformed fixture; returns the failure message, or "".
std::string run_fixture(const YAML::Node& doc, const std::string& flavor) {
    std::string listing;
    const YAML::Node features = doc["features"];
    if (features && features.IsSequence()) {
        for (const auto& line : features) listing += line.as<std::string>() + "\n";
    } else if (features) {
        listing = features.as<std::string>();
    }
    const std::vector<std::string> lines = dsl::feature_lines(listing);

    std::size_t span_size = DEFAULT_SPAN_SIZE;
    if (doc["options"] && doc["options"]["span size"])
        span_size = static_cast<std::size_t>(dsl::parse_int0(doc["options"]["span size"].Scalar()).v);

    std::vector<std::shared_ptr<Rule>> rules;
    for (const auto& rule_doc : doc["rules"]) {
        const YAML::Node wrapped = normalize_rule(rule_doc, flavor);
        rules.push_back(std::make_shared<Rule>(Rule::from_yaml_node(wrapped, YAML::Dump(wrapped))));
    }
    RuleSet ruleset(std::move(rules));
    ruleset.set_paranoid(true);
    FeatureFilter filter = FeatureFilter::from_ruleset(ruleset);
    filter.disable();

    MatchResults matches;
    std::map<std::uint64_t, Address> calls_by_id;
    if (flavor == "static") {
        Address base = Address::absolute(0);
        if (doc["base address"]) base = dsl::parse_static_address(doc["base address"].Scalar());
        auto ex = dsl::parse_static(lines, base);
        matches = find_static_capabilities(ruleset, *ex, filter).matches;
    } else {
        dsl::DynamicListing listing_ = dsl::parse_dynamic(lines);
        calls_by_id = listing_.calls_by_id;
        matches = find_dynamic_capabilities(ruleset, *listing_.extractor, filter, MatchRetention::kKeepAll,
                                            false, false, span_size)
                      .matches;
    }

    Expected expected;
    const YAML::Node expect = doc["expect"];
    if (expect && expect["matches"]) {
        for (const auto& kv : expect["matches"]) {
            auto& v = expected[kv.first.as<std::string>()];
            for (const auto& spec : kv.second) v.push_back(parse_expected(spec, flavor == "dynamic", calls_by_id));
        }
    }
    Expected actual;
    for (const auto& [name, results] : matches) {
        auto rule = ruleset.get(name);
        if (!rule || rule->is_subscope) continue;
        auto& v = actual[name];
        for (const auto& [addr, res] : results) v.push_back(addr);
    }

    std::string failure;
    if (actual != expected) failure = "expected " + describe(expected) + "\n        actual   " + describe(actual);
    for (const auto& p : ruleset.paranoid_failures()) failure += (failure.empty() ? "" : "\n        ") + p;
    return failure;
}

std::string infer_flavor(const fs::path& path) {
    std::string flavor;
    for (const auto& part : path)
        if (part == "static" || part == "dynamic") flavor = part.string();
    return flavor;
}

}  // namespace

int run_match_fixtures(const std::string& dir, const Options& opts) {
    std::vector<fs::path> paths;
    for (const auto& e : fs::recursive_directory_iterator(dir)) {
        const auto ext = e.path().extension();
        if (e.is_regular_file() && (ext == ".yml" || ext == ".yaml" || ext == ".json")) paths.push_back(e.path());
    }
    std::sort(paths.begin(), paths.end());
    if (paths.empty()) {
        std::fprintf(stderr, "error: no matcher fixtures under %s\n", dir.c_str());
        return 2;
    }

    Tally tally;
    for (const fs::path& path : paths) {
        const std::string rel = fs::relative(path, dir).generic_string();
        YAML::Node doc;
        try {
            doc = YAML::LoadFile(path.string());
        } catch (const std::exception& e) {
            tally.fail(rel, std::string("cannot load: ") + e.what());
            continue;
        }
        std::vector<YAML::Node> tests;
        if (doc.IsSequence()) {
            for (const auto& t : doc) tests.push_back(t);
        } else if (doc.IsMap() && doc["tests"] && doc["tests"].IsSequence()) {
            for (const auto& t : doc["tests"]) tests.push_back(t);
        } else if (doc.IsMap()) {
            tests.push_back(doc);
        }
        const std::string inferred = infer_flavor(fs::relative(path, dir));
        for (std::size_t i = 0; i < tests.size(); ++i) {
            const YAML::Node& t = tests[i];
            const std::string name = t["name"] ? t["name"].as<std::string>() : path.stem().string() + "-" + std::to_string(i + 1);
            const std::string id = rel + "[" + std::to_string(i + 1) + "]::" + name;
            if (!opts.filter.empty() && id.find(opts.filter) == std::string::npos) continue;
            const std::string flavor = t["flavor"] ? t["flavor"].as<std::string>() : inferred;
            try {
                if (flavor != "static" && flavor != "dynamic") throw dsl::DslError("unknown fixture flavor: " + flavor);
                const std::string failure = run_fixture(t, flavor);
                if (failure.empty())
                    tally.pass(id, opts.verbose);
                else
                    tally.fail(id, failure);
            } catch (const InvalidRule& e) {
                tally.fail(id, "invalid rule: " + e.message);
            } catch (const std::exception& e) {
                tally.fail(id, e.what());
            }
        }
    }
    return tally.report("matcher fixtures");
}

}  // namespace capa::tests
