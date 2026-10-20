// capa's backend feature fixtures (tests/fixtures/features), evaluated against freeze files.
//
// Ports run_feature_fixture and resolve_scope from capa's tests/fixtures/__init__.py. A
// fixture says: in sample S, at location L, feature F is (or is not) extracted. capa runs
// these against each live backend; here a backend is represented by the freeze file it
// wrote for S -- which is how any backend, capa's or capa-cpp's, can be checked with no
// Python and no disassembler in the loop. Selection follows capa's backend policies:
// include/exclude tags, plus the per-backend `skip`/`xfail` marks the manifests carry.
#include "tests.h"

#include <fstream>
#include <memory>

#include <nlohmann/json.hpp>

#include "engine.h"
#include "freeze.h"
#include "rules.h"

namespace capa::tests {

namespace {

using nlohmann::json;

struct Sample {
    freeze::Frozen frozen;
};

FeatureSet& add(FeatureSet& fs, const std::vector<FeaturePair>& pairs) {
    for (const auto& [f, a] : pairs) fs[f].insert(a);
    return fs;
}

std::uint64_t hex_value(const std::string& spec) { return std::stoull(spec.substr(spec.find('=') + 1), nullptr, 16); }

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        auto pos = s.find(sep, start);
        out.push_back(s.substr(start, pos == std::string::npos ? std::string::npos : pos - start));
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    return out;
}

// "process=(pid:ppid)": capa's fixtures list the pid first.
Address parse_process(const std::string& spec) {
    std::string inner = spec.substr(spec.find('=') + 1);
    inner = inner.substr(1, inner.size() - 2);
    const auto parts = split(inner, ':');
    if (parts.size() != 2) throw std::runtime_error("bad process location: " + spec);
    return Address::process(static_cast<std::uint32_t>(std::stoul(parts[0])),
                            static_cast<std::uint32_t>(std::stoul(parts[1])));
}

// resolve_scope: the features of the scope the location names, with every lower scope's
// features merged in and the global features added.
FeatureSet scope_features(const freeze::Frozen& frz, const std::string& location) {
    FeatureSet fs;
    if (frz.static_extractor) {
        const auto& ex = *frz.static_extractor;
        add(fs, ex.extract_global_features());
        if (location == "file") return add(fs, ex.extract_file_features());

        const auto specs = split(location, ',');
        const Address fva = Address::absolute(hex_value(specs[0]));
        auto f = ex.functions.find(fva);
        if (specs[0].rfind("token", 0) == 0) f = ex.functions.find(Address::dn_token(hex_value(specs[0])));
        if (f == ex.functions.end()) throw std::runtime_error("function not found");
        auto add_bb = [&](const NullBasicBlock& bb) {
            for (const auto& [ia, insn] : bb.instructions) add(fs, insn.features);
            add(fs, bb.features);
        };
        if (specs.size() == 1) {
            for (const auto& [ba, bb] : f->second.basic_blocks) add_bb(bb);
            return add(fs, f->second.features);
        }
        auto bb = f->second.basic_blocks.find(Address::absolute(hex_value(specs[1])));
        if (bb == f->second.basic_blocks.end()) throw std::runtime_error("basic block not found");
        if (specs.size() == 2) {
            add_bb(bb->second);
            return fs;
        }
        auto insn = bb->second.instructions.find(Address::absolute(hex_value(specs[2])));
        if (insn == bb->second.instructions.end()) throw std::runtime_error("instruction not found");
        return add(fs, insn->second.features);
    }

    const auto& ex = *frz.dynamic_extractor;
    add(fs, ex.extract_global_features());
    if (location == "file") return add(fs, ex.extract_file_features());
    const auto specs = split(location, ',');
    const Address pa = parse_process(specs[0]);
    auto p = ex.processes.find(pa);
    if (p == ex.processes.end()) throw std::runtime_error("process not found");
    auto add_thread = [&](const NullThread& t) {
        for (const auto& [ca, c] : t.calls) add(fs, c.features);
        add(fs, t.features);
    };
    if (specs.size() == 1) {
        for (const auto& [ta, t] : p->second.threads) add_thread(t);
        return add(fs, p->second.features);
    }
    const std::uint32_t tid = static_cast<std::uint32_t>(std::stoul(specs[1].substr(specs[1].find('=') + 1)));
    auto t = p->second.threads.find(Address::thread(pa, tid));
    if (t == p->second.threads.end()) throw std::runtime_error("thread not found");
    if (specs.size() == 2) {
        add_thread(t->second);
        return fs;
    }
    const std::uint64_t cid = std::stoull(specs[2].substr(specs[2].find('=') + 1));
    auto c = t->second.calls.find(Address::call(Address::thread(pa, tid), cid));
    if (c == t->second.calls.end()) throw std::runtime_error("call not found");
    return add(fs, c->second.features);
}

std::string scope_of(const std::string& location) {
    if (location == "file") return "file";
    if (location.find("insn=") != std::string::npos) return "instruction";
    if (location.find("bb=") != std::string::npos) return "basic block";
    if (location.find("call=") != std::string::npos) return "call";
    if (location.find("thread=") != std::string::npos) return "thread";
    if (location.find("process=") != std::string::npos) return "process";
    if (location.rfind("function", 0) == 0 || location.rfind("token", 0) == 0) return "function";
    throw std::runtime_error("unexpected scope location: " + location);
}

}  // namespace

int run_feature_fixtures(const FeatureFixtureOptions& fopts, const Options& opts) {
    std::map<std::string, std::unique_ptr<freeze::Frozen>> loaded;
    for (const auto& [key, path] : fopts.freeze_by_key) {
        try {
            loaded[key] = std::make_unique<freeze::Frozen>(freeze::load_file(path));
        } catch (const std::exception& e) {
            std::fprintf(stderr, "error: %s: %s\n", path.c_str(), e.what());
            return 2;
        }
    }

    Tally tally;
    for (const std::string& manifest : fopts.manifests) {
        json doc;
        try {
            std::ifstream in(manifest);
            doc = json::parse(in);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "error: %s: %s\n", manifest.c_str(), e.what());
            return 2;
        }
        std::map<std::string, std::set<std::string>> file_tags;
        for (const auto& f : doc["files"]) {
            auto& tags = file_tags[f["key"].get<std::string>()];
            if (f.contains("tags"))
                for (const auto& t : f["tags"]) tags.insert(t.get<std::string>());
        }
        for (const auto& fx : doc["features"]) {
            const std::string key = fx["file"].get<std::string>();
            auto sample = loaded.find(key);
            if (sample == loaded.end()) continue;  // no freeze given for this sample
            const std::string location = fx["location"].get<std::string>();
            const std::string feature_str = fx["feature"].get<std::string>();
            const bool expected = fx.value("expected", true);
            const std::string id = key + "-" + location + "-" + feature_str + "-" + (expected ? "True" : "False");
            if (!opts.filter.empty() && id.find(opts.filter) == std::string::npos) continue;

            try {
                // parse_feature_string: "key: value", built as capa's build_feature builds it
                const auto sep = feature_str.find(": ");
                const std::string fkey = feature_str.substr(0, sep);
                const std::string fvalue = sep == std::string::npos ? "" : feature_str.substr(sep + 2);
                const Node statement = build_feature_from_text(fkey, fvalue);

                std::set<std::string> tags = file_tags[key];
                if (fx.contains("tags"))
                    for (const auto& t : fx["tags"]) tags.insert(t.get<std::string>());
                tags.insert(scope_of(location));
                if (!statement.is_statement) tags.insert(statement.feature.name);

                bool included = fopts.include_tags.empty();
                for (const auto& t : fopts.include_tags) included = included || tags.count(t);
                for (const auto& t : fopts.exclude_tags) included = included && !tags.count(t);
                if (!included) {
                    tally.skip(id, "not selected by the backend policy", opts.verbose);
                    continue;
                }

                std::string mark, reason;
                if (fx.contains("marks"))
                    for (const auto& m : fx["marks"])
                        if (m["backend"].get<std::string>() == fopts.backend) {
                            mark = m["mark"].get<std::string>();
                            reason = m.value("reason", "");
                        }
                if (mark == "skip") {
                    tally.skip(id, reason, opts.verbose);
                    continue;
                }

                const FeatureSet features = scope_features(*sample->second, location);
                const bool actual = eval_node(statement, features, true).success;
                if (actual == expected) {
                    if (mark == "xfail")
                        tally.fail(id, "expected to fail (" + reason + "), but passed");
                    else
                        tally.pass(id, opts.verbose);
                } else if (mark == "xfail") {
                    tally.xfail(id, reason, opts.verbose);
                } else {
                    tally.fail(id, feature_str + (expected ? " should match in " : " should not match in ") + location);
                }
            } catch (const InvalidRule& e) {
                tally.fail(id, "invalid feature: " + e.message);
            } catch (const std::exception& e) {
                tally.fail(id, e.what());
            }
        }
    }
    return tally.report("feature fixtures");
}

}  // namespace capa::tests
