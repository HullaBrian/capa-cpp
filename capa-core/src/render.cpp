#include "render.h"

#include "match_retention.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include <nlohmann/json.hpp>

#include "freeze.h"
#include "render_tree.h"

namespace capa::render {

namespace {

using nlohmann::ordered_json;
using freeze::address_to_json;
using freeze::feature_to_json;

constexpr const char* CAPA_CPP_VERSION = "capa-cpp 0.2.0";

// Every string the document carries is checked by nlohmann on the way out, and a backend
// can hand over bytes that are not UTF-8 (a string read out of a dump, say). Replaced
// rather than thrown on: one odd string must not cost the whole document.
std::string dump_json(const ordered_json& j) {
    return j.dump(-1, ' ', false, ordered_json::error_handler_t::replace);
}

// ---------------------------------------------------------------------------
// result document models (capa/render/result_document.py)
//
// Spelled as capa writes them: model_dump_json(exclude_none=True), so pydantic *field*
// names ("is_subscope_rule", "import_", "malware_category", ...) and no member whose
// value is None. Members appear in capa's declaration order.
// ---------------------------------------------------------------------------

ordered_json addresses_json(const AddressSet& addrs) {
    // capa serializes a frozenset, whose order is Python's hash order; sorted is the
    // stable spelling of the same set.
    ordered_json arr = ordered_json::array();
    for (const auto& a : addrs) arr.push_back(address_to_json(a));
    return arr;
}

// rd.statement_from_capa
ordered_json statement_json(const Statement& s) {
    ordered_json j;
    auto desc = [&] {
        if (!s.description.empty()) j["description"] = s.description;
    };
    switch (s.type) {
        case StatementType::And: j["type"] = "and"; desc(); break;
        case StatementType::Or: j["type"] = "or"; desc(); break;
        case StatementType::Not: j["type"] = "not"; desc(); break;
        case StatementType::Some:
            if (s.count == 0) {
                j["type"] = "optional";
                desc();
            } else {
                j["type"] = "some";
                desc();
                j["count"] = s.count;
            }
            break;
        case StatementType::Range:
            j["type"] = "range";
            desc();
            j["min"] = s.range_min;
            j["max"] = s.range_max;
            j["child"] = feature_to_json(s.range_child);
            break;
        case StatementType::Subscope:
            j["type"] = "subscope";
            desc();
            j["scope"] = scope_to_string(s.subscope);
            break;
    }
    return j;
}

ordered_json statement_node(ordered_json statement) {
    ordered_json j;
    j["type"] = "statement";
    j["statement"] = std::move(statement);
    return j;
}

// The stub that stands in for a match tree `--max-match-trees` dropped. A capa-cpp
// extension: capa keeps every tree. Spelled out rather than left as an empty Match,
// because a Match with no node and no children is otherwise indistinguishable from a
// serializer bug.
ordered_json truncated_match_json() {
    ordered_json j;
    j["success"] = true;
    j["truncated"] = true;
    j["node"] = nullptr;
    j["children"] = ordered_json::array();
    j["locations"] = ordered_json::array();
    j["captures"] = ordered_json::object();
    return j;
}

// rd.Match.from_capa, including the splice of `match:` references: a matched `match:`
// feature carries, as its children, the match trees of the rule (or of every rule in the
// namespace) it names, at the locations it matched -- and a reference to a subscope rule
// is turned back into the `subscope` statement it was extracted from.
class MatchWriter {
public:
    explicit MatchWriter(const RenderInput& in) : in_(in) {}

    ordered_json match(const MatchEvidence& evidence) {
        if (!evidence) return truncated_match_json();
        return match(*evidence);
    }

    ordered_json match(const Result& res) {
        ordered_json node;
        if (res.node_is_statement) {
            node = statement_node(statement_json(*res.stmt));
        } else {
            node["type"] = "feature";
            node["feature"] = feature_to_json(res.feature);
        }

        ordered_json children = ordered_json::array();
        for (const auto& c : res.children) children.push_back(match(c));

        // logic nodes have no locations, their children do; except a range, which
        // reports where its counted feature was.
        const bool has_locations =
            res.success && (!res.node_is_statement || (res.stmt && res.stmt->type == StatementType::Range));

        ordered_json captures = ordered_json::object();
        for (const auto& [str, locs] : res.captures) captures[str] = addresses_json(locs);

        if (!res.node_is_statement && res.feature.type == FeatureType::MatchedRule && res.success)
            splice(res, node, children);

        ordered_json j;
        j["success"] = res.success;
        j["node"] = std::move(node);
        j["children"] = std::move(children);
        j["locations"] = has_locations ? addresses_json(res.locations) : ordered_json::array();
        j["captures"] = std::move(captures);
        return j;
    }

private:
    struct RuleMatches {
        std::map<Address, const MatchEvidence*> by_address;  // dict(capabilities[name])
        // thread -> (call id, evidence), ascending: for "the most recent match in the
        // thread at or before this call"
        std::map<Address, std::vector<std::pair<std::uint64_t, const MatchEvidence*>>> by_thread;
    };

    const RuleMatches* matches_of(const std::string& name) {
        auto cached = cache_.find(name);
        if (cached != cache_.end()) return cached->second.get();
        std::unique_ptr<RuleMatches> rm;
        auto it = in_.matches.find(name);
        if (it != in_.matches.end()) {
            rm = std::make_unique<RuleMatches>();
            for (const auto& [addr, evidence] : it->second) rm->by_address[addr] = &evidence;
            for (const auto& [addr, evidence] : rm->by_address)
                if (addr.type == AddressType::CALL)
                    rm->by_thread[addr.thread_part()].emplace_back(addr.id, evidence);
        }
        const RuleMatches* out = rm.get();
        cache_.emplace(name, std::move(rm));
        return out;
    }

    // `exact_only` is the namespace case, where a non-call location is looked up but not
    // required to be there.
    void splice_locations(const RuleMatches& rm, const AddressSet& locations, ordered_json& children) {
        for (const Address& location : locations) {
            auto exact = rm.by_address.find(location);
            if (exact != rm.by_address.end()) {
                children.push_back(match(*exact->second));
                continue;
            }
            if (location.type != AddressType::CALL) continue;
            // Span-of-calls rules can match each other but do not contain each other the
            // way a function contains a basic block; take the most recent match of the
            // referenced rule in the same thread, at or before this call.
            auto thread = rm.by_thread.find(location.thread_part());
            if (thread == rm.by_thread.end()) continue;
            const auto& calls = thread->second;
            auto after = std::upper_bound(calls.begin(), calls.end(), location.id,
                                          [](std::uint64_t id, const auto& e) { return id < e.first; });
            if (after == calls.begin()) continue;
            children.push_back(match(*std::prev(after)->second));
        }
    }

    void splice(const Result& res, ordered_json& node, ordered_json& children) {
        const std::string& name = res.feature.s;
        if (auto rule = in_.ruleset.get(name)) {
            if (rule->is_subscope) {
                // e.g. `contain loop/<id>` -> `basic block`
                const Scope scope = rule->scopes.static_scope ? *rule->scopes.static_scope
                                                              : rule->scopes.dynamic_scope.value_or(Scope::FILE);
                ordered_json st;
                st["type"] = "subscope";
                st["scope"] = scope_to_string(scope);
                node = statement_node(std::move(st));
            }
            if (const RuleMatches* rm = matches_of(name)) splice_locations(*rm, res.locations, children);
            return;
        }
        // a namespace: splice in every rule of it that matched, at the locations matched.
        // (capa notes that the document loses which rule of the namespace it was.)
        const auto& by_ns = in_.ruleset.rules_by_namespace();
        auto ns = by_ns.find(name);
        if (ns == by_ns.end()) return;
        for (const auto& rule : ns->second)
            if (const RuleMatches* rm = matches_of(rule->name)) splice_locations(*rm, res.locations, children);
    }

    const RenderInput& in_;
    std::unordered_map<std::string, std::unique_ptr<RuleMatches>> cache_;
};

// The compact evidence for one match: the single feature node that completed it, rather
// than the tree that contains it. `--match-evidence`, a capa-cpp extension.
//
// Two sources, one shape. A leaf the matcher took before dropping the tree is used as it
// stands; otherwise one is found in the tree, which is how the paths that keep every tree
// (the static backends) get this without a retention pass of their own. Null when there is
// neither -- a stub from a run that did not ask for leaves -- said as `null` rather than as
// an empty object, so "no evidence" cannot be misread as "a feature with no name".
ordered_json evidence_leaf_json(const MatchEvidence& evidence) {
    const EvidenceKind* kind = nullptr;
    const AddressSet* locations = nullptr;
    EvidenceKind from_tree;

    if (evidence.leaf && evidence.leaf->kind) {
        kind = evidence.leaf->kind.get();
        locations = &evidence.leaf->locations;
    } else if (evidence.tree) {
        const Result* node = find_evidence_leaf(*evidence.tree);
        if (!node) return ordered_json(nullptr);
        from_tree = evidence_kind_of(*node);
        kind = &from_tree;
        locations = &node->locations;
    } else {
        return ordered_json(nullptr);
    }

    ordered_json j;
    j["feature"] = feature_to_json(kind->feature);
    // Only for the features that have one. An empty member on every other match is one
    // more thing per match in a document whose whole point is that it is small.
    if (!kind->captured.empty()) {
        j["captured"] = kind->captured;
        if (kind->captured_truncated) j["captured_truncated"] = true;
    }
    // The feature's own addresses, not the match address: for a span-of-calls rule the two
    // differ, and that difference is what makes the leaf worth shipping.
    j["locations"] = addresses_json(*locations);
    return j;
}

// ---------------------------------------------------------------------------
// att&ck / mbc meta parsing (rd.parse_parts_id: "Tactic::Technique::Sub [ID]")
// ---------------------------------------------------------------------------

struct Spec {
    std::vector<std::string> parts;
    std::string id;
};

// rd.parse_parts_id, quirks included: the id is whatever follows the last space of the
// last part, brackets stripped -- so a spec written without an id loses its last word.
Spec parse_spec(const std::string& raw) {
    Spec s;
    std::size_t start = 0;
    while (true) {
        auto sep = raw.find("::", start);
        if (sep == std::string::npos) {
            s.parts.push_back(raw.substr(start));
            break;
        }
        s.parts.push_back(raw.substr(start, sep - start));
        start = sep + 2;
    }
    std::string last = s.parts.back();
    s.parts.pop_back();
    const auto space = last.rfind(' ');
    std::string id;
    if (space == std::string::npos) {
        id = last;
        last.clear();
    } else {
        id = last.substr(space + 1);
        last = last.substr(0, space);
    }
    std::size_t a = 0, b = id.size();
    while (a < b && id[a] == '[') ++a;
    while (b > a && id[b - 1] == ']') --b;
    s.id = id.substr(a, b - a);
    s.parts.push_back(last);
    return s;
}

ordered_json spec_json(const std::string& raw, const char* k0, const char* k1, const char* k2) {
    Spec s = parse_spec(raw);
    ordered_json j;
    j["parts"] = s.parts;
    j[k0] = s.parts.size() > 0 ? s.parts[0] : "";
    j[k1] = s.parts.size() > 1 ? s.parts[1] : "";
    j[k2] = s.parts.size() > 2 ? s.parts[2] : "";
    j["id"] = s.id;
    return j;
}

// rd.RuleMetadata.from_capa
ordered_json rule_meta_json(const Rule& r) {
    ordered_json m;
    m["name"] = r.name;
    if (!r.namespace_.empty()) m["namespace"] = r.namespace_;
    m["authors"] = r.authors;
    ordered_json scopes = ordered_json::object();
    if (r.scopes.static_scope) scopes["static"] = scope_to_string(*r.scopes.static_scope);
    if (r.scopes.dynamic_scope) scopes["dynamic"] = scope_to_string(*r.scopes.dynamic_scope);
    m["scopes"] = std::move(scopes);
    ordered_json attack = ordered_json::array();
    for (const auto& a : r.attack) attack.push_back(spec_json(a, "tactic", "technique", "subtechnique"));
    m["attack"] = std::move(attack);
    ordered_json mbc = ordered_json::array();
    for (const auto& b : r.mbc) mbc.push_back(spec_json(b, "objective", "behavior", "method"));
    m["mbc"] = std::move(mbc);
    m["references"] = r.references;
    m["examples"] = r.examples;
    m["description"] = r.description;
    m["lib"] = r.is_lib;
    m["is_subscope_rule"] = r.is_subscope;
    ordered_json maec = ordered_json::object();
    for (const char* key : {"analysis-conclusion", "analysis-conclusion-ov", "malware-family",
                            "malware-category", "malware-category-ov"}) {
        auto it = r.maec.find(key);
        if (it == r.maec.end()) continue;
        std::string field = key;
        std::replace(field.begin(), field.end(), '-', '_');
        maec[field] = it->second;
    }
    m["maec"] = std::move(maec);
    return m;
}

// capa writes datetime.now().isoformat(): local time, microseconds.
std::string iso_timestamp() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const std::time_t t = system_clock::to_time_t(now);
    const auto micros = duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000;
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[48];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tmv);
    char out[64];
    std::snprintf(out, sizeof(out), "%s.%06lld", buf, static_cast<long long>(micros));
    return out;
}

// Batches the many small pieces a streamed document is made of into writes worth making.
// Serializing a match tree produces a few dozen bytes; handing each of those to a
// std::function that ends in fwrite would spend more time in the call than in the copy.
class JsonSink {
public:
    explicit JsonSink(const JsonWriter& write) : write_(write) { buf_.reserve(kChunk * 2); }

    // The flush that matters is the explicit one at the end of the document; this is only
    // the safety net for a caller who forgets. It swallows, because the writer can throw
    // and a destructor that throws while an exception is already propagating terminates
    // the process -- and on the way out of an exception a half-written document is not
    // worth completing anyway.
    ~JsonSink() noexcept {
        try {
            flush();
        } catch (...) {
        }
    }

    JsonSink(const JsonSink&) = delete;
    JsonSink& operator=(const JsonSink&) = delete;

    void put(const char* s) { put(std::string_view(s)); }
    void put(std::string_view s) {
        buf_.append(s);
        if (buf_.size() >= kChunk) flush();
    }
    void put(const ordered_json& j) { put(std::string_view(dump_json(j))); }

    void flush() {
        if (buf_.empty()) return;
        write_(buf_.data(), buf_.size());
        buf_.clear();
    }

private:
    static constexpr std::size_t kChunk = 1u << 20;  // 1 MiB
    const JsonWriter& write_;
    std::string buf_;
};

// How the document's structure is spelled.
//
// JSON and MessagePack differ, for this document, in exactly two ways: JSON puts commas
// between members and MessagePack says up front how many there will be. Both are covered
// by "begin a container of n" plus a separator the encoder places or does not, so the
// walk that knows the document's shape can be written once and encoded either way.
class DocEncoder {
public:
    virtual ~DocEncoder() = default;
    virtual void begin_map(std::size_t members) = 0;
    virtual void end_map() = 0;
    virtual void begin_array(std::size_t elements) = 0;
    virtual void end_array() = 0;
    virtual void key(const std::string& k) = 0;
    virtual void value(const ordered_json& v) = 0;
};

// Emits exactly what building the whole document and calling dump() emits. The member
// counts are ignored: JSON does not declare them.
class JsonEncoder final : public DocEncoder {
public:
    explicit JsonEncoder(JsonSink& sink) : s_(sink) {}

    void begin_map(std::size_t) override { open("{"); }
    void end_map() override { close("}"); }
    void begin_array(std::size_t) override { open("["); }
    void end_array() override { close("]"); }

    void key(const std::string& k) override {
        separate();
        s_.put(ordered_json(k));  // escaped, not pasted in raw
        s_.put(":");
        after_key_ = true;
    }

    void value(const ordered_json& v) override {
        separate();
        s_.put(v);
    }

private:
    // A comma before every item except the first -- but not between a key and its value,
    // which `after_key_` absorbs.
    void separate() {
        if (after_key_) {
            after_key_ = false;
            return;
        }
        if (first_.empty()) return;
        if (!first_.back()) s_.put(",");
        first_.back() = false;
    }
    void open(const char* brace) {
        separate();
        s_.put(brace);
        first_.push_back(true);
    }
    void close(const char* brace) {
        s_.put(brace);
        first_.pop_back();
    }

    JsonSink& s_;
    std::vector<bool> first_;
    bool after_key_ = false;
};

// The same document as MessagePack. Containers declare their size, so nothing is written
// until the walk knows how many members it is about to produce -- which it always does,
// every count here being a container's size.
class MsgpackEncoder final : public DocEncoder {
public:
    explicit MsgpackEncoder(JsonSink& sink) : s_(sink) {}

    void begin_map(std::size_t n) override { header(n, 0x80, 0xde, 0xdf); }
    void end_map() override {}
    void begin_array(std::size_t n) override { header(n, 0x90, 0xdc, 0xdd); }
    void end_array() override {}

    void key(const std::string& k) override { str(k); }

    void value(const ordered_json& v) override {
        // A scalar or a small subtree; the containers this document is made of are
        // driven by the walk above, not encoded whole.
        const std::vector<std::uint8_t> bytes = ordered_json::to_msgpack(v);
        s_.put(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    }

private:
    void byte(std::uint8_t b) { s_.put(std::string_view(reinterpret_cast<const char*>(&b), 1)); }
    void be16(std::uint32_t v) {
        byte(static_cast<std::uint8_t>(v >> 8));
        byte(static_cast<std::uint8_t>(v));
    }
    void be32(std::uint32_t v) {
        be16(v >> 16);
        be16(v & 0xffff);
    }
    // fixmap/fixarray for the small case, then the 16- and 32-bit forms.
    void header(std::size_t n, std::uint8_t fix, std::uint8_t u16, std::uint8_t u32) {
        if (n < 16) {
            byte(static_cast<std::uint8_t>(fix | n));
        } else if (n <= 0xffff) {
            byte(u16);
            be16(static_cast<std::uint32_t>(n));
        } else {
            byte(u32);
            be32(static_cast<std::uint32_t>(n));
        }
    }
    void str(const std::string& v) {
        if (v.size() < 32) {
            byte(static_cast<std::uint8_t>(0xa0 | v.size()));
        } else if (v.size() <= 0xff) {
            byte(0xd9);
            byte(static_cast<std::uint8_t>(v.size()));
        } else if (v.size() <= 0xffff) {
            byte(0xda);
            be16(static_cast<std::uint32_t>(v.size()));
        } else {
            byte(0xdb);
            be32(static_cast<std::uint32_t>(v.size()));
        }
        s_.put(std::string_view(v));  // the bytes, not a JSON-encoded string
    }

    JsonSink& s_;
};

// Writes the members of an object already built.
void write_members(DocEncoder& e, const ordered_json& obj) {
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        e.key(it.key());
        e.value(it.value());
    }
}

// ---------------------------------------------------------------------------
// layout (capa loader.compute_{dynamic,static}_layout)
//
// The walk that decides *which* processes/threads/calls or functions/blocks are
// "matched" belongs to the backend, which owns the handles; by the time a Doc
// reaches here the layout is already resolved and this is pure serialization.
// ---------------------------------------------------------------------------

// The analysis layout, streamed: on a large trace it is the one part of `meta` whose size
// follows the trace -- one entry per matched call.
void write_layout(DocEncoder& e, const Doc& doc) {
    if (doc.flavor != Flavor::Dynamic) {
        ordered_json functions = ordered_json::array();
        for (const StaticFunction& f : doc.static_layout) {
            ordered_json bbs = ordered_json::array();
            for (const Address& bb : f.matched_basic_blocks)
                bbs.push_back(ordered_json{{"address", address_to_json(bb)}});
            ordered_json entry;
            entry["address"] = address_to_json(f.address);
            entry["matched_basic_blocks"] = std::move(bbs);
            // capa-cpp extension; absent unless a minidump run set it.
            if (!f.region.empty()) entry["region"] = f.region;
            functions.push_back(std::move(entry));
        }
        e.begin_map(1);
        e.key("functions");
        e.value(functions);
        e.end_map();
        return;
    }

    e.begin_map(1);
    e.key("processes");
    e.begin_array(doc.dyn_layout.size());
    for (const DynProcess& p : doc.dyn_layout) {
        e.begin_map(3);
        e.key("address");
        e.value(address_to_json(p.address));
        e.key("name");
        e.value(ordered_json(p.name));
        e.key("matched_threads");
        e.begin_array(p.matched_threads.size());
        for (const DynThread& t : p.matched_threads) {
            e.begin_map(2);
            e.key("address");
            e.value(address_to_json(t.address));
            e.key("matched_calls");
            e.begin_array(t.matched_calls.size());
            for (const DynCall& c : t.matched_calls) {
                e.begin_map(2);
                e.key("address");
                e.value(address_to_json(c.address));
                e.key("name");
                e.value(ordered_json(c.name));
                e.end_map();
            }
            e.end_array();
            e.end_map();
        }
        e.end_array();
        e.end_map();
    }
    e.end_array();
    e.end_map();
}

// ---------------------------------------------------------------------------
// the document
// ---------------------------------------------------------------------------

// The members of meta.analysis that come after the layout, in capa's order, followed by
// capa-cpp's own (each present only when the run used the feature it describes).
ordered_json analysis_tail(const Doc& doc) {
    const bool dynamic = doc.flavor == Flavor::Dynamic;
    ordered_json tail;

    ordered_json feature_counts;
    feature_counts["file"] = doc.file_feature_count;
    ordered_json scopes = ordered_json::array();
    for (const auto& [addr, count] : doc.scope_feature_counts) {
        ordered_json c;
        c["address"] = address_to_json(addr);
        c["count"] = count;
        scopes.push_back(std::move(c));
    }
    feature_counts[dynamic ? "processes" : "functions"] = std::move(scopes);
    // capa-cpp extension. These numbers are the one part of the document the feature
    // filter changes, and a silently smaller count is worse than a flagged one.
    if (doc.feature_counts_filtered) feature_counts["filtered"] = true;
    tail["feature_counts"] = std::move(feature_counts);

    if (!dynamic) {
        ordered_json libs = ordered_json::array();
        for (const auto& [addr, name] : doc.library_functions) {
            ordered_json l;
            l["address"] = address_to_json(addr);
            l["name"] = name;
            libs.push_back(std::move(l));
        }
        tail["library_functions"] = std::move(libs);
    }

    // ---- capa-cpp extensions ----
    // Distinguishes "the layout was not computed" from "nothing matched", which is what
    // an empty layout otherwise reads as. See Doc::layout_omitted.
    if (doc.layout_omitted) tail["layout_omitted"] = true;
    // Says that `matches` holds addresses rather than (address, evidence) pairs. Not said
    // when the leaf shape is in force: that shape is pairs again, and a reader that keyed
    // off this one would take the second element for a match tree.
    if (doc.matches_only && !doc.match_evidence) tail["matches_only"] = true;
    // Says that the second element of each pair is one evidence leaf, not a match tree.
    if (doc.match_evidence) tail["match_evidence"] = true;
    // Says that an element is a pair only where a tree was kept, and a bare address
    // otherwise. At most one of these three names the element shape, and none means every
    // element is an (address, tree) pair.
    if (doc.sparse_evidence && !doc.matches_only && !doc.match_evidence) tail["sparse_evidence"] = true;
    // The memory regions a minidump run scanned.
    if (!doc.regions.empty()) {
        ordered_json regions = ordered_json::array();
        for (const RegionInfo& r : doc.regions) {
            ordered_json rj;
            rj["base"] = r.base;
            rj["size"] = r.size;
            rj["name"] = r.name;
            rj["kind"] = r.kind;
            rj["path"] = r.path;
            rj["arch"] = r.arch;
            regions.push_back(std::move(rj));
        }
        tail["regions"] = std::move(regions);
    }
    return tail;
}

// The document's shape, once, for either encoding. Members follow capa's declaration
// order (ResultDocument: meta, rules; RuleMatches: meta, source, matches).
void write_document(DocEncoder& e, const RenderInput& in) {
    const Doc& doc = in.doc;
    const bool dynamic = doc.flavor == Flavor::Dynamic;

    // ---- meta ----
    ordered_json head;
    head["timestamp"] = iso_timestamp();
    head["version"] = CAPA_CPP_VERSION;
    if (!in.argv.empty()) head["argv"] = in.argv;  // capa: None (so absent) when empty
    ordered_json sample;
    sample["md5"] = doc.hashes.md5;
    sample["sha1"] = doc.hashes.sha1;
    sample["sha256"] = doc.hashes.sha256;
    sample["path"] = in.input_path;
    head["sample"] = std::move(sample);
    head["flavor"] = dynamic ? "dynamic" : "static";

    ordered_json analysis_head;
    analysis_head["format"] = doc.format;
    analysis_head["arch"] = doc.arch;
    analysis_head["os"] = doc.os;
    analysis_head["extractor"] = doc.extractor_name;
    analysis_head["rules"] = doc.rule_paths;
    if (!dynamic) analysis_head["base_address"] = address_to_json(doc.base_address);
    const ordered_json tail = analysis_tail(doc);

    // Counted first because MessagePack declares a map's size before its contents; the
    // filter here is the same one the loop below applies.
    std::size_t rule_count = 0;
    for (const auto& [name, results] : in.matches) {
        auto rule = in.ruleset.get(name);
        if (rule && rule->is_subscope) continue;
        ++rule_count;
    }

    e.begin_map(2);
    e.key("meta");
    e.begin_map(head.size() + 1);
    write_members(e, head);
    e.key("analysis");
    e.begin_map(analysis_head.size() + 1 + tail.size());
    write_members(e, analysis_head);
    e.key("layout");
    write_layout(e, doc);
    write_members(e, tail);
    e.end_map();
    e.end_map();

    // ---- rules ----
    MatchWriter writer(in);
    e.key("rules");
    e.begin_map(rule_count);
    for (const auto& [name, results] : in.matches) {
        auto rule = in.ruleset.get(name);
        if (rule && rule->is_subscope) continue;  // spliced into their parents instead

        e.key(name);
        e.begin_map(3);
        e.key("meta");
        e.value(rule ? rule_meta_json(*rule) : ordered_json::object());
        e.key("source");
        e.value(ordered_json(rule ? rule->definition : std::string()));

        e.key("matches");
        e.begin_array(results.size());
        for (const auto& [addr, evidence] : results) {
            // capa-cpp extension: the address, and the one leaf that completed the match.
            if (doc.match_evidence) {
                e.value(ordered_json::array({address_to_json(addr), evidence_leaf_json(evidence)}));
                continue;
            }
            // capa-cpp extension: the address alone (`--matches-only`), said once in
            // `meta.analysis.matches_only` rather than by a placeholder per match.
            if (doc.matches_only) {
                e.value(address_to_json(addr));
                continue;
            }
            // capa-cpp extension: a match whose tree `--max-match-trees` dropped, as its
            // address alone (`--sparse-evidence`).
            if (doc.sparse_evidence && is_truncated_match(evidence)) {
                e.value(address_to_json(addr));
                continue;
            }
            // The one place the peak is set: a single match tree, built and dropped.
            e.value(ordered_json::array({address_to_json(addr), writer.match(evidence)}));
        }
        e.end_array();

        e.end_map();
    }
    e.end_map();

    e.end_map();
}

// ---------------------------------------------------------------------------
// text-rendering helpers
// ---------------------------------------------------------------------------

// rules that were matched only as a subrule of another rule (capa find_subrule_matches):
// collect every successful match: feature value across all match trees.
std::unordered_set<std::string> collect_subrule_matches(const MatchResults& matches) {
    std::unordered_set<std::string> out;
    std::function<void(const Result&)> walk = [&](const Result& res) {
        if (!res.node_is_statement && res.feature.type == FeatureType::MatchedRule && res.success)
            out.insert(res.feature.s);
        for (const auto& c : res.children) walk(c);
    };
    for (const auto& [name, results] : matches)
        for (const auto& [addr, evidence] : results)
            if (evidence) walk(*evidence);  // a capped match kept no tree to walk
    return out;
}

// non-lib capability rules, hidden if only matched as a subrule; sorted by (namespace, name)
std::vector<std::shared_ptr<Rule>> capability_rules(const RenderInput& in) {
    // Walking in.matches only finds the `match:` features in trees that survived the
    // per-rule tree cap, so a rule whose every subrule appearance was capped away would
    // wrongly be shown as a top-level capability. The matcher collects the same set from
    // every tree; use it when it is there.
    std::unordered_set<std::string> walked;
    if (in.subrule_matches == nullptr) walked = collect_subrule_matches(in.matches);
    const std::unordered_set<std::string>& subrules =
        in.subrule_matches != nullptr ? *in.subrule_matches : walked;
    std::vector<std::shared_ptr<Rule>> out;
    for (const auto& [name, results] : in.matches) {
        auto rule = in.ruleset.get(name);
        if (!rule || rule->is_lib || rule->is_subscope) continue;
        if (subrules.count(name)) continue;
        out.push_back(rule);
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a->namespace_ != b->namespace_) return a->namespace_ < b->namespace_;
        return a->name < b->name;
    });
    return out;
}

std::size_t match_count(const MatchResults& matches, const std::string& name) {
    auto it = matches.find(name);
    return it == matches.end() ? 0 : it->second.size();
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        auto nl = s.find('\n', start);
        if (nl == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, nl - start));
        start = nl + 1;
    }
    return out;
}

// simple 2-column table renderer; multi-line second-column cells align under col 2.
std::string table(const std::string& c1, const std::string& c2,
                  const std::vector<std::pair<std::string, std::string>>& rows) {
    std::size_t w1 = c1.size();
    for (const auto& [a, b] : rows) {
        for (const auto& line : split_lines(a)) w1 = std::max(w1, line.size());
    }
    std::ostringstream os;
    auto pad = [](const std::string& s, std::size_t w) {
        return s.size() >= w ? s : s + std::string(w - s.size(), ' ');
    };
    if (!c1.empty() || !c2.empty()) {
        os << pad(c1, w1) << " | " << c2 << "\n";
        os << std::string(w1, '-') << "-+-"
           << std::string(std::max<std::size_t>(c2.size(), 1), '-') << "\n";
    }
    std::string cont(w1, ' ');
    for (const auto& [a, b] : rows) {
        auto blines = split_lines(b);
        os << pad(a, w1) << " | " << (blines.empty() ? "" : blines[0]) << "\n";
        for (std::size_t k = 1; k < blines.size(); ++k)
            os << cont << " | " << blines[k] << "\n";
    }
    return os.str();
}

}  // namespace

// ---------------------------------------------------------------------------
// public renderers
// ---------------------------------------------------------------------------

void render_json_to(const RenderInput& in, const JsonWriter& write, DocFormat format) {
    JsonSink sink(write);
    if (format == DocFormat::MsgPack) {
        MsgpackEncoder e(sink);
        write_document(e, in);
    } else {
        JsonEncoder e(sink);
        write_document(e, in);
    }
    sink.flush();
}

std::string render_json(const RenderInput& in) {
    std::string out;
    render_json_to(in, [&out](const char* data, std::size_t size) { out.append(data, size); });
    return out;
}

std::string render_default(const RenderInput& in) {
    std::ostringstream os;

    const Doc& doc = in.doc;

    os << table("", "",
                {{"md5", doc.hashes.md5},
                 {"sha1", doc.hashes.sha1},
                 {"sha256", doc.hashes.sha256},
                 {"analysis", doc.flavor == Flavor::Dynamic ? "dynamic" : "static"},
                 {"os", doc.os},
                 {"format", doc.format},
                 {"arch", doc.arch},
                 {"path", in.input_path}});
    os << "\n";

    // ATT&CK / MBC aggregation across capability rules
    auto rules = capability_rules(in);

    std::map<std::string, std::set<std::string>> attack;  // tactic -> {technique [id]}
    std::map<std::string, std::set<std::string>> mbc;     // objective -> {behavior [id]}
    for (const auto& rule : rules) {
        for (const auto& a : rule->attack) {
            Spec s = parse_spec(a);
            if (s.parts.empty()) continue;
            std::string tech = s.parts.size() > 1 ? s.parts[1] : "";
            if (s.parts.size() > 2) tech += "::" + s.parts[2];
            if (!s.id.empty()) tech += " [" + s.id + "]";
            attack[s.parts[0]].insert(tech);
        }
        for (const auto& b : rule->mbc) {
            Spec s = parse_spec(b);
            if (s.parts.empty()) continue;
            std::string beh = s.parts.size() > 1 ? s.parts[1] : "";
            if (!s.id.empty()) beh += " [" + s.id + "]";
            mbc[s.parts[0]].insert(beh);
        }
    }
    if (!attack.empty()) {
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto& [tactic, techs] : attack) {
            std::string joined;
            for (const auto& t : techs) { if (!joined.empty()) joined += "\n"; joined += t; }
            std::string up = tactic;
            std::transform(up.begin(), up.end(), up.begin(), ::toupper);
            rows.emplace_back(up, joined);
        }
        os << table("ATT&CK Tactic", "ATT&CK Technique", rows) << "\n";
    }
    if (!mbc.empty()) {
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto& [obj, behs] : mbc) {
            std::string joined;
            for (const auto& b : behs) { if (!joined.empty()) joined += "\n"; joined += b; }
            std::string up = obj;
            std::transform(up.begin(), up.end(), up.begin(), ::toupper);
            rows.emplace_back(up, joined);
        }
        os << table("MBC Objective", "MBC Behavior", rows) << "\n";
    }

    // capability table
    if (rules.empty()) {
        os << "no capabilities found\n";
    } else {
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto& rule : rules) {
            std::size_t n = match_count(in.matches, rule->name);
            std::string cap = rule->name;
            if (n > 1) cap += " (" + std::to_string(n) + " matches)";
            rows.emplace_back(cap, rule->namespace_);
        }
        os << table("Capability", "Namespace", rows);
    }

    return os.str();
}

// ---- vverbose ----

std::string render_vverbose(const RenderInput& in) {
    std::ostringstream os;

    // rule ordering: by (namespace, name), skip subscope rules
    std::vector<std::shared_ptr<Rule>> rules;
    for (const auto& [name, results] : in.matches) {
        auto rule = in.ruleset.get(name);
        if (!rule || rule->is_subscope) continue;
        rules.push_back(rule);
    }
    std::sort(rules.begin(), rules.end(), [](const auto& a, const auto& b) {
        if (a->namespace_ != b->namespace_) return a->namespace_ < b->namespace_;
        return a->name < b->name;
    });

    for (const auto& rule : rules) {
        const auto& results = in.matches.at(rule->name);
        os << rule->name;
        if (results.size() > 1) os << " (" << results.size() << " matches)";
        if (rule->is_lib) os << " (library rule)";
        os << "\n";
        if (!rule->namespace_.empty()) os << "  namespace  " << rule->namespace_ << "\n";
        if (!rule->authors.empty()) {
            os << "  author     ";
            for (std::size_t k = 0; k < rule->authors.size(); ++k) {
                if (k) os << ", ";
                os << rule->authors[k];
            }
            os << "\n";
        }
        // the label must follow the flavor of *this* analysis: preferring the
        // dynamic scope unconditionally would mislabel every static match.
        Scope sc = in.doc.flavor == Flavor::Dynamic
                       ? rule->scopes.dynamic_scope.value_or(
                             rule->scopes.static_scope.value_or(Scope::FILE))
                       : rule->scopes.static_scope.value_or(
                             rule->scopes.dynamic_scope.value_or(Scope::FILE));
        os << "  scope      " << scope_to_string(sc) << "\n";
        for (const auto& m : rule->mbc) os << "  mbc        " << m << "\n";
        if (!rule->description.empty()) os << "  description " << rule->description << "\n";

        MatchCtx ctx{in.ruleset, in.matches};
        int shown = 0;
        for (const auto& [addr, evidence] : results) {
            if (rule->is_lib && shown >= 1) break;  // lib rules: only first match
            os << "  " << scope_to_string(sc) << " @ " << format_address(addr) << "\n";
            os << render_match_tree(ctx, evidence, 2);
            ++shown;
        }
        os << "\n";
    }

    if (rules.empty()) os << "no capabilities found\n";
    return os.str();
}

}  // namespace capa::render
