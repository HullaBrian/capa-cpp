#include "freeze.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <tuple>

#include <zlib.h>

namespace capa::freeze {

using nlohmann::json;
using nlohmann::ordered_json;

namespace {

const char* type_name(AddressType t) {
    switch (t) {
        case AddressType::ABSOLUTE: return "absolute";
        case AddressType::RELATIVE_VA: return "relative";
        case AddressType::FILE_OFFSET: return "file";
        case AddressType::DN_TOKEN: return "dn token";
        case AddressType::DN_TOKEN_OFFSET: return "dn token offset";
        case AddressType::PROCESS: return "process";
        case AddressType::THREAD: return "thread";
        case AddressType::CALL: return "call";
        case AddressType::NO_ADDRESS: return "no address";
    }
    return "no address";
}

std::uint64_t as_u64(const json& v) {
    if (v.is_number_unsigned()) return v.get<std::uint64_t>();
    if (v.is_number_integer()) return static_cast<std::uint64_t>(v.get<std::int64_t>());
    throw FreezeError("expected an integer, got " + v.dump());
}

std::uint32_t as_u32(const json& v) { return static_cast<std::uint32_t>(as_u64(v)); }

// The first of `keys` present in `j`: capa's field name, then its alias.
const json& field(const json& j, std::initializer_list<const char*> keys) {
    for (const char* k : keys) {
        auto it = j.find(k);
        if (it != j.end()) return *it;
    }
    throw FreezeError(std::string("missing field: ") + *keys.begin());
}

const json* optional_field(const json& j, std::initializer_list<const char*> keys) {
    for (const char* k : keys) {
        auto it = j.find(k);
        if (it != j.end() && !it->is_null()) return &*it;
    }
    return nullptr;
}

ordered_json int_json(const Feature& f) {
    if (f.vkind == ValueKind::Float) return ordered_json(f.f);
    if (f.big) return ordered_json(static_cast<std::uint64_t>(f.i));
    return ordered_json(f.i);
}

void set_int(Feature& f, const json& v) {
    if (v.is_number_float()) {
        f.vkind = ValueKind::Float;
        f.f = v.get<double>();
        return;
    }
    if (v.is_number_unsigned()) {
        const std::uint64_t u = v.get<std::uint64_t>();
        f.i = static_cast<std::int64_t>(u);
        f.big = u >= (std::uint64_t{1} << 63);
        return;
    }
    if (v.is_number_integer()) {
        f.i = v.get<std::int64_t>();
        return;
    }
    throw FreezeError("expected a number, got " + v.dump());
}

std::string to_hex(const std::string& raw) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        out += digits[c >> 4];
        out += digits[c & 0xf];
    }
    return out;
}

std::string from_hex(const std::string& hex) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    std::size_t k = 0;
    while (k < hex.size()) {
        if (hex[k] == ' ') {
            ++k;
            continue;
        }
        if (k + 1 >= hex.size() || nibble(hex[k]) < 0 || nibble(hex[k + 1]) < 0)
            throw FreezeError("invalid bytes value: " + hex);
        out.push_back(static_cast<char>((nibble(hex[k]) << 4) | nibble(hex[k + 1])));
        k += 2;
    }
    return out;
}

// The feature as pydantic's model_dump_json() spells it *without* exclude_none: the key
// capa's dumps sorts features by.
std::string sort_key(const Feature& f) {
    ordered_json j = feature_to_json(f);
    if (f.type == FeatureType::Property && !j.contains("access")) {
        // field order: type, access, property, description
        ordered_json k;
        k["type"] = "property";
        k["access"] = nullptr;
        k["property"] = j["property"];
        j = std::move(k);
    }
    if (!j.contains("description")) j["description"] = nullptr;
    return j.dump(-1, ' ', false, ordered_json::error_handler_t::replace);
}

using Located = std::pair<Address, Feature>;

// (address, feature) sorted as capa sorts them: address, then the feature's JSON.
std::vector<FeaturePair> sorted_pairs(std::vector<FeaturePair> pairs) {
    std::vector<std::pair<std::string, FeaturePair>> keyed;
    keyed.reserve(pairs.size());
    for (auto& p : pairs) keyed.emplace_back(sort_key(p.first), std::move(p));
    std::stable_sort(keyed.begin(), keyed.end(), [](const auto& a, const auto& b) {
        if (address_less(a.second.second, b.second.second)) return true;
        if (address_less(b.second.second, a.second.second)) return false;
        return a.first < b.first;
    });
    std::vector<FeaturePair> out;
    out.reserve(keyed.size());
    for (auto& [k, p] : keyed) out.push_back(std::move(p));
    return out;
}

ordered_json located_features(const char* scope_key, const Address& scope,
                              const std::vector<FeaturePair>& pairs) {
    ordered_json arr = ordered_json::array();
    for (const auto& [feature, addr] : sorted_pairs(pairs)) {
        ordered_json e;
        e[scope_key] = address_to_json(scope);
        e["address"] = address_to_json(addr);
        e["feature"] = feature_to_json(feature);
        arr.push_back(std::move(e));
    }
    return arr;
}

ordered_json global_features(const std::vector<FeaturePair>& pairs) {
    std::vector<std::pair<std::string, const Feature*>> keyed;
    for (const auto& p : pairs) keyed.emplace_back(sort_key(p.first), &p.first);
    std::stable_sort(keyed.begin(), keyed.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    ordered_json arr = ordered_json::array();
    for (const auto& [k, f] : keyed) arr.push_back(ordered_json{{"feature", feature_to_json(*f)}});
    return arr;
}

ordered_json file_features(const std::vector<FeaturePair>& pairs) {
    ordered_json arr = ordered_json::array();
    for (const auto& [feature, addr] : sorted_pairs(pairs)) {
        ordered_json e;
        e["address"] = address_to_json(addr);
        e["feature"] = feature_to_json(feature);
        arr.push_back(std::move(e));
    }
    return arr;
}

template <class H>
void sort_handles(std::vector<H>& handles) {
    std::stable_sort(handles.begin(), handles.end(),
                     [](const H& a, const H& b) { return address_less(a.address, b.address); });
}

ordered_json header(int, const Address& base, const SampleHashes& hashes, const char* flavor,
                    const std::string& extractor_name, bool reproducible) {
    ordered_json doc;
    doc["version"] = CURRENT_VERSION;
    doc["base_address"] = address_to_json(base);
    doc["sample_hashes"] = ordered_json{{"md5", hashes.md5}, {"sha1", hashes.sha1}, {"sha256", hashes.sha256}};
    doc["flavor"] = flavor;
    doc["extractor"] = ordered_json{{"name", extractor_name},
                                    {"version", reproducible ? std::string() : std::string(engine_version())}};
    return doc;
}

std::string compress(const std::string& text) {
    uLongf size = compressBound(static_cast<uLong>(text.size()));
    std::string out(size, '\0');
    if (compress2(reinterpret_cast<Bytef*>(out.data()), &size,
                  reinterpret_cast<const Bytef*>(text.data()), static_cast<uLong>(text.size()),
                  Z_DEFAULT_COMPRESSION) != Z_OK)
        throw FreezeError("zlib compression failed");
    out.resize(size);
    return out;
}

std::string decompress(const char* data, std::size_t size) {
    z_stream zs{};
    if (inflateInit(&zs) != Z_OK) throw FreezeError("zlib init failed");
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data));
    zs.avail_in = static_cast<uInt>(size);
    std::string out;
    std::vector<char> buf(1 << 20);
    int rc = Z_OK;
    while (rc != Z_STREAM_END) {
        zs.next_out = reinterpret_cast<Bytef*>(buf.data());
        zs.avail_out = static_cast<uInt>(buf.size());
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            inflateEnd(&zs);
            throw FreezeError("corrupt freeze file: zlib error " + std::to_string(rc));
        }
        out.append(buf.data(), buf.size() - zs.avail_out);
        if (rc == Z_OK && zs.avail_in == 0 && zs.avail_out != 0) {
            inflateEnd(&zs);
            throw FreezeError("corrupt freeze file: truncated zlib stream");
        }
    }
    inflateEnd(&zs);
    return out;
}

std::vector<FeaturePair> load_located(const json& arr) {
    std::vector<FeaturePair> out;
    out.reserve(arr.size());
    for (const json& e : arr)
        out.emplace_back(feature_from_json(field(e, {"feature"})), address_from_json(field(e, {"address"})));
    return out;
}

}  // namespace

const char* engine_version() { return "capa-cpp 0.2.0"; }

// ---------------------------------------------------------------------------
// models
// ---------------------------------------------------------------------------

ordered_json address_to_json(const Address& a) {
    ordered_json j;
    j["type"] = type_name(a.type);
    switch (a.type) {
        case AddressType::ABSOLUTE:
        case AddressType::RELATIVE_VA:
        case AddressType::FILE_OFFSET:
        case AddressType::DN_TOKEN:
            j["value"] = a.value;
            break;
        case AddressType::DN_TOKEN_OFFSET:
            j["value"] = ordered_json::array({a.value, a.id});
            break;
        case AddressType::PROCESS:
            j["value"] = ordered_json::array({a.ppid, a.pid});
            break;
        case AddressType::THREAD:
            j["value"] = ordered_json::array({a.ppid, a.pid, a.tid});
            break;
        case AddressType::CALL:
            j["value"] = ordered_json::array({a.ppid, a.pid, a.tid, a.id});
            break;
        case AddressType::NO_ADDRESS:
            break;  // value is None, and capa writes with exclude_none
    }
    return j;
}

Address address_from_json(const json& j) {
    const std::string type = field(j, {"type"}).get<std::string>();
    const json* v = optional_field(j, {"value"});
    auto need = [&](std::size_t n) -> const json& {
        if (!v || !v->is_array() || v->size() != n)
            throw FreezeError("address of type " + type + " needs " + std::to_string(n) + " values");
        return *v;
    };
    auto scalar = [&]() -> std::uint64_t {
        if (!v) throw FreezeError("address of type " + type + " needs a value");
        return as_u64(*v);
    };
    if (type == "absolute") return Address::absolute(scalar());
    if (type == "relative") return Address::relative(scalar());
    if (type == "file") return Address::file_offset(scalar());
    if (type == "dn token") return Address::dn_token(scalar());
    if (type == "dn token offset") {
        const json& t = need(2);
        return Address::dn_token_offset(as_u64(t[0]), as_u64(t[1]));
    }
    if (type == "process") {
        const json& t = need(2);
        return Address::process(as_u32(t[1]), as_u32(t[0]));
    }
    if (type == "thread") {
        const json& t = need(3);
        return Address::thread(Address::process(as_u32(t[1]), as_u32(t[0])), as_u32(t[2]));
    }
    if (type == "call") {
        const json& t = need(4);
        return Address::call(Address::thread(Address::process(as_u32(t[1]), as_u32(t[0])), as_u32(t[2])),
                             as_u64(t[3]));
    }
    if (type == "no address") return Address::no_address();
    throw FreezeError("unknown address type: " + type);
}

bool address_less(const Address& a, const Address& b) {
    if (a.type != b.type) return std::string(type_name(a.type)) < type_name(b.type);
    switch (a.type) {
        case AddressType::NO_ADDRESS: return false;
        case AddressType::DN_TOKEN_OFFSET: return std::tie(a.value, a.id) < std::tie(b.value, b.id);
        default: return a < b;  // within one kind, Address orders by the same tuple
    }
}

ordered_json feature_to_json(const Feature& f) {
    ordered_json j;
    auto str = [&](const char* type, const char* key) {
        j["type"] = type;
        j[key] = f.s;
    };
    switch (f.type) {
        case FeatureType::OS: str("os", "os"); break;
        case FeatureType::Arch: str("arch", "arch"); break;
        case FeatureType::Format: str("format", "format"); break;
        case FeatureType::MatchedRule: str("match", "match"); break;
        case FeatureType::Characteristic: str("characteristic", "characteristic"); break;
        case FeatureType::Export: str("export", "export"); break;
        case FeatureType::Import: str("import", "import_"); break;
        case FeatureType::Section: str("section", "section"); break;
        case FeatureType::FunctionName: str("function name", "function_name"); break;
        case FeatureType::Substring: str("substring", "substring"); break;
        case FeatureType::Regex: str("regex", "regex"); break;
        case FeatureType::String: str("string", "string"); break;
        case FeatureType::Class: str("class", "class_"); break;
        case FeatureType::Namespace: str("namespace", "namespace"); break;
        case FeatureType::API: str("api", "api"); break;
        case FeatureType::Mnemonic: str("mnemonic", "mnemonic"); break;
        case FeatureType::BasicBlock: j["type"] = "basic block"; break;
        case FeatureType::Property:
            j["type"] = "property";
            if (!f.access.empty()) j["access"] = f.access;
            j["property"] = f.s;
            break;
        case FeatureType::Number:
            j["type"] = "number";
            j["number"] = int_json(f);
            break;
        case FeatureType::Offset:
            j["type"] = "offset";
            j["offset"] = int_json(f);
            break;
        case FeatureType::Bytes:
            j["type"] = "bytes";
            j["bytes"] = to_hex(f.s);
            break;
        case FeatureType::OperandNumber:
            j["type"] = "operand number";
            j["index"] = f.index;
            j["operand_number"] = int_json(f);
            break;
        case FeatureType::OperandOffset:
            j["type"] = "operand offset";
            j["index"] = f.index;
            j["operand_offset"] = int_json(f);
            break;
    }
    if (!f.description.empty()) j["description"] = f.description;
    return j;
}

Feature feature_from_json(const json& j) {
    const std::string type = field(j, {"type"}).get<std::string>();
    std::string desc;
    if (const json* d = optional_field(j, {"description"})) desc = d->get<std::string>();
    auto s = [&](std::initializer_list<const char*> keys) { return field(j, keys).get<std::string>(); };
    if (type == "os") return Feature::os(s({"os"}), desc);
    if (type == "arch") return Feature::arch(s({"arch"}), desc);
    if (type == "format") return Feature::format(s({"format"}), desc);
    if (type == "match") return Feature::matched_rule(s({"match"}), desc);
    if (type == "characteristic") return Feature::characteristic(s({"characteristic"}), desc);
    if (type == "export") return Feature::export_(s({"export"}), desc);
    if (type == "import") return Feature::import_(s({"import_", "import"}), desc);
    if (type == "section") return Feature::section(s({"section"}), desc);
    if (type == "function name") return Feature::function_name(s({"function_name", "function name"}), desc);
    if (type == "substring") return Feature::substring(s({"substring"}), desc);
    if (type == "regex") return Feature::regex(s({"regex"}), desc);
    if (type == "string") return Feature::string(s({"string"}), desc);
    if (type == "class") return Feature::klass(s({"class_", "class"}), desc);
    if (type == "namespace") return Feature::namespace_(s({"namespace"}), desc);
    if (type == "api") return Feature::api(s({"api"}), desc);
    if (type == "mnemonic") return Feature::mnemonic(s({"mnemonic"}), desc);
    if (type == "basic block") return Feature::basic_block(desc);
    if (type == "property") {
        std::string access;
        if (const json* a = optional_field(j, {"access"})) access = a->get<std::string>();
        return Feature::property(s({"property"}), access, desc);
    }
    if (type == "bytes") return Feature::bytes(from_hex(s({"bytes"})), desc);
    if (type == "number") {
        Feature f = Feature::number(0, desc);
        set_int(f, field(j, {"number"}));
        return f;
    }
    if (type == "offset") {
        Feature f = Feature::offset(0, desc);
        set_int(f, field(j, {"offset"}));
        return f;
    }
    if (type == "operand number" || type == "operand offset") {
        const int index = field(j, {"index"}).get<int>();
        Feature f = type == "operand number" ? Feature::operand_number(index, 0, desc)
                                             : Feature::operand_offset(index, 0, desc);
        set_int(f, field(j, {type == "operand number" ? "operand_number" : "operand_offset",
                             type == "operand number" ? "operand number" : "operand offset"}));
        return f;
    }
    throw FreezeError("unknown feature type: " + type);
}

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------

bool is_freeze(const std::string& buf) {
    return buf.size() >= MAGIC_SIZE && buf.compare(0, MAGIC_SIZE, MAGIC) == 0;
}

bool is_freeze_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    char head[MAGIC_SIZE] = {};
    if (!f.read(head, MAGIC_SIZE)) return false;
    return std::string(head, MAGIC_SIZE) == MAGIC;
}

Frozen loads(const std::string& json_text) {
    json doc;
    try {
        doc = json::parse(json_text);
    } catch (const json::exception& e) {
        throw FreezeError(std::string("invalid freeze document: ") + e.what());
    }
    try {
        Frozen out;
        out.version = field(doc, {"version"}).get<int>();
        if (out.version != CURRENT_VERSION)
            throw FreezeError("unsupported freeze format version: " + std::to_string(out.version));
        out.flavor = field(doc, {"flavor"}).get<std::string>();
        const json& ex = field(doc, {"extractor"});
        out.extractor_name = field(ex, {"name"}).get<std::string>();
        if (const json* v = optional_field(ex, {"version"})) out.extractor_version = v->get<std::string>();

        const Address base = address_from_json(field(doc, {"base_address", "base address"}));
        const json& h = field(doc, {"sample_hashes"});
        const SampleHashes hashes{field(h, {"md5"}).get<std::string>(), field(h, {"sha1"}).get<std::string>(),
                                  field(h, {"sha256"}).get<std::string>()};
        const json& features = field(doc, {"features"});

        std::vector<FeaturePair> global;
        for (const json& g : field(features, {"global_", "global"}))
            global.emplace_back(feature_from_json(field(g, {"feature"})), Address::no_address());
        std::vector<FeaturePair> file = load_located(field(features, {"file"}));

        if (out.flavor == "static") {
            auto ex = std::make_unique<NullStaticFeatureExtractor>();
            ex->base_address = base;
            ex->sample_hashes = hashes;
            ex->global_features = std::move(global);
            ex->file_features = std::move(file);
            for (const json& fj : field(features, {"functions"})) {
                NullFunction f;
                f.features = load_located(field(fj, {"features"}));
                for (const json& bj : field(fj, {"basic_blocks", "basic blocks"})) {
                    NullBasicBlock bb;
                    bb.features = load_located(field(bj, {"features"}));
                    for (const json& ij : field(bj, {"instructions"})) {
                        NullInstruction insn;
                        insn.features = load_located(field(ij, {"features"}));
                        bb.instructions[address_from_json(field(ij, {"address"}))] = std::move(insn);
                    }
                    f.basic_blocks[address_from_json(field(bj, {"address"}))] = std::move(bb);
                }
                ex->functions[address_from_json(field(fj, {"address"}))] = std::move(f);
            }
            out.static_extractor = std::move(ex);
        } else if (out.flavor == "dynamic") {
            auto ex = std::make_unique<NullDynamicFeatureExtractor>();
            ex->base_address = base;
            ex->sample_hashes = hashes;
            ex->global_features = std::move(global);
            ex->file_features = std::move(file);
            for (const json& pj : field(features, {"processes"})) {
                NullProcess p;
                p.name = field(pj, {"name"}).get<std::string>();
                p.features = load_located(field(pj, {"features"}));
                for (const json& tj : field(pj, {"threads"})) {
                    NullThread t;
                    t.features = load_located(field(tj, {"features"}));
                    for (const json& cj : field(tj, {"calls"})) {
                        NullCall c;
                        c.name = field(cj, {"name"}).get<std::string>();
                        c.features = load_located(field(cj, {"features"}));
                        t.calls[address_from_json(field(cj, {"address"}))] = std::move(c);
                    }
                    p.threads[address_from_json(field(tj, {"address"}))] = std::move(t);
                }
                ex->processes[address_from_json(field(pj, {"address"}))] = std::move(p);
            }
            ex->index_calls();
            out.dynamic_extractor = std::move(ex);
        } else {
            throw FreezeError("unsupported freeze format flavor: " + out.flavor);
        }
        return out;
    } catch (const json::exception& e) {
        throw FreezeError(std::string("invalid freeze document: ") + e.what());
    }
}

std::string decompress_document(const std::string& buf) {
    if (!is_freeze(buf)) throw FreezeError("missing magic header");
    return decompress(buf.data() + MAGIC_SIZE, buf.size() - MAGIC_SIZE);
}

Frozen load(const std::string& buf) { return loads(decompress_document(buf)); }

Frozen load_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw FreezeError("cannot open " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return load(ss.str());
}

std::string dumps(const StaticFeatureExtractor& ex, const std::string& extractor_name, bool reproducible) {
    ordered_json doc = header(CURRENT_VERSION, ex.get_base_address(), ex.get_sample_hashes(), "static",
                              extractor_name, reproducible);
    ordered_json features;
    features["global_"] = global_features(ex.extract_global_features());
    features["file"] = file_features(ex.extract_file_features());

    std::vector<FunctionHandle> functions = ex.get_functions();
    sort_handles(functions);
    ordered_json fs = ordered_json::array();
    for (const FunctionHandle& fh : functions) {
        std::vector<BBHandle> bbs = ex.get_basic_blocks(fh);
        sort_handles(bbs);
        ordered_json bbs_json = ordered_json::array();
        for (const BBHandle& bbh : bbs) {
            std::vector<InsnHandle> insns = ex.get_instructions(fh, bbh);
            sort_handles(insns);
            ordered_json insns_json = ordered_json::array();
            for (const InsnHandle& ih : insns) {
                ordered_json i;
                i["address"] = address_to_json(ih.address);
                i["features"] = located_features("instruction", ih.address, ex.extract_insn_features(fh, bbh, ih));
                insns_json.push_back(std::move(i));
            }
            ordered_json b;
            b["address"] = address_to_json(bbh.address);
            b["features"] = located_features("basic_block", bbh.address, ex.extract_basic_block_features(fh, bbh));
            b["instructions"] = std::move(insns_json);
            bbs_json.push_back(std::move(b));
        }
        ordered_json f;
        f["address"] = address_to_json(fh.address);
        f["features"] = located_features("function", fh.address, ex.extract_function_features(fh));
        f["basic_blocks"] = std::move(bbs_json);
        fs.push_back(std::move(f));
    }
    features["functions"] = std::move(fs);
    doc["features"] = std::move(features);
    return doc.dump(-1, ' ', false, ordered_json::error_handler_t::replace);
}

std::string dumps(const DynamicFeatureExtractor& ex, const std::string& extractor_name, bool reproducible) {
    ordered_json doc = header(CURRENT_VERSION, ex.get_base_address(), ex.get_sample_hashes(), "dynamic",
                              extractor_name, reproducible);
    ordered_json features;
    features["global_"] = global_features(ex.extract_global_features());
    features["file"] = file_features(ex.extract_file_features());

    std::vector<ProcessHandle> processes = ex.get_processes();
    sort_handles(processes);
    ordered_json ps = ordered_json::array();
    for (const ProcessHandle& ph : processes) {
        std::vector<ThreadHandle> threads = ex.get_threads(ph);
        sort_handles(threads);
        ordered_json ts = ordered_json::array();
        for (const ThreadHandle& th : threads) {
            std::vector<CallHandle> calls = ex.get_calls(ph, th);
            sort_handles(calls);
            ordered_json cs = ordered_json::array();
            for (const CallHandle& ch : calls) {
                ordered_json c;
                c["address"] = address_to_json(ch.address);
                c["name"] = ex.get_call_name(ph, th, ch);
                c["features"] = located_features("call", ch.address, ex.extract_call_features(ph, th, ch));
                cs.push_back(std::move(c));
            }
            ordered_json t;
            t["address"] = address_to_json(th.address);
            t["features"] = located_features("thread", th.address, ex.extract_thread_features(ph, th));
            t["calls"] = std::move(cs);
            ts.push_back(std::move(t));
        }
        ordered_json p;
        p["address"] = address_to_json(ph.address);
        p["name"] = ex.get_process_name(ph);
        p["features"] = located_features("process", ph.address, ex.extract_process_features(ph));
        p["threads"] = std::move(ts);
        ps.push_back(std::move(p));
    }
    features["processes"] = std::move(ps);
    doc["features"] = std::move(features);
    return doc.dump(-1, ' ', false, ordered_json::error_handler_t::replace);
}

std::string dump(const StaticFeatureExtractor& ex, const std::string& extractor_name, bool reproducible) {
    return std::string(MAGIC, MAGIC_SIZE) + compress(dumps(ex, extractor_name, reproducible));
}

std::string dump(const DynamicFeatureExtractor& ex, const std::string& extractor_name, bool reproducible) {
    return std::string(MAGIC, MAGIC_SIZE) + compress(dumps(ex, extractor_name, reproducible));
}

}  // namespace capa::freeze
