#include "rules.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#include <yaml-cpp/yaml.h>

#include "com_database.h"
#include "pyregex.h"

namespace capa {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Scope helpers
// ---------------------------------------------------------------------------

std::string scope_to_string(Scope s) {
    switch (s) {
        case Scope::FILE: return "file";
        case Scope::PROCESS: return "process";
        case Scope::THREAD: return "thread";
        case Scope::SPAN_OF_CALLS: return "span of calls";
        case Scope::CALL: return "call";
        case Scope::FUNCTION: return "function";
        case Scope::BASIC_BLOCK: return "basic block";
        case Scope::INSTRUCTION: return "instruction";
        case Scope::GLOBAL: return "global";
        case Scope::UNSUPPORTED: return "unsupported";
    }
    return "unsupported";
}

std::optional<Scope> scope_from_string(const std::string& s) {
    if (s == "file") return Scope::FILE;
    if (s == "process") return Scope::PROCESS;
    if (s == "thread") return Scope::THREAD;
    if (s == "span of calls") return Scope::SPAN_OF_CALLS;
    if (s == "call") return Scope::CALL;
    if (s == "function") return Scope::FUNCTION;
    if (s == "basic block") return Scope::BASIC_BLOCK;
    if (s == "instruction") return Scope::INSTRUCTION;
    if (s == "global") return Scope::GLOBAL;
    return std::nullopt;
}

bool is_static_scope(Scope s) {
    return s == Scope::FILE || s == Scope::GLOBAL || s == Scope::FUNCTION ||
           s == Scope::BASIC_BLOCK || s == Scope::INSTRUCTION;
}
bool is_dynamic_scope(Scope s) {
    return s == Scope::FILE || s == Scope::GLOBAL || s == Scope::PROCESS ||
           s == Scope::THREAD || s == Scope::SPAN_OF_CALLS || s == Scope::CALL;
}

namespace {

// subscope nesting order (capa.rules.is_subscope_compatible)
const std::vector<Scope> STATIC_SCOPE_ORDER = {Scope::FILE, Scope::FUNCTION, Scope::BASIC_BLOCK,
                                               Scope::INSTRUCTION};
const std::vector<Scope> DYNAMIC_SCOPE_ORDER = {Scope::FILE, Scope::PROCESS, Scope::THREAD,
                                                Scope::SPAN_OF_CALLS, Scope::CALL};

int index_of(const std::vector<Scope>& order, Scope s) {
    for (int k = 0; k < static_cast<int>(order.size()); ++k)
        if (order[k] == s) return k;
    return -1;
}

bool is_subscope_compatible(std::optional<Scope> scope, Scope subscope) {
    if (!scope) return false;
    if (index_of(STATIC_SCOPE_ORDER, subscope) >= 0) {
        int a = index_of(STATIC_SCOPE_ORDER, subscope);
        int b = index_of(STATIC_SCOPE_ORDER, *scope);
        return b >= 0 && a >= b;
    }
    if (index_of(DYNAMIC_SCOPE_ORDER, subscope) >= 0) {
        int a = index_of(DYNAMIC_SCOPE_ORDER, subscope);
        int b = index_of(DYNAMIC_SCOPE_ORDER, *scope);
        return b >= 0 && a >= b;
    }
    return false;
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}
bool ends_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v'; }

std::string strip(const std::string& s) {
    std::size_t a = 0, b = s.size();
    while (a < b && is_space(s[a])) ++a;
    while (b > a && is_space(s[b - 1])) --b;
    return s.substr(a, b - a);
}

// ---------------------------------------------------------------------------
// Python integers
//
// capa's numbers are Python ints. The ones any backend can produce, and any rule can
// usefully name, lie in [-2^63, 2^64), which a (bits, big) pair represents exactly; see
// Feature::big. Anything outside that range is rejected as an invalid rule rather than
// silently wrapped into a different number.
// ---------------------------------------------------------------------------

struct PyInt {
    std::int64_t v = 0;
    bool big = false;  // v holds the bits of a value >= 2^63
};

// From a sign and a magnitude, or nullopt when out of range.
std::optional<PyInt> make_int(bool negative, std::uint64_t magnitude, bool overflow) {
    if (overflow) return std::nullopt;
    PyInt out;
    if (negative) {
        if (magnitude > (std::uint64_t{1} << 63)) return std::nullopt;
        out.v = static_cast<std::int64_t>(std::uint64_t{0} - magnitude);
    } else {
        out.v = static_cast<std::int64_t>(magnitude);
        out.big = magnitude >= (std::uint64_t{1} << 63);
    }
    return out;
}

int digit_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    return 99;
}

// Accumulate `digits` (underscores already validated or removed) in `base`.
bool accumulate(const std::string& digits, int base, std::uint64_t& magnitude, bool& overflow) {
    if (digits.empty()) return false;
    for (char c : digits) {
        const int d = digit_value(c);
        if (d >= base) return false;
        if (magnitude > (UINT64_MAX - static_cast<std::uint64_t>(d)) / static_cast<std::uint64_t>(base))
            overflow = true;
        magnitude = magnitude * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(d);
    }
    return true;
}

// Python's int(s, base) for base 10 and 16: surrounding whitespace, an optional sign, an
// optional 0x for base 16, and single underscores between digits.
std::optional<PyInt> python_int(const std::string& in, int base) {
    std::string s = strip(in);
    std::size_t k = 0;
    bool negative = false;
    if (k < s.size() && (s[k] == '+' || s[k] == '-')) negative = s[k++] == '-';
    bool prefixed = false;
    if (base == 16 && k + 1 < s.size() && s[k] == '0' && (s[k + 1] == 'x' || s[k + 1] == 'X')) {
        k += 2;
        prefixed = true;
    }
    std::string digits;
    bool last_underscore = false;
    for (std::size_t j = k; j < s.size(); ++j) {
        if (s[j] == '_') {
            // allowed between digits, and right after a base prefix
            if (last_underscore || (digits.empty() && !prefixed)) return std::nullopt;
            last_underscore = true;
            continue;
        }
        last_underscore = false;
        digits += s[j];
    }
    if (last_underscore) return std::nullopt;
    std::uint64_t magnitude = 0;
    bool overflow = false;
    if (!accumulate(digits, base, magnitude, overflow)) return std::nullopt;
    return make_int(negative, magnitude, overflow);
}

// capa.rules.parse_int: hex for "0x"/"-0x", else decimal.
PyInt parse_int(const std::string& s) {
    const int base = (starts_with(s, "0x") || starts_with(s, "-0x")) ? 16 : 10;
    auto v = python_int(s, base);
    if (!v) throw InvalidRule{"invalid integer: " + s};
    return *v;
}

// ---------------------------------------------------------------------------
// YAML scalars, typed the way PyYAML types them
//
// capa reads rules with PyYAML, which resolves plain (unquoted) scalars by the YAML 1.1
// rules: `number: 010` is the integer 8, `number: 0x10` is 16, `count(...): 2` is an
// int rather than a string, `string: 123` is an int and therefore an invalid string
// feature, and yes/no/on/off are booleans. yaml-cpp hands every scalar over as text, so
// the resolution is redone here; quoted and block scalars stay strings, as in PyYAML.
// ---------------------------------------------------------------------------

enum class YType { Null, Bool, Int, Float, Str, Seq, Map };

struct YVal {
    YType t = YType::Null;
    std::string s;  // Str (and the source text of every scalar)
    PyInt i;
    double f = 0.0;
    bool b = false;
};

bool all_of(const std::string& s, std::size_t from, std::size_t to, const char* allowed) {
    for (std::size_t k = from; k < to; ++k)
        if (!std::strchr(allowed, s[k])) return false;
    return true;
}

// YAML 1.1 int, as PyYAML's resolver and constructor read it.
std::optional<std::optional<PyInt>> resolve_yaml_int(const std::string& s) {
    if (s.empty()) return std::nullopt;
    std::size_t k = 0;
    bool negative = false;
    if (s[k] == '+' || s[k] == '-') negative = s[k++] == '-';
    if (k >= s.size()) return std::nullopt;
    const std::string body = s.substr(k);
    auto no_us = [](std::string t) {
        t.erase(std::remove(t.begin(), t.end(), '_'), t.end());
        return t;
    };
    std::uint64_t magnitude = 0;
    bool overflow = false;
    auto finish = [&]() -> std::optional<std::optional<PyInt>> {
        return std::optional<PyInt>(make_int(negative, magnitude, overflow));
    };
    if (starts_with(body, "0b")) {
        if (body.size() < 3 || !all_of(body, 2, body.size(), "01_")) return std::nullopt;
        if (!accumulate(no_us(body.substr(2)), 2, magnitude, overflow)) return std::nullopt;
        return finish();
    }
    if (starts_with(body, "0x")) {
        if (body.size() < 3 || !all_of(body, 2, body.size(), "0123456789abcdefABCDEF_"))
            return std::nullopt;
        if (!accumulate(no_us(body.substr(2)), 16, magnitude, overflow)) return std::nullopt;
        return finish();
    }
    if (body == "0") return finish();
    if (body[0] == '0') {  // octal
        if (!all_of(body, 1, body.size(), "01234567_")) return std::nullopt;
        const std::string digits = no_us(body.substr(1));
        if (digits.empty()) return finish();
        if (!accumulate(digits, 8, magnitude, overflow)) return std::nullopt;
        return finish();
    }
    if (body[0] >= '1' && body[0] <= '9') {
        if (all_of(body, 0, body.size(), "0123456789_")) {
            if (!accumulate(no_us(body), 10, magnitude, overflow)) return std::nullopt;
            return finish();
        }
        // sexagesimal: [1-9][0-9_]*(:[0-5]?[0-9])+
        const std::size_t colon = body.find(':');
        if (colon == std::string::npos || !all_of(body, 0, colon, "0123456789_")) return std::nullopt;
        std::vector<std::string> parts{no_us(body.substr(0, colon))};
        std::size_t start = colon + 1;
        while (true) {
            std::size_t next = body.find(':', start);
            std::string part = body.substr(start, next == std::string::npos ? std::string::npos : next - start);
            if (part.empty() || part.size() > 2 || !all_of(part, 0, part.size(), "0123456789") ||
                (part.size() == 2 && part[0] > '5'))
                return std::nullopt;
            parts.push_back(part);
            if (next == std::string::npos) break;
            start = next + 1;
        }
        for (const std::string& part : parts) {
            std::uint64_t v = 0;
            bool o = false;
            if (!accumulate(part, 10, v, o)) return std::nullopt;
            if (magnitude > (UINT64_MAX - v) / 60) overflow = true;
            magnitude = magnitude * 60 + v;
            overflow = overflow || o;
        }
        return finish();
    }
    return std::nullopt;
}

bool resolve_yaml_float(const std::string& s, double& out) {
    static const std::regex re(
        R"(^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$)");
    if (!std::regex_match(s, re)) return false;
    std::string t = s;
    t.erase(std::remove(t.begin(), t.end(), '_'), t.end());
    if (t.find("inf") != std::string::npos || t.find("Inf") != std::string::npos ||
        t.find("INF") != std::string::npos) {
        out = (t[0] == '-' ? -1.0 : 1.0) * HUGE_VAL;
        return true;
    }
    if (t.find("nan") != std::string::npos || t.find("NaN") != std::string::npos ||
        t.find("NAN") != std::string::npos) {
        out = std::nan("");
        return true;
    }
    if (t.find(':') != std::string::npos) {  // sexagesimal float
        double sign = 1.0;
        if (t[0] == '-' || t[0] == '+') {
            sign = t[0] == '-' ? -1.0 : 1.0;
            t = t.substr(1);
        }
        double value = 0.0;
        std::size_t start = 0;
        while (true) {
            std::size_t next = t.find(':', start);
            value = value * 60.0 + std::stod(t.substr(start, next - start));
            if (next == std::string::npos) break;
            start = next + 1;
        }
        out = sign * value;
        return true;
    }
    out = std::stod(t);
    return true;
}

YVal yval(const YAML::Node& n) {
    YVal v;
    if (!n || n.IsNull()) {
        v.t = YType::Null;
        return v;
    }
    if (n.IsSequence()) {
        v.t = YType::Seq;
        return v;
    }
    if (n.IsMap()) {
        v.t = YType::Map;
        return v;
    }
    v.s = n.Scalar();
    const std::string& tag = n.Tag();
    if (tag != "?") {
        // quoted or block scalar ("!"), or an explicit tag
        if (tag == "tag:yaml.org,2002:int") {
            if (auto r = resolve_yaml_int(v.s); r && *r) {
                v.t = YType::Int;
                v.i = **r;
                return v;
            }
        }
        v.t = YType::Str;
        return v;
    }
    const std::string& s = v.s;
    static const std::set<std::string> trues = {"yes", "Yes", "YES", "true", "True", "TRUE", "on", "On", "ON"};
    static const std::set<std::string> falses = {"no", "No", "NO", "false", "False", "FALSE", "off", "Off", "OFF"};
    if (trues.count(s) || falses.count(s)) {
        v.t = YType::Bool;
        v.b = trues.count(s) != 0;
        return v;
    }
    if (auto r = resolve_yaml_int(s)) {
        if (!*r) throw InvalidRule{"integer out of range: " + s};
        v.t = YType::Int;
        v.i = **r;
        return v;
    }
    double f = 0.0;
    if (resolve_yaml_float(s, f)) {
        v.t = YType::Float;
        v.f = f;
        return v;
    }
    v.t = YType::Str;
    return v;
}

// The text of a scalar the way Python's str() would print the loaded value, for the few
// places a non-string meta value becomes a string (a numeric description, say).
std::string yval_text(const YVal& v) {
    switch (v.t) {
        case YType::Bool: return v.b ? "True" : "False";
        case YType::Int: return v.i.big ? std::to_string(static_cast<std::uint64_t>(v.i.v)) : std::to_string(v.i.v);
        case YType::Null: return "None";
        default: return v.s;
    }
}

const char* ytype_name(YType t) {
    switch (t) {
        case YType::Null: return "NoneType";
        case YType::Bool: return "bool";
        case YType::Int: return "int";
        case YType::Float: return "float";
        case YType::Str: return "str";
        case YType::Seq: return "list";
        case YType::Map: return "dict";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// scalar parsing (parse_range / parse_bytes / parse_description)
// ---------------------------------------------------------------------------

// capa.rules.parse_range: "(min, max)", either side optional.
std::pair<std::optional<PyInt>, std::optional<PyInt>> parse_range(const std::string& s) {
    if (!starts_with(s, "(") || !ends_with(s, ")")) throw InvalidRule{"invalid range: " + s};
    const std::string inner = s.substr(1, s.size() - 2);
    const auto comma = inner.find(',');
    const std::string min_spec = strip(comma == std::string::npos ? inner : inner.substr(0, comma));
    const std::string max_spec = comma == std::string::npos ? "" : strip(inner.substr(comma + 1));
    std::optional<PyInt> mn, mx;
    auto negative = [](const PyInt& v) { return !v.big && v.v < 0; };
    if (!min_spec.empty()) {
        mn = parse_int(min_spec);
        if (negative(*mn)) throw InvalidRule{"range min less than zero"};
    }
    if (!max_spec.empty()) {
        mx = parse_int(max_spec);
        if (negative(*mx)) throw InvalidRule{"range max less than zero"};
    }
    if (mn && mx && static_cast<std::uint64_t>(mx->v) < static_cast<std::uint64_t>(mn->v))
        throw InvalidRule{"range max less than min"};
    return {mn, mx};
}

// capa.rules.parse_bytes: bytes.fromhex(s.replace(" ", "")), at most 0x100 bytes.
std::string parse_bytes(const std::string& in) {
    std::string raw;
    std::size_t k = 0;
    const std::string s = [&] {
        std::string t;
        for (char c : in)
            if (c != ' ') t += c;
        return t;
    }();
    while (k < s.size()) {
        if (is_space(s[k])) {  // fromhex skips whitespace between byte pairs
            ++k;
            continue;
        }
        if (k + 1 >= s.size() || digit_value(s[k]) >= 16 || digit_value(s[k + 1]) >= 16)
            throw InvalidRule{"unexpected bytes value: must be a valid hex sequence: \"" + in + "\""};
        raw.push_back(static_cast<char>((digit_value(s[k]) << 4) | digit_value(s[k + 1])));
        k += 2;
    }
    if (raw.size() > 0x100)
        throw InvalidRule{"unexpected bytes value: byte sequences must be no larger than 256 bytes"};
    return raw;
}

const char* DESCRIPTION_SEPARATOR = " = ";

// The value of a feature after capa.rules.parse_description.
struct PValue {
    enum class Kind { Str, Int, Float, Bytes, Bool, Null, Other } k = Kind::Null;
    std::string s;  // Str, Bytes
    PyInt i;
    double f = 0.0;
};

bool is_numeric_value_type(const std::string& value_type) {
    return value_type == "number" || value_type == "offset" || starts_with(value_type, "number/") ||
           starts_with(value_type, "offset/") ||
           (starts_with(value_type, "operand[") &&
            (ends_with(value_type, "].number") || ends_with(value_type, "].offset")));
}

// capa.rules.parse_description: split an inline "value = description" (except for
// `string`, whose value is taken whole), then cast the value to its feature's type.
std::pair<PValue, std::optional<std::string>> parse_description(
    const YVal& s, const std::string& value_type, std::optional<std::string> description) {
    PValue value;
    if (value_type == "string") {
        if (s.t == YType::Str) {
            value.k = PValue::Kind::Str;
            value.s = s.s;
        } else {
            value.k = PValue::Kind::Other;
        }
        return {value, description};
    }
    if (s.t == YType::Str) {
        std::string text = s.s;
        const auto pos = text.find(DESCRIPTION_SEPARATOR);
        if (pos != std::string::npos) {
            if (description)
                throw InvalidRule{"unexpected value: \"" + text +
                                  "\", only one description allowed (inline description with ` = `)"};
            description = text.substr(pos + 3);
            text = text.substr(0, pos);
            if (description->empty())
                throw InvalidRule{"unexpected value: \"" + s.s + "\", description cannot be empty"};
        }
        if (value_type == "bytes") {
            value.k = PValue::Kind::Bytes;
            value.s = parse_bytes(text);
        } else if (is_numeric_value_type(value_type)) {
            try {
                value.i = parse_int(text);
            } catch (const InvalidRule&) {
                throw InvalidRule{"unexpected value: \"" + text + "\", must begin with numerical value"};
            }
            value.k = PValue::Kind::Int;
        } else {
            value.k = PValue::Kind::Str;
            value.s = text;
        }
        return {value, description};
    }
    switch (s.t) {
        case YType::Int:
            value.k = PValue::Kind::Int;
            value.i = s.i;
            break;
        case YType::Bool:  // a Python bool is an int
            value.k = PValue::Kind::Int;
            value.i.v = s.b ? 1 : 0;
            break;
        case YType::Float:
            value.k = PValue::Kind::Float;
            value.f = s.f;
            break;
        case YType::Null: value.k = PValue::Kind::Null; break;
        default: value.k = PValue::Kind::Other; break;
    }
    return {value, description};
}

// capa.rules.trim_dll_part: kernel32.CreateFileA -> CreateFileA (keeps ordinals and ::)
std::string trim_dll_part(const std::string& api) {
    if (api.find(".#") != std::string::npos) return api;
    if (std::count(api.begin(), api.end(), '.') == 1 && api.find("::") == std::string::npos)
        return api.substr(api.find('.') + 1);
    return api;
}

// ---------------------------------------------------------------------------
// feature-for-scope validation (capa.rules.SUPPORTED_FEATURES)
// ---------------------------------------------------------------------------

struct ScopeSupport {
    std::set<FeatureType> types;
    std::set<std::string> characteristics;
};

const std::map<Scope, ScopeSupport>& supported_features() {
    static const std::map<Scope, ScopeSupport> table = [] {
        using T = FeatureType;
        std::map<Scope, ScopeSupport> m;
        m[Scope::GLOBAL] = {{T::OS, T::Arch, T::Format}, {}};
        m[Scope::FILE] = {{T::MatchedRule, T::Export, T::Import, T::Section, T::FunctionName,
                           T::String, T::Class, T::Namespace},
                          {"embedded pe", "mixed mode", "forwarded export"}};
        m[Scope::PROCESS] = {{T::MatchedRule}, {}};
        m[Scope::THREAD] = {};
        m[Scope::SPAN_OF_CALLS] = {};
        m[Scope::CALL] = {{T::MatchedRule, T::Regex, T::String, T::Substring, T::API, T::Number}, {}};
        m[Scope::FUNCTION] = {{T::MatchedRule, T::BasicBlock},
                              {"calls from", "calls to", "loop", "recursive call"}};
        m[Scope::BASIC_BLOCK] = {{T::MatchedRule}, {"tight loop", "stack string"}};
        m[Scope::INSTRUCTION] = {{T::MatchedRule, T::API, T::Property, T::Number, T::String,
                                  T::Bytes, T::Offset, T::Mnemonic, T::OperandNumber,
                                  T::OperandOffset, T::Class, T::Namespace},
                                 {"nzxor", "peb access", "fs access", "gs access", "indirect call",
                                  "call $+5", "cross section flow", "unmanaged call"}};
        auto merge = [&](Scope into, Scope from) {
            m[into].types.insert(m[from].types.begin(), m[from].types.end());
            m[into].characteristics.insert(m[from].characteristics.begin(),
                                           m[from].characteristics.end());
        };
        for (Scope s : {Scope::INSTRUCTION, Scope::BASIC_BLOCK, Scope::FUNCTION, Scope::FILE,
                        Scope::PROCESS, Scope::THREAD, Scope::SPAN_OF_CALLS, Scope::CALL})
            merge(s, Scope::GLOBAL);
        merge(Scope::SPAN_OF_CALLS, Scope::CALL);
        merge(Scope::THREAD, Scope::SPAN_OF_CALLS);
        merge(Scope::PROCESS, Scope::THREAD);
        merge(Scope::BASIC_BLOCK, Scope::INSTRUCTION);
        merge(Scope::FUNCTION, Scope::BASIC_BLOCK);
        return m;
    }();
    return table;
}

std::string scopes_repr(const Scopes& scopes) {
    if (scopes.static_scope && scopes.dynamic_scope)
        return "static-scope: " + scope_to_string(*scopes.static_scope) +
               ", dynamic-scope: " + scope_to_string(*scopes.dynamic_scope);
    if (scopes.static_scope) return "static-scope: " + scope_to_string(*scopes.static_scope);
    if (scopes.dynamic_scope) return "dynamic-scope: " + scope_to_string(*scopes.dynamic_scope);
    return "";
}

// capa.rules.ensure_feature_valid_for_scopes. Substring and Regex are subclasses of String
// in capa, so wherever String is allowed they are too.
void ensure_feature_valid_for_scopes(const Scopes& scopes, const Feature& feature) {
    ScopeSupport supported;
    for (const auto& s : {scopes.static_scope, scopes.dynamic_scope}) {
        if (!s) continue;
        auto it = supported_features().find(*s);
        if (it == supported_features().end()) continue;
        supported.types.insert(it->second.types.begin(), it->second.types.end());
        supported.characteristics.insert(it->second.characteristics.begin(),
                                         it->second.characteristics.end());
    }
    bool ok;
    if (feature.type == FeatureType::Characteristic) {
        ok = supported.characteristics.count(feature.s) != 0;
    } else {
        ok = supported.types.count(feature.type) != 0;
        if (!ok && (feature.type == FeatureType::Substring || feature.type == FeatureType::Regex))
            ok = supported.types.count(FeatureType::String) != 0;
    }
    if (!ok)
        throw InvalidRule{"feature " + feature.str() + " not supported for scopes " + scopes_repr(scopes)};
}

// ---------------------------------------------------------------------------
// leaf feature construction (parse_feature + build_feature)
// ---------------------------------------------------------------------------

// The keys capa.rules.parse_feature accepts (operand[N].* aside).
bool known_feature_key(const std::string& key) {
    static const std::set<std::string> keys = {
        "api",    "string",        "substring", "bytes",  "number",  "offset",
        "mnemonic", "basic blocks", "characteristic", "export", "import", "section",
        "match",  "function-name", "os",        "format", "arch",    "class",
        "namespace", "property"};
    return keys.count(key) != 0;
}

int operand_index(const std::string& key, const char* suffix) {
    const std::string inner = key.substr(8, key.size() - 8 - std::strlen(suffix));
    auto v = python_int(inner, 10);
    if (!v || v->big || v->v < 0 || v->v > 4)  // capa.features.insn.MAX_OPERAND_COUNT
        throw InvalidRule{"operand index must be an integer"};
    return static_cast<int>(v->v);
}

[[noreturn]] void bad_value_type(const std::string& key, const PValue& v) {
    const char* t = "unknown";
    switch (v.k) {
        case PValue::Kind::Str: t = "str"; break;
        case PValue::Kind::Int: t = "int"; break;
        case PValue::Kind::Float: t = "float"; break;
        case PValue::Kind::Bytes: t = "bytes"; break;
        case PValue::Kind::Bool: t = "bool"; break;
        case PValue::Kind::Null: t = "NoneType"; break;
        case PValue::Kind::Other: t = "object"; break;
    }
    throw InvalidRule{"unexpected " + key + " value type: " + t};
}

Feature int_feature(Feature f, const PyInt& v) {
    f.i = v.v;
    f.big = v.big;
    return f;
}

// Construct the feature named by `key` (one parse_feature accepts) from a parsed value.
Feature make_feature(const std::string& key, const PValue& value, const std::string& desc) {
    auto str = [&]() -> const std::string& {
        if (value.k != PValue::Kind::Str) bad_value_type(key, value);
        return value.s;
    };
    if (key == "api") return Feature::api(trim_dll_part(str()), desc);
    if (key == "string") return Feature::string_factory(str(), desc);
    if (key == "substring") return Feature::substring(str(), desc);
    if (key == "bytes") {
        if (value.k != PValue::Kind::Bytes) bad_value_type(key, value);
        return Feature::bytes(value.s, desc);
    }
    if (key == "number") {
        if (value.k == PValue::Kind::Int) return int_feature(Feature::number(0, desc), value.i);
        bad_value_type(key, value);
    }
    if (key == "offset") {
        if (value.k == PValue::Kind::Int) return int_feature(Feature::offset(0, desc), value.i);
        bad_value_type(key, value);
    }
    if (key == "mnemonic") return Feature::mnemonic(str(), desc);
    if (key == "basic blocks") return Feature::basic_block(desc);
    if (key == "characteristic") return Feature::characteristic(str(), desc);
    if (key == "export") return Feature::export_(str(), desc);
    if (key == "import") return Feature::import_(str(), desc);
    if (key == "section") return Feature::section(str(), desc);
    if (key == "match") return Feature::matched_rule(str(), desc);
    if (key == "function-name") return Feature::function_name(str(), desc);
    if (key == "os") return Feature::os(str(), desc);
    if (key == "format") return Feature::format(str(), desc);
    if (key == "arch") return Feature::arch(str(), desc);
    if (key == "class") return Feature::klass(str(), desc);
    if (key == "namespace") return Feature::namespace_(str(), desc);
    if (key == "property") return Feature::property(str(), "", desc);
    if (starts_with(key, "operand[") && ends_with(key, "].number")) {
        const int idx = operand_index(key, "].number");
        if (value.k != PValue::Kind::Int) bad_value_type(key, value);
        return int_feature(Feature::operand_number(idx, 0, desc), value.i);
    }
    if (starts_with(key, "operand[") && ends_with(key, "].offset")) {
        const int idx = operand_index(key, "].offset");
        if (value.k != PValue::Kind::Int) bad_value_type(key, value);
        return int_feature(Feature::operand_offset(idx, 0, desc), value.i);
    }
    throw InvalidRule{"unexpected statement: " + key};
}

void reject_invalid_regex(const Feature& f) {
    // capa compiles every regex as the rule loads and rejects the rule if it does not
    // compile. A pattern that is valid Python but has no std::regex translation is kept
    // (it may still be meaningful to a reader of the rule) but cannot match; say so.
    if (f.type != FeatureType::Regex) return;
    std::string why;
    if (!compile_capa_regex(f.s, &why))
        std::fprintf(stderr, "warning: regex %s cannot be compiled (%s); it will never match\n",
                     f.s.c_str(), why.c_str());
}

std::string com_guid_bytes(const std::string& guid) {
    std::string hex;
    for (char c : guid)
        if (c != '-') hex += c;
    if (hex.size() != 32) throw InvalidRule{"invalid COM GUID: " + guid};
    static const int order[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    std::string reordered;
    for (int idx : order) reordered += hex.substr(static_cast<std::size_t>(idx) * 2, 2);
    return parse_bytes(reordered);
}

// capa.rules.translate_com_feature
Node translate_com_feature(const std::string& com_name, ComType com_type) {
    const std::vector<std::string>* guids = com_guids(com_type, com_name);
    if (!guids || guids->empty())
        throw InvalidRule{"'" + com_name + "' doesn't exist in COM " +
                          (com_type == ComType::Class ? "class" : "interface") + " database"};
    auto stmt = std::make_shared<Statement>();
    stmt->type = StatementType::Or;
    const std::string symbol = com_prefix(com_type) + com_name;
    for (const std::string& guid : *guids) {
        stmt->children.push_back(Node::of_feature(Feature::string(guid, symbol + " as GUID string")));
        stmt->children.push_back(Node::of_feature(Feature::bytes(com_guid_bytes(guid), symbol + " as bytes")));
    }
    return Node::of_statement(stmt);
}

// capa.rules.build_feature
Node build_feature(const std::string& key, const YVal& initial_value,
                   const std::optional<std::string>& initial_description, const Scopes* scopes) {
    auto validate = [&](const Feature& f) {
        if (scopes) ensure_feature_valid_for_scopes(*scopes, f);
    };
    const std::string node_desc = initial_description.value_or("");

    if (starts_with(key, "count(") && ends_with(key, ")")) {
        // count(basic blocks), count(mnemonic(mov)), count(number(0x10 = description)), ...
        std::string term = key.substr(6, key.size() - 7);
        std::string arg;
        const auto paren = term.find('(');
        if (paren != std::string::npos) {
            arg = term.substr(paren + 1);
            term = term.substr(0, paren);
        }
        if (!known_feature_key(term) &&
            !(starts_with(term, "operand[") && (ends_with(term, "].number") || ends_with(term, "].offset"))))
            throw InvalidRule{"unexpected statement: " + term};

        Feature feature;
        if (!arg.empty()) {
            arg.pop_back();  // arg[:-len(")")]
            if (term != "string") {
                // can't rely on yaml parsing ints embedded within strings
                YVal text;
                text.t = YType::Str;
                text.s = arg;
                auto [value, desc] = parse_description(text, term, std::nullopt);
                feature = make_feature(term, value, desc.value_or(""));
            } else {
                // a string argument takes no inline description, like capa
                feature = Feature::string_factory(arg);
            }
        } else if (term == "basic blocks") {
            feature = Feature::basic_block();
        } else {
            throw InvalidRule{"unexpected count term without a value: " + term};
        }
        reject_invalid_regex(feature);

        auto stmt = std::make_shared<Statement>();
        stmt->type = StatementType::Range;
        stmt->range_child = feature;
        stmt->description = node_desc;

        auto set_range = [&](std::optional<PyInt> mn, std::optional<PyInt> mx) {
            stmt->range_min = mn ? mn->v : 0;
            stmt->range_max = mx ? static_cast<std::uint64_t>(mx->v) : ~0ull;
        };
        if (initial_value.t == YType::Int || initial_value.t == YType::Bool) {
            PyInt n = initial_value.t == YType::Int ? initial_value.i : PyInt{initial_value.b ? 1 : 0, false};
            set_range(n, n);
        } else if (initial_value.t == YType::Str) {
            const std::string& count = initial_value.s;
            if (ends_with(count, " or more")) {
                set_range(parse_int(count.substr(0, count.size() - 8)), std::nullopt);
            } else if (ends_with(count, " or fewer")) {
                set_range(std::nullopt, parse_int(count.substr(0, count.size() - 9)));
            } else if (starts_with(count, "(")) {
                auto [mn, mx] = parse_range(count);
                set_range(mn, mx);
            } else {
                std::optional<PyInt> n;
                try {
                    n = parse_int(count);
                } catch (const InvalidRule&) {
                    throw InvalidRule{"unexpected range: " + count};
                }
                set_range(n, n);
            }
        } else {
            throw InvalidRule{std::string("unexpected range value type: ") + ytype_name(initial_value.t)};
        }
        // for count(...) features, validate the inner feature rather than the Range.
        validate(feature);
        return Node::of_statement(stmt);
    }

    if (key == "string" && initial_value.t != YType::Str)
        throw InvalidRule{"ambiguous string value " + yval_text(initial_value) +
                          ", must be defined as explicit string"};

    if (starts_with(key, "operand[") && (ends_with(key, "].number") || ends_with(key, "].offset"))) {
        auto [value, desc] = parse_description(initial_value, key, initial_description);
        Feature feature = make_feature(key, value, desc.value_or(""));
        validate(feature);
        return Node::of_feature(feature);
    }

    if (key == "os" || key == "format" || key == "arch") {
        static const std::set<std::string> valid_os = {
            "86open", "aix", "android", "any", "aros", "cloud", "dragonfly BSD", "fenixos",
            "freebsd", "hpux", "hurd", "illumos", "irix", "linux", "macos", "modesto", "nacl",
            "netbsd", "nsk", "openbsd", "openvms", "solaris", "syllable", "tru64", "unix",
            "windows", "z/os"};
        static const std::set<std::string> valid_format = {"pe", "elf", "dotnet"};
        static const std::set<std::string> valid_arch = {"i386", "amd64", "aarch64", "any"};
        const auto& valid = key == "os" ? valid_os : key == "format" ? valid_format : valid_arch;
        if (initial_value.t != YType::Str || !valid.count(initial_value.s))
            throw InvalidRule{"unexpected " + key + " value " + yval_text(initial_value)};
    }

    if (starts_with(key, "property/")) {
        const std::string access = key.substr(9);
        if (access != ACCESS_READ && access != ACCESS_WRITE)
            throw InvalidRule{"unexpected " + key + " access " + access};
        auto [value, desc] = parse_description(initial_value, key, initial_description);
        if (value.k != PValue::Kind::Str) bad_value_type(key, value);
        Feature feature = Feature::property(value.s, access, desc.value_or(""));
        validate(feature);
        return Node::of_feature(feature);
    }

    if (starts_with(key, "com/")) {
        const std::string type = key.substr(4);
        if (type != "class" && type != "interface") throw InvalidRule{"unexpected COM type: " + type};
        auto [value, desc] = parse_description(initial_value, key, initial_description);
        if (value.k != PValue::Kind::Str) bad_value_type(key, value);
        // the description is dropped, as capa drops it: the expansion carries its own
        return translate_com_feature(value.s, type == "class" ? ComType::Class : ComType::Interface);
    }

    if (!known_feature_key(key)) throw InvalidRule{"unexpected statement: " + key};
    auto [value, desc] = parse_description(initial_value, key, initial_description);
    Feature feature = make_feature(key, value, desc.value_or(""));
    reject_invalid_regex(feature);
    validate(feature);
    return Node::of_feature(feature);
}

// ---------------------------------------------------------------------------
// statement tree construction (build_statements)
// ---------------------------------------------------------------------------

std::optional<std::string> description_of(const YAML::Node& n) {
    if (!n) return std::nullopt;
    const YVal v = yval(n);
    if (v.t == YType::Null) return std::nullopt;
    return yval_text(v);
}

// capa.rules.pop_statement_description_entry: a child of the form `{description: ...}`
// is the statement's description, not a child statement.
std::vector<YAML::Node> pop_statement_description(const YAML::Node& seq,
                                                  std::optional<std::string>& description) {
    std::vector<YAML::Node> children;
    int found = 0;
    for (const auto& child : seq) {
        if (child.IsMap() && child.size() == 1 && child["description"]) {
            ++found;
            description = description_of(child["description"]);
            continue;
        }
        children.push_back(child);
    }
    if (found > 1) throw InvalidRule{"statements can only have one description"};
    return children;
}

Node build_statements(const YAML::Node& d, const Scopes& scopes);

// capa.rules.unique over built children: features are deduplicated by identity (capa's
// Feature __eq__/__hash__, which ignore the description); statements never are, since
// capa compares them by object identity.
std::vector<Node> build_unique(const std::vector<YAML::Node>& docs, const Scopes& scopes) {
    std::vector<Node> out;
    for (const auto& dd : docs) {
        Node node = build_statements(dd, scopes);
        if (!node.is_statement) {
            bool dup = false;
            for (const Node& seen : out)
                if (!seen.is_statement && seen.feature == node.feature) {
                    dup = true;
                    break;
                }
            if (dup) continue;
        }
        out.push_back(std::move(node));
    }
    return out;
}

std::shared_ptr<Statement> make_compound(StatementType t, std::vector<Node> children,
                                         const std::optional<std::string>& desc) {
    auto s = std::make_shared<Statement>();
    s->type = t;
    s->children = std::move(children);
    s->description = desc.value_or("");
    return s;
}

Node make_subscope(Scope scope, Node child, const std::optional<std::string>& desc) {
    auto s = std::make_shared<Statement>();
    s->type = StatementType::Subscope;
    s->subscope = scope;
    s->children.push_back(std::move(child));
    s->description = desc.value_or("");
    return Node::of_statement(s);
}

Node build_statements(const YAML::Node& d, const Scopes& scopes) {
    if (!d.IsMap()) throw InvalidRule{"statement must be a mapping"};
    if (d.size() > 2) throw InvalidRule{"too many statements"};
    if (d.size() == 0) throw InvalidRule{"empty statement"};

    // the first key, as Python's list(d.keys())[0]
    const std::string key = d.begin()->first.as<std::string>();
    const YAML::Node body = d.begin()->second;

    std::optional<std::string> description;
    std::vector<YAML::Node> children;
    if (body.IsSequence()) children = pop_statement_description(body, description);

    auto need_list = [&]() {
        if (!body.IsSequence()) throw InvalidRule{"`" + key + "` must be a list of statements"};
    };
    auto subscope_child = [&](Scope scope, const char* what) -> Node {
        need_list();
        if (children.size() != 1) throw InvalidRule{"subscope must have exactly one child statement"};
        Scopes inner;
        if (is_static_scope(scope) && scope != Scope::FILE)
            inner.static_scope = scope;
        else
            inner.dynamic_scope = scope;
        (void)what;
        return make_subscope(scope, build_statements(children[0], inner), description);
    };

    if (key == "and") {
        need_list();
        return Node::of_statement(make_compound(StatementType::And, build_unique(children, scopes), description));
    }
    if (key == "or") {
        need_list();
        return Node::of_statement(make_compound(StatementType::Or, build_unique(children, scopes), description));
    }
    if (key == "not") {
        need_list();
        if (children.size() != 1) throw InvalidRule{"not statement must have exactly one child statement"};
        std::vector<Node> kids;
        kids.push_back(build_statements(children[0], scopes));
        return Node::of_statement(make_compound(StatementType::Not, std::move(kids), description));
    }
    if (ends_with(key, " or more")) {
        need_list();
        auto count = python_int(key.substr(0, key.size() - 7), 10);
        if (!count || count->big) throw InvalidRule{"invalid count: " + key};
        auto s = make_compound(StatementType::Some, build_unique(children, scopes), description);
        s->count = static_cast<int>(count->v);
        return Node::of_statement(s);
    }
    if (key == "optional") {
        // `optional` is an alias for `0 or more`
        need_list();
        auto s = make_compound(StatementType::Some, build_unique(children, scopes), description);
        s->count = 0;
        return Node::of_statement(s);
    }

    if (key == "process") {
        if (!is_subscope_compatible(scopes.dynamic_scope, Scope::PROCESS))
            throw InvalidRule{"`process` subscope supported only for `file` scope"};
        return subscope_child(Scope::PROCESS, "process");
    }
    if (key == "thread") {
        if (!is_subscope_compatible(scopes.dynamic_scope, Scope::THREAD))
            throw InvalidRule{"`thread` subscope supported only for the `process` scope"};
        return subscope_child(Scope::THREAD, "thread");
    }
    if (key == "span of calls") {
        if (!is_subscope_compatible(scopes.dynamic_scope, Scope::SPAN_OF_CALLS))
            throw InvalidRule{"`span of calls` subscope supported only for the `process` and `thread` scopes"};
        return subscope_child(Scope::SPAN_OF_CALLS, "span of calls");
    }
    if (key == "call") {
        if (!is_subscope_compatible(scopes.dynamic_scope, Scope::CALL))
            throw InvalidRule{"`call` subscope supported only for the `process`, `thread`, and `call` scopes"};
        return subscope_child(Scope::CALL, "call");
    }
    if (key == "function") {
        if (!is_subscope_compatible(scopes.static_scope, Scope::FUNCTION))
            throw InvalidRule{"`function` subscope supported only for `file` scope"};
        return subscope_child(Scope::FUNCTION, "function");
    }
    if (key == "basic block") {
        if (!is_subscope_compatible(scopes.static_scope, Scope::BASIC_BLOCK))
            throw InvalidRule{"`basic block` subscope supported only for `function` scope"};
        return subscope_child(Scope::BASIC_BLOCK, "basic block");
    }
    if (key == "instruction") {
        if (!is_subscope_compatible(scopes.static_scope, Scope::INSTRUCTION))
            throw InvalidRule{"`instruction` subscope supported only for `function` and `basic block` scope"};
        need_list();
        Scopes inner;
        inner.static_scope = Scope::INSTRUCTION;
        // for instruction subscopes, a top level `and` may be implied:
        //     - instruction:            - instruction:
        //       - and:           ==       - arch: i386
        //         - arch: i386            - mnemonic: cmp
        //         - mnemonic: cmp
        Node inner_node = children.size() == 1
                              ? build_statements(children[0], inner)
                              : Node::of_statement(make_compound(StatementType::And,
                                                                 build_unique(children, inner), std::nullopt));
        return make_subscope(Scope::INSTRUCTION, std::move(inner_node), description);
    }

    // leaf feature: the value of the first key, and the `description:` sibling if any
    return build_feature(key, yval(body), description_of(d["description"]), &scopes);
}

// capa.rules.Scopes.from_dict
Scopes parse_scopes(const YAML::Node& meta, const std::string& name) {
    if (meta["scope"])
        throw InvalidRule{"legacy rule detected (rule.meta.scope), please update to the new syntax: " + name};
    const YAML::Node sc = meta["scopes"];
    if (!sc) throw InvalidRule{"please specify at least one of this rule's (static/dynamic) scopes"};
    if (!sc.IsMap()) throw InvalidRule{"the scopes field must contain a dictionary specifying the scopes"};
    if (!sc["static"]) throw InvalidRule{"static scope must be provided"};
    if (!sc["dynamic"]) throw InvalidRule{"dynamic scope must be provided"};
    if (sc.size() != 2) throw InvalidRule{"scope flavors can be either static or dynamic"};

    auto read = [](const YAML::Node& n) -> std::optional<std::string> {
        const YVal v = yval(n);
        if (v.t == YType::Null) return std::nullopt;
        std::string s = yval_text(v);
        if (s == "unsupported" || s.empty()) return std::nullopt;
        return s;
    };
    const std::optional<std::string> st = read(sc["static"]);
    const std::optional<std::string> dy = read(sc["dynamic"]);
    if (!st && !dy) throw InvalidRule{"invalid scopes value. At least one scope must be specified"};

    Scopes out;
    if (st) {
        auto s = scope_from_string(*st);
        if (!s || !is_static_scope(*s)) throw InvalidRule{*st + " is not a valid static scope"};
        out.static_scope = *s;
    }
    if (dy) {
        auto s = scope_from_string(*dy);
        if (!s || !is_dynamic_scope(*s)) throw InvalidRule{*dy + " is not a valid dynamic scope"};
        out.dynamic_scope = *s;
    }
    return out;
}

std::vector<std::string> as_str_list(const YAML::Node& n) {
    std::vector<std::string> out;
    if (!n) return out;
    if (n.IsSequence()) {
        for (const auto& e : n)
            if (e.IsScalar()) out.push_back(yval_text(yval(e)));
    } else if (n.IsScalar()) {
        out.push_back(n.Scalar());
    }
    return out;
}

// ---------------------------------------------------------------------------
// query optimizer (capa/optimizer.py)
//
// capa reorders the children of every and/or/some so the cheapest are evaluated first,
// once, when the ruleset is built. The order is visible: it is the order of `children`
// in every match tree of the result document. Python's sort is stable, so ties keep the
// order the rule wrote them in.
// ---------------------------------------------------------------------------

int node_cost(const Node& node) {
    if (!node.is_statement) {
        switch (node.feature.type) {
            // the most restrictive features: authors use them to open rules
            case FeatureType::OS:
            case FeatureType::Arch:
            case FeatureType::Format:
                return 0;
            // require a scan of every string (or bytes) feature
            case FeatureType::Substring:
            case FeatureType::Regex:
            case FeatureType::Bytes:
                return 2;
            default:
                return 1;  // hash lookups
        }
    }
    const Statement& s = *node.stmt;
    switch (s.type) {
        case StatementType::Not:
            return 1 + node_cost(s.children.at(0));
        case StatementType::Range:
            return 1 + node_cost(Node::of_feature(s.range_child));
        case StatementType::And:
        case StatementType::Or:
        case StatementType::Some: {
            int total = 1;
            for (const Node& c : s.children) total += node_cost(c);
            return total;
        }
        case StatementType::Subscope:
            return 1;
    }
    return 1;
}

void optimize_node(Node& node) {
    if (!node.is_statement) return;
    Statement& s = *node.stmt;
    switch (s.type) {
        case StatementType::And:
        case StatementType::Or:
        case StatementType::Some: {
            std::vector<std::pair<int, Node>> keyed;
            keyed.reserve(s.children.size());
            for (Node& c : s.children) keyed.emplace_back(node_cost(c), std::move(c));
            std::stable_sort(keyed.begin(), keyed.end(),
                             [](const auto& a, const auto& b) { return a.first < b.first; });
            s.children.clear();
            for (auto& [cost, c] : keyed) s.children.push_back(std::move(c));
            for (Node& c : s.children) optimize_node(c);
            return;
        }
        case StatementType::Not:
            optimize_node(s.children.at(0));
            return;
        default:
            return;
    }
}

// ---------------------------------------------------------------------------
// feature-index scoring (capa RuleSet._score_feature / _index_rules_by_feature)
// ---------------------------------------------------------------------------

// Score a feature by expected selectivity (higher == rarer == better for indexing).
int score_feature(const std::unordered_map<std::string, int>& scores_by_rule, const Feature& f) {
    switch (f.type) {
        case FeatureType::MatchedRule: {
            auto it = scores_by_rule.find(f.s);
            // unknown dependency (e.g. a static-only derived rule referenced in dynamic
            // mode) never matches here, so treat as very selective. capa returns 9.
            return it == scores_by_rule.end() ? 9 : it->second;
        }
        case FeatureType::Number:
        case FeatureType::OperandNumber: {
            if (f.vkind != ValueKind::Int) return 7;
            const std::int64_t v = f.i;
            if (!f.big && v >= -0x8000 && v <= 0x8000) return 3;
            if (!f.big && v >= 0xFFFFFF00LL && v <= 0xFFFFFFFFLL) return 3;
            if (f.big && static_cast<std::uint64_t>(v) >= 0xFFFFFFFFFFFFFF00ull) return 3;
            return 7;
        }
        case FeatureType::Substring:
        case FeatureType::Regex:
        case FeatureType::Bytes:
            return 0;  // non-hashable; can't index by hash lookup
        case FeatureType::String: return 9;
        case FeatureType::API: return 8;
        case FeatureType::Export: return 7;
        case FeatureType::Class:
        case FeatureType::Namespace:
        case FeatureType::Property:
        case FeatureType::Import:
        case FeatureType::Section:
        case FeatureType::FunctionName: return 5;
        case FeatureType::Characteristic:
        case FeatureType::Offset:
        case FeatureType::OperandOffset: return 4;
        case FeatureType::Mnemonic: return 2;
        case FeatureType::BasicBlock: return 1;
        case FeatureType::OS:
        case FeatureType::Arch:
        case FeatureType::Format: return 0;
    }
    return 0;
}

struct ScoredFeatures {
    int score = 0;
    std::vector<Feature> features;
};

void union_feature(std::vector<Feature>& into, const Feature& f) {
    for (const auto& e : into)
        if (e == f) return;
    into.push_back(f);
}

// Walk a rule's logic tree, choosing the minimal set of most-selective features that
// must be present for the rule to match. Ports RuleSet._index_rules_by_feature::rec.
//
// Where capa would assert (a rule whose root, or one of whose `or:` branches, has no
// indexable feature -- a top-level `not:`, say), this returns nullopt and the rule is
// evaluated at every scope instance instead, which is what the naive matcher does.
std::optional<ScoredFeatures> index_rec(const Node& node,
                                        const std::unordered_map<std::string, int>& scores) {
    if (!node.is_statement) {
        return ScoredFeatures{score_feature(scores, node.feature), {node.feature}};
    }
    const Statement& s = *node.stmt;
    switch (s.type) {
        case StatementType::Not:
            return std::nullopt;
        case StatementType::Subscope:
            return std::nullopt;  // lowered away before indexing; be safe
        case StatementType::Some:
            if (s.count == 0) return std::nullopt;
            break;  // count>0 handled as OR below
        case StatementType::Range:
            if (s.range_min == 0) return std::nullopt;  // min 0 -> optional/not-like
            return ScoredFeatures{score_feature(scores, s.range_child), {s.range_child}};
        case StatementType::And: {
            // the highest score, then the fewest features; the first such child on a tie
            // (capa sorts stably on (score, -len) and takes the head)
            std::optional<ScoredFeatures> best;
            for (const auto& c : s.children) {
                auto r = index_rec(c, scores);
                if (!r) continue;
                if (!best || r->score > best->score ||
                    (r->score == best->score && r->features.size() < best->features.size()))
                    best = std::move(r);
            }
            return best;  // may be nullopt if all children un-indexable
        }
        case StatementType::Or:
            break;  // handled below
    }
    // Or / Some(count>0): must index every branch (union), score = min branch score.
    ScoredFeatures out;
    out.score = 10000000;
    for (const auto& c : s.children) {
        auto r = index_rec(c, scores);
        if (!r) {
            // an un-indexable OR branch means the rule can match without any indexed
            // feature; fall back to always-evaluate.
            return std::nullopt;
        }
        out.score = std::min(out.score, r->score);
        for (const auto& f : r->features) union_feature(out.features, f);
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

std::vector<std::string> Rule::namespace_prefixes() const {
    std::vector<std::string> out;
    std::string ns = namespace_;
    while (!ns.empty()) {
        out.push_back(ns);
        auto pos = ns.rfind('/');
        if (pos == std::string::npos) break;
        ns = ns.substr(0, pos);
    }
    return out;
}

MatchableRule Rule::matchable() const {
    return MatchableRule{name, namespace_prefixes(), &root};
}

Rule Rule::from_yaml(const std::string& yaml_text) {
    YAML::Node doc;
    try {
        doc = YAML::Load(yaml_text);
    } catch (const std::exception& e) {
        throw InvalidRule{std::string("yaml parse error: ") + e.what()};
    }
    return from_yaml_node(doc, yaml_text);
}

// capa.rules.Rule.from_dict
Rule Rule::from_yaml_node(const YAML::Node& doc, const std::string& definition) {
    if (!doc || !doc.IsMap() || !doc["rule"]) throw InvalidRule{"empty or invalid YAML document"};
    const YAML::Node r = doc["rule"];
    if (!r.IsMap()) throw InvalidRule{"empty or invalid YAML document"};
    const YAML::Node meta = r["meta"];
    if (!meta || !meta.IsMap() || !meta["name"]) throw InvalidRule{"missing rule.meta.name"};

    Rule rule;
    rule.name = yval_text(yval(meta["name"]));
    rule.scopes = parse_scopes(meta, rule.name);

    const YAML::Node features = r["features"];
    // the rule must start with a single logic node; anything else is too implicit
    if (!features || !features.IsSequence() || features.size() != 1)
        throw InvalidRule{"rule must begin with a single top level statement"};

    if (meta["att&ck"] && !meta["att&ck"].IsSequence()) throw InvalidRule{"ATT&CK mapping must be a list"};
    if (meta["mbc"] && !meta["mbc"].IsSequence()) throw InvalidRule{"MBC mapping must be a list"};

    if (meta["namespace"] && !meta["namespace"].IsNull())
        rule.namespace_ = yval_text(yval(meta["namespace"]));
    if (meta["description"] && !meta["description"].IsNull())
        rule.description = yval_text(yval(meta["description"]));
    rule.authors = as_str_list(meta["authors"]);
    rule.attack = as_str_list(meta["att&ck"]);
    rule.mbc = as_str_list(meta["mbc"]);
    rule.references = as_str_list(meta["references"]);
    rule.examples = as_str_list(meta["examples"]);
    if (meta["lib"]) {
        const YVal lib = yval(meta["lib"]);
        rule.is_lib = (lib.t == YType::Bool && lib.b) || (lib.t == YType::Int && lib.i.v != 0);
    }
    for (const char* key : {"analysis-conclusion", "analysis-conclusion-ov", "malware-family",
                            "malware-category", "malware-category-ov"}) {
        const YAML::Node v = meta[std::string("maec/") + key];
        if (v && !v.IsNull()) rule.maec[key] = yval_text(yval(v));
    }
    rule.definition = definition;

    rule.root = build_statements(features[0], rule.scopes);
    // capa's own check for this compares a dict against Subscope and never fires; a rule
    // whose root is a subscope then fails to evaluate. Rejecting it is the useful reading.
    if (rule.root.is_statement && rule.root.stmt->type == StatementType::Subscope)
        throw InvalidRule{"top level statement may not be a subscope"};
    return rule;
}

Node build_feature_from_text(const std::string& key, const std::string& value) {
    YVal v;
    v.t = YType::Str;
    v.s = value;
    return build_feature(key, v, std::nullopt, nullptr);
}

// ---------------------------------------------------------------------------
// dependencies / subscope extraction / ordering
// ---------------------------------------------------------------------------

namespace {

void collect_deps(const Node& node, std::set<std::string>& out) {
    if (!node.is_statement) {
        if (node.feature.type == FeatureType::MatchedRule) out.insert(node.feature.s);
        return;
    }
    const Statement& s = *node.stmt;
    if (s.type == StatementType::Range) {
        if (s.range_child.type == FeatureType::MatchedRule) out.insert(s.range_child.s);
        return;
    }
    for (const auto& c : s.children) collect_deps(c, out);
}

// capa.rules.Rule.get_dependencies: a `match:` names a namespace in preference to a rule.
std::set<std::string> rule_dependencies(
    const Rule& rule,
    const std::unordered_map<std::string, std::vector<std::shared_ptr<Rule>>>& by_ns) {
    std::set<std::string> raw;
    collect_deps(rule.root, raw);
    std::set<std::string> deps;
    for (const auto& d : raw) {
        auto it = by_ns.find(d);
        if (it != by_ns.end()) {
            for (const auto& r : it->second) deps.insert(r->name);
        } else {
            deps.insert(d);
        }
    }
    return deps;
}

// walk tree, replace Subscope children with MatchedRule features, yield new rules
// (capa.rules.Rule._extract_subscope_rules_rec)
void extract_subscopes_rec(Node& node, const std::string& parent_name, int& counter,
                           std::vector<std::shared_ptr<Rule>>& out) {
    if (!node.is_statement) return;
    Statement& s = *node.stmt;
    for (auto& child : s.children) {
        if (child.is_statement && child.stmt->type == StatementType::Subscope) {
            Statement& sub = *child.stmt;
            // capa names these "<parent>/<uuid4 hex>". The name is never rendered: the
            // result document drops subscope rules and splices their trees into the
            // parent's, so a deterministic counter serves as well and diffs better.
            std::string name = parent_name + "/subscope-" + std::to_string(counter++);

            auto nr = std::make_shared<Rule>();
            nr->name = name;
            if (is_static_scope(sub.subscope) && sub.subscope != Scope::FILE)
                nr->scopes.static_scope = sub.subscope;
            else
                nr->scopes.dynamic_scope = sub.subscope;
            nr->root = std::move(sub.children.at(0));
            nr->is_lib = true;
            nr->is_subscope = true;
            nr->parent = parent_name;

            // replace the subscope child with a match: reference
            child = Node::of_feature(Feature::matched_rule(name));

            out.push_back(nr);
        }
    }
    // recurse into remaining children (replaced ones are now features, so they stop)
    for (auto& child : s.children) extract_subscopes_rec(child, parent_name, counter, out);
}

}  // namespace

// ---------------------------------------------------------------------------
// RuleSet
// ---------------------------------------------------------------------------

RuleSet::RuleSet(std::vector<std::shared_ptr<Rule>> input) {
    // capa refuses a ruleset with two rules of one name (ensure_rules_are_unique); a
    // loader that skips bad rules keeps the first and says so.
    std::vector<std::shared_ptr<Rule>> rules;
    {
        std::unordered_set<std::string> names;
        for (auto& r : input) {
            if (!names.insert(r->name).second) {
                std::fprintf(stderr, "warning: duplicate rule name, keeping the first: %s\n",
                             r->name.c_str());
                continue;
            }
            rules.push_back(std::move(r));
        }
    }
    source_rule_count_ = rules.size();

    // 1. extract subscope rules (mutates parents, appends synthetic lib rules)
    int counter = 0;
    std::vector<std::shared_ptr<Rule>> all = rules;
    // process like a stack so nested subscopes are handled
    std::vector<std::shared_ptr<Rule>> stack = rules;
    while (!stack.empty()) {
        auto rule = stack.back();
        stack.pop_back();
        std::vector<std::shared_ptr<Rule>> produced;
        extract_subscopes_rec(rule->root, rule->name, counter, produced);
        for (auto& nr : produced) {
            all.push_back(nr);
            stack.push_back(nr);
        }
    }
    rules_ = std::move(all);

    // 2. index by name + namespace
    for (const auto& r : rules_) by_name_[r->name] = r;
    for (const auto& r : rules_) {
        std::string ns = r->namespace_;
        while (!ns.empty()) {
            by_namespace_[ns].push_back(r);
            auto pos = ns.rfind('/');
            if (pos == std::string::npos) break;
            ns = ns.substr(0, pos);
        }
    }

    // 2b. report `match:` targets that no loaded rule provides. Nothing downstream fails
    //     loudly on these: the topological walk below skips unknown names, and match() just
    //     never produces the matched_rule feature -- so every dependent silently stops
    //     matching and the report still looks clean. capa instead raises
    //     (ensure_rule_dependencies_are_met). We keep loading, since a skipped rule
    //     shouldn't take the whole run down, but say what it hollowed out.
    {
        std::map<std::string, std::vector<std::string>> unresolved;  // dep -> dependents
        for (const auto& r : rules_)
            for (const auto& dep : rule_dependencies(*r, by_namespace_))
                if (!by_name_.count(dep)) unresolved[dep].push_back(r->name);
        for (const auto& [dep, dependents] : unresolved) {
            std::string who;
            for (std::size_t i = 0; i < dependents.size() && i < 3; ++i)
                who += (i ? ", " : "") + dependents[i];
            if (dependents.size() > 3)
                who += " (+" + std::to_string(dependents.size() - 3) + " more)";
            std::fprintf(stderr,
                         "warning: no rule provides `%s`; %zu rule(s) can never match: %s\n",
                         dep.c_str(), dependents.size(), who.c_str());
        }
    }

    // 3. capa.optimizer.optimize_rules: after subscope extraction, before indexing --
    //    the index picks among `and:` children in their optimized order.
    for (const auto& r : rules_) optimize_node(r->root);

    // 4. topological order over all rules (deps before dependents)
    std::vector<std::shared_ptr<Rule>> ordered;
    {
        std::unordered_set<std::string> seen;
        std::function<void(const std::shared_ptr<Rule>&)> rec =
            [&](const std::shared_ptr<Rule>& r) {
                if (seen.count(r->name)) return;
                seen.insert(r->name);  // insert before recursion to tolerate cycles
                for (const auto& dep : rule_dependencies(*r, by_namespace_)) {
                    auto it = by_name_.find(dep);
                    if (it != by_name_.end()) rec(it->second);
                }
                ordered.push_back(r);
            };
        for (const auto& r : rules_) rec(r);
    }

    // 5. build the per-scope feature index, in capa's scope order with one shared
    //    scores_by_rule map: a rule with both a static and a dynamic scope is indexed
    //    twice, and the score a FILE rule sees for it is the one written last.
    const Scope scopes[] = {Scope::CALL,        Scope::SPAN_OF_CALLS, Scope::THREAD,
                            Scope::PROCESS,     Scope::INSTRUCTION,   Scope::BASIC_BLOCK,
                            Scope::FUNCTION,    Scope::FILE};
    std::unordered_map<std::string, int> scores_by_rule;
    for (Scope sc : scopes) build_scope_index(sc, ordered, scores_by_rule);
}

void RuleSet::build_scope_index(Scope scope, const std::vector<std::shared_ptr<Rule>>& ordered,
                                std::unordered_map<std::string, int>& scores_by_rule) {
    ScopeIndex& si = scope_index_[scope];

    // topologically-ordered rules for this scope
    for (const auto& r : ordered)
        if (r->scopes.contains(scope)) si.matchables.push_back(r->matchable());
    si.ptrs.reserve(si.matchables.size());
    for (const auto& m : si.matchables) si.ptrs.push_back(&m);
    for (int i = 0; i < static_cast<int>(si.matchables.size()); ++i)
        si.index_by_name[si.matchables[i].name] = i;

    // index each rule by its most-selective feature(s)
    for (int i = 0; i < static_cast<int>(si.matchables.size()); ++i) {
        const MatchableRule& mr = si.matchables[i];
        auto scored = mr.root ? index_rec(*mr.root, scores_by_rule) : std::nullopt;
        if (!scored || scored->features.empty()) {
            si.always_rules.push_back(i);
            scores_by_rule[mr.name] = 9;  // couldn't index; assume selective
            continue;
        }
        scores_by_rule[mr.name] = scored->score;

        std::vector<Feature> string_feats;
        bool scan_bytes = false;
        for (const auto& f : scored->features) {
            if (f.type == FeatureType::Regex || f.type == FeatureType::Substring) {
                string_feats.push_back(f);
            } else if (f.type == FeatureType::Bytes) {
                // capa buckets these by 4-byte prefix; evaluating the rule outright is the
                // same answer, and bytes-indexed rules are rare.
                scan_bytes = true;
            } else {
                si.rules_by_feature[f].push_back(i);
            }
        }
        if (scan_bytes) si.always_rules.push_back(i);
        if (!string_feats.empty()) si.string_rules.emplace_back(i, std::move(string_feats));
    }
}

const std::vector<const MatchableRule*>& RuleSet::rules_for_scope(Scope scope) const {
    static const std::vector<const MatchableRule*> empty;
    auto it = scope_index_.find(scope);
    return it == scope_index_.end() ? empty : it->second.ptrs;
}

// capa RuleSet._match: evaluate only the candidate rules whose selective feature is
// present, in topological order, re-queuing dependents as their prerequisites match.
//
// Rather than copying the (possibly large) feature set to hold the match features added
// during matching, we add them into `features` in place and undo those exact additions
// before returning, so `features` is observably unchanged to the caller.
MatchResults RuleSet::match_indexed(const ScopeIndex& si, FeatureSet& features,
                                    const Address& addr) const {
    // worklist of candidate rule indices, processed smallest-index (topological) first.
    // std::set dedups on insert, so no separate "seen" set is needed: dependents always
    // have a larger topo index than the rule that produced them, so an already-processed
    // (smaller) index is never re-queued.
    std::set<int> worklist;
    auto add = [&](int i) { worklist.insert(i); };

    for (int i : si.always_rules) add(i);
    for (const auto& [f, locs] : features) {
        auto it = si.rules_by_feature.find(f);
        if (it != si.rules_by_feature.end())
            for (int idx : it->second) add(idx);
    }

    // rules indexed only by regex/substring: scan them against the String features.
    if (!si.string_rules.empty()) {
        FeatureSet string_features;
        for (const auto& [f, locs] : features)
            if (f.type == FeatureType::String) string_features[f] = locs;
        if (!string_features.empty()) {
            for (const auto& [idx, wanted] : si.string_rules) {
                for (const auto& w : wanted) {
                    if (eval_feature(w, string_features, true).success) {
                        add(idx);
                        break;
                    }
                }
            }
        }
    }

    MatchResults results;
    if (worklist.empty()) return results;

    // record match features we insert, so we can undo them before returning.
    struct Undo {
        Feature feat;
        bool key_created;
        bool addr_inserted;
    };
    std::vector<Undo> undo_log;
    auto add_match_feature = [&](const Feature& mf) {
        auto [it, created] = features.try_emplace(mf);
        bool inserted = it->second.insert(addr);
        if (created || inserted) undo_log.push_back({mf, created, inserted});
    };

    while (!worklist.empty()) {
        auto itmin = worklist.begin();
        int idx = *itmin;
        worklist.erase(itmin);

        const MatchableRule& rule = si.matchables[idx];
        if (!rule.root) continue;

        Result res = eval_node(*rule.root, features, /*short_circuit=*/true);
        if (!res.success) continue;

        res = eval_node(*rule.root, features, /*short_circuit=*/false);
        results[rule.name].emplace_back(addr, std::make_unique<Result>(std::move(res)));

        // add match features in place so dependent rules can match on them
        add_match_feature(Feature::matched_rule(rule.name));
        for (const auto& ns : rule.namespaces) add_match_feature(Feature::matched_rule(ns));

        // re-queue any rules indexed by this match (rule name or its namespaces)
        auto queue_dependents = [&](const Feature& mf) {
            auto it = si.rules_by_feature.find(mf);
            if (it != si.rules_by_feature.end())
                for (int di : it->second) add(di);
        };
        queue_dependents(Feature::matched_rule(rule.name));
        for (const auto& ns : rule.namespaces) queue_dependents(Feature::matched_rule(ns));
    }

    // undo our in-place additions (reverse order), restoring `features` exactly.
    for (auto it = undo_log.rbegin(); it != undo_log.rend(); ++it) {
        if (it->key_created) {
            features.erase(it->feat);
        } else if (it->addr_inserted) {
            auto f = features.find(it->feat);
            if (f != features.end()) f->second.erase(addr);
        }
    }

    return results;
}

MatchResults RuleSet::match(Scope scope, FeatureSet& features, const Address& addr) const {
    auto it = scope_index_.find(scope);
    if (it == scope_index_.end()) return {};
    MatchResults results = match_indexed(it->second, features, addr);
    if (paranoid_) {
        // `features` is back to what it was; the naive matcher must agree exactly.
        const MatchResults naive = match_naive(scope, features, addr);
        auto names = [](const MatchResults& m) {
            std::set<std::string> out;
            for (const auto& [name, r] : m) out.insert(name);
            return out;
        };
        if (names(results) != names(naive)) {
            std::string msg = "paranoid: " + scope_to_string(scope) + " @ " + addr.repr() + ": indexed {";
            for (const auto& n : names(results)) msg += " " + n;
            msg += " } != naive {";
            for (const auto& n : names(naive)) msg += " " + n;
            paranoid_failures_.push_back(msg + " }");
        }
    }
    return results;
}

MatchResults RuleSet::match_naive(Scope scope, const FeatureSet& features,
                                  const Address& addr) const {
    return capa::match(rules_for_scope(scope), features, addr).second;
}

std::shared_ptr<Rule> RuleSet::get(const std::string& name) const {
    auto it = by_name_.find(name);
    return it == by_name_.end() ? nullptr : it->second;
}

std::set<std::string> RuleSet::dependencies_of(const std::string& name) const {
    auto it = by_name_.find(name);
    if (it == by_name_.end()) return {};
    return rule_dependencies(*it->second, by_namespace_);
}

namespace {

// capa.rules.collect_rule_file_paths
std::vector<fs::path> collect_rule_file_paths(const std::vector<std::string>& paths) {
    std::vector<fs::path> out;
    for (const std::string& p : paths) {
        const fs::path root(p);
        if (!fs::exists(root)) throw InvalidRule{"rule path " + p + " does not exist or cannot be accessed"};
        if (fs::is_regular_file(root)) {
            out.push_back(root);
            continue;
        }
        std::vector<fs::path> found;
        for (auto it = fs::recursive_directory_iterator(root); it != fs::recursive_directory_iterator(); ++it) {
            // the .github directory contains CI config in capa-rules, including .yml files
            // that are not rules; .git holds nothing of interest either
            const std::string rel = fs::relative(it->path(), root).generic_string();
            if (it->is_directory()) {
                if (rel.find(".git") != std::string::npos) it.disable_recursion_pending();
                continue;
            }
            if (!it->is_regular_file()) continue;
            const std::string dir_rel = fs::relative(it->path().parent_path(), root).generic_string();
            if (dir_rel.find(".git") != std::string::npos) continue;
            const std::string file = it->path().filename().string();
            if (!ends_with(file, ".yml")) {
                if (!(starts_with(file, ".git") || ends_with(file, ".git") || ends_with(file, ".md") ||
                      ends_with(file, ".txt")))
                    std::fprintf(stderr, "warning: skipping non-.yml file: %s\n", file.c_str());
                continue;
            }
            found.push_back(it->path());
        }
        std::sort(found.begin(), found.end());
        out.insert(out.end(), found.begin(), found.end());
    }
    return out;
}

bool is_nursery_rule_path(const fs::path& path) {
    for (const auto& part : path)
        if (part.string() == "nursery") return true;
    return false;
}

}  // namespace

RuleSet RuleSet::load_from_paths(const std::vector<std::string>& paths) {
    std::vector<std::shared_ptr<Rule>> rules;
    int skipped = 0;
    for (const fs::path& path : collect_rule_file_paths(paths)) {
        std::ifstream f(path, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        try {
            auto rule = std::make_shared<Rule>(Rule::from_yaml(ss.str()));
            rule->path = path.generic_string();
            rule->nursery = is_nursery_rule_path(path);
            rules.push_back(std::move(rule));
        } catch (const InvalidRule& e) {
            // capa skips an empty document and refuses to run on any other bad rule;
            // capa-cpp skips both, loudly, so one bad rule cannot take a run down.
            ++skipped;
            std::fprintf(stderr, "warning: skipping rule %s: %s\n", path.string().c_str(),
                         e.message.c_str());
        } catch (const std::exception& e) {
            ++skipped;
            std::fprintf(stderr, "warning: skipping rule %s: %s\n", path.string().c_str(), e.what());
        } catch (...) {
            ++skipped;
            std::fprintf(stderr, "warning: skipping rule %s: unknown parse error\n",
                         path.string().c_str());
        }
    }
    if (skipped) std::fprintf(stderr, "note: skipped %d unparseable rule(s)\n", skipped);
    if (rules.empty()) {
        std::string joined;
        for (const auto& p : paths) joined += (joined.empty() ? "" : ", ") + p;
        throw InvalidRule{"no rules found under " + joined};
    }
    return RuleSet(std::move(rules));
}

RuleSet RuleSet::load_from_directory(const std::string& dir) { return load_from_paths({dir}); }

}  // namespace capa
