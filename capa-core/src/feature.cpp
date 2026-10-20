#include "feature.h"

#include <cctype>
#include <cstdio>

namespace capa {

namespace {

std::size_t hash_combine(std::size_t h, std::size_t v) {
    return h ^ (v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
}

// capa.helpers.hex: "0x123ABC" upper case, "-0x..." for negatives.
std::string hex_upper(std::int64_t n, bool big) {
    char buf[32];
    if (n < 0 && !big) {
        // negate in unsigned space: -n would overflow for INT64_MIN.
        std::snprintf(buf, sizeof(buf), "-0x%llX",
                      static_cast<unsigned long long>(0ull - static_cast<unsigned long long>(n)));
    } else {
        std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(n));
    }
    return buf;
}

// capa.features.common.escape_string, approximated: Python repr-style escaping of
// control chars and quotes. Good enough for rendering/JSON display parity.
std::string escape_string(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\x%02x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// capa.features.common.hex_string: "0a40b1" -> "0A 40 B1"
std::string hex_string_spaced(const std::string& raw) {
    std::string out;
    out.reserve(raw.size() * 3);
    char buf[4];
    for (std::size_t k = 0; k < raw.size(); ++k) {
        if (k) out += ' ';
        std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned char>(raw[k]));
        out += buf;
    }
    return out;
}

}  // namespace

// ---- factories ----

Feature Feature::api(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::API;
    f.name = "api";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::number(std::int64_t v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Number;
    f.name = "number";
    f.vkind = ValueKind::Int;
    f.i = v;
    f.description = desc;
    return f;
}

Feature Feature::number_float(double v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Number;
    f.name = "number";
    f.vkind = ValueKind::Float;
    f.f = v;
    f.description = desc;
    return f;
}

Feature Feature::offset(std::int64_t v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Offset;
    f.name = "offset";
    f.vkind = ValueKind::Int;
    f.i = v;
    f.description = desc;
    return f;
}

Feature Feature::mnemonic(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Mnemonic;
    f.name = "mnemonic";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::operand_number(int idx, std::int64_t v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::OperandNumber;
    f.name = "operand[" + std::to_string(idx) + "].number";
    f.vkind = ValueKind::Int;
    f.i = v;
    f.index = idx;
    f.description = desc;
    return f;
}

Feature Feature::operand_offset(int idx, std::int64_t v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::OperandOffset;
    f.name = "operand[" + std::to_string(idx) + "].offset";
    f.vkind = ValueKind::Int;
    f.i = v;
    f.index = idx;
    f.description = desc;
    return f;
}

Feature Feature::property(const std::string& v, const std::string& access,
                          const std::string& desc) {
    Feature f;
    f.type = FeatureType::Property;
    f.name = "property";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.access = access;
    f.description = desc;
    return f;
}

Feature Feature::export_(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Export;
    f.name = "export";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::import_(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Import;
    f.name = "import";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::section(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Section;
    f.name = "section";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::function_name(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::FunctionName;
    f.name = "function-name";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::string(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::String;
    f.name = "string";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::substring(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Substring;
    f.name = "substring";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::regex(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Regex;
    f.name = "regex";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::bytes(const std::string& raw, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Bytes;
    f.name = "bytes";
    f.vkind = ValueKind::Bytes;
    f.s = raw;
    f.description = desc;
    return f;
}

Feature Feature::matched_rule(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::MatchedRule;
    f.name = "match";  // capa: MatchedRule.name == "match"
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::characteristic(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Characteristic;
    f.name = "characteristic";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::klass(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Class;
    f.name = "class";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::namespace_(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Namespace;
    f.name = "namespace";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::os(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::OS;
    f.name = "os";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::arch(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Arch;
    f.name = "arch";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::format(const std::string& v, const std::string& desc) {
    Feature f;
    f.type = FeatureType::Format;
    f.name = "format";
    f.vkind = ValueKind::Str;
    f.s = v;
    f.description = desc;
    return f;
}

Feature Feature::basic_block(const std::string& desc) {
    Feature f;
    f.type = FeatureType::BasicBlock;
    f.name = "basicblock";
    f.vkind = ValueKind::None;
    f.description = desc;
    return f;
}

Feature Feature::string_factory(const std::string& v, const std::string& desc) {
    if (v.size() >= 2 && v.front() == '/' &&
        (v.back() == '/' || (v.size() >= 3 && v[v.size() - 1] == 'i' && v[v.size() - 2] == '/'))) {
        return regex(v, desc);
    }
    return string(v, desc);
}

// ---- identity / rendering ----

std::size_t Feature::hash() const {
    if (has_hash_) return cached_hash_;
    std::size_t h = std::hash<std::string>{}(name);
    h = hash_combine(h, static_cast<std::size_t>(vkind));
    switch (vkind) {
        case ValueKind::Str:
        case ValueKind::Bytes:
            h = hash_combine(h, std::hash<std::string>{}(s));
            break;
        case ValueKind::Int:
            h = hash_combine(h, std::hash<std::int64_t>{}(i));
            h = hash_combine(h, big ? 1 : 0);
            break;
        case ValueKind::Float:
            h = hash_combine(h, std::hash<double>{}(f));
            break;
        case ValueKind::None:
            break;
    }
    h = hash_combine(h, std::hash<std::string>{}(access));
    h = hash_combine(h, std::hash<int>{}(index));
    cached_hash_ = h;
    has_hash_ = true;
    return h;
}

std::string Feature::get_name_str() const {
    if (type == FeatureType::Property && !access.empty()) {
        return name + "/" + access;
    }
    return name;
}

std::string Feature::get_value_str() const {
    switch (type) {
        case FeatureType::Number:
        case FeatureType::Offset:
        case FeatureType::OperandNumber:
        case FeatureType::OperandOffset:
            if (vkind == ValueKind::Float) {
                char buf[64];
                std::snprintf(buf, sizeof(buf), "%g", f);
                return buf;
            }
            return hex_upper(i, big);
        case FeatureType::String:
        case FeatureType::Substring:
            return escape_string(s);
        case FeatureType::Regex:
            return s;  // raw pattern, see capa Regex.get_value_str
        case FeatureType::Bytes:
            return hex_string_spaced(s);
        default:
            if (vkind == ValueKind::Str) return s;
            if (vkind == ValueKind::Int) return int_decimal();
            return "";
    }
}

std::string Feature::int_decimal() const {
    return big ? std::to_string(static_cast<std::uint64_t>(i)) : std::to_string(i);
}

std::string Feature::str() const {
    if (vkind == ValueKind::None) {
        return get_name_str();
    }
    if (!description.empty()) {
        return get_name_str() + "(" + get_value_str() + " = " + description + ")";
    }
    return get_name_str() + "(" + get_value_str() + ")";
}

}  // namespace capa
