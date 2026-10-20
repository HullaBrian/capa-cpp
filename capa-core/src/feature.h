// Feature model for capa-cpp.
//
// Ports capa/features/common.py, features/insn.py, features/file.py.
//
// A Feature is a pure value type. Identity (hash + equality) is on
// (name, value[, access][, index]) exactly like capa:
//   - most features hash on (name, value)
//   - Property additionally on `access`
//   - operand features encode their index in the name ("operand[0].number")
// `description` is NOT part of identity.
//
// Evaluation lives in engine.h (free functions over FeatureSet) to avoid a
// circular dependency, so this header stays data-only.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace capa {

// ---- global feature constants (capa/features/common.py) ----
inline constexpr const char* OS_WINDOWS = "windows";
inline constexpr const char* OS_LINUX = "linux";
inline constexpr const char* OS_MACOS = "macos";
inline constexpr const char* OS_ANDROID = "android";
inline constexpr const char* OS_ANY = "any";

inline constexpr const char* ARCH_I386 = "i386";
inline constexpr const char* ARCH_AMD64 = "amd64";
inline constexpr const char* ARCH_AARCH64 = "aarch64";
inline constexpr const char* ARCH_ANY = "any";

inline constexpr const char* FORMAT_PE = "pe";
inline constexpr const char* FORMAT_ELF = "elf";
inline constexpr const char* FORMAT_DOTNET = "dotnet";
// capa's spelling for position-independent code with no container, which is what an
// unbacked executable region in a process dump is.
inline constexpr const char* FORMAT_SC32 = "sc32";
inline constexpr const char* FORMAT_SC64 = "sc64";

inline constexpr const char* ACCESS_READ = "read";
inline constexpr const char* ACCESS_WRITE = "write";

enum class FeatureType {
    // insn.py
    API,
    Number,
    Offset,
    Mnemonic,
    OperandNumber,
    OperandOffset,
    Property,
    // file.py
    Export,
    Import,
    Section,
    FunctionName,
    // common.py
    String,
    Substring,
    Regex,
    Bytes,
    MatchedRule,
    Characteristic,
    Class,
    Namespace,
    OS,
    Arch,
    Format,
    // basicblock.py (structural; only used inside count() on the static path)
    BasicBlock,
};

enum class ValueKind { None, Str, Int, Float, Bytes };

struct Feature {
    FeatureType type = FeatureType::String;
    std::string name;  // canonical name used for hashing/rendering ("api", "match", ...)

    ValueKind vkind = ValueKind::None;
    std::string s;       // Str/Regex-pattern/Bytes(raw bytes)
    std::int64_t i = 0;  // Int: the low 64 bits of the value
    double f = 0.0;      // Float
    // Int only. capa's values are Python ints, which are unbounded, and the ones the
    // backends produce span [-2^63, 2^64): x64 immediates and sandbox-logged arguments
    // reach past INT64_MAX. `big` marks a value of 2^63 or more, whose bits `i` holds and
    // which would otherwise read as negative -- so that number(-1) and
    // number(0xFFFFFFFFFFFFFFFF) stay two different features, as they are in capa.
    bool big = false;

    std::string access;  // Property: "read"/"write" (empty otherwise)
    int index = 0;       // operand index (encoded in name too)

    std::string description;  // not part of identity

    // Lazily-cached identity hash. Features are immutable after construction (the
    // factories set all identity fields), so caching is safe and avoids re-hashing the
    // name/value strings on every unordered_map operation (a hot path during matching).
    mutable std::size_t cached_hash_ = 0;
    mutable bool has_hash_ = false;

    // ---- factories (mirror capa's Feature subclasses) ----
    static Feature api(const std::string& v, const std::string& desc = "");
    static Feature number(std::int64_t v, const std::string& desc = "");
    static Feature number_float(double v, const std::string& desc = "");
    static Feature offset(std::int64_t v, const std::string& desc = "");
    static Feature mnemonic(const std::string& v, const std::string& desc = "");
    static Feature operand_number(int idx, std::int64_t v, const std::string& desc = "");
    static Feature operand_offset(int idx, std::int64_t v, const std::string& desc = "");
    static Feature property(const std::string& v, const std::string& access,
                            const std::string& desc = "");
    static Feature export_(const std::string& v, const std::string& desc = "");
    static Feature import_(const std::string& v, const std::string& desc = "");
    static Feature section(const std::string& v, const std::string& desc = "");
    static Feature function_name(const std::string& v, const std::string& desc = "");
    static Feature string(const std::string& v, const std::string& desc = "");
    static Feature substring(const std::string& v, const std::string& desc = "");
    static Feature regex(const std::string& v, const std::string& desc = "");
    static Feature bytes(const std::string& raw, const std::string& desc = "");
    static Feature matched_rule(const std::string& v, const std::string& desc = "");
    static Feature characteristic(const std::string& v, const std::string& desc = "");
    static Feature klass(const std::string& v, const std::string& desc = "");
    static Feature namespace_(const std::string& v, const std::string& desc = "");
    static Feature os(const std::string& v, const std::string& desc = "");
    static Feature arch(const std::string& v, const std::string& desc = "");
    static Feature format(const std::string& v, const std::string& desc = "");
    static Feature basic_block(const std::string& desc = "");

    // Reinterprets an Int value as unsigned 64-bit, the way capa's backends report
    // machine words: `number_u(f.i)` for a register or immediate read as uint64.
    Feature& as_unsigned() {
        if (vkind == ValueKind::Int && i < 0) big = true;
        has_hash_ = false;
        return *this;
    }
    // The Int value as Python would print it, e.g. "18446744073709551615".
    std::string int_decimal() const;

    // `StringFactory`: "/pat/" or "/pat/i" -> Regex, else String.
    static Feature string_factory(const std::string& v, const std::string& desc = "");

    bool is_global() const {
        return type == FeatureType::OS || type == FeatureType::Arch ||
               type == FeatureType::Format;
    }

    // Identity comparison (ignores description), matching capa __eq__.
    bool identity_equal(const Feature& o) const {
        if (name != o.name || vkind != o.vkind) return false;
        switch (vkind) {
            case ValueKind::Str:
            case ValueKind::Bytes:
                if (s != o.s) return false;
                break;
            case ValueKind::Int:
                if (i != o.i || big != o.big) return false;
                break;
            case ValueKind::Float:
                if (f != o.f) return false;
                break;
            case ValueKind::None:
                break;
        }
        return access == o.access && index == o.index;
    }
    bool operator==(const Feature& o) const { return identity_equal(o); }

    std::size_t hash() const;

    // Rendering helpers (capa get_name_str / get_value_str / __str__).
    std::string get_name_str() const;   // e.g. "property/read", "operand[0].number"
    std::string get_value_str() const;  // hex for numbers, escaped for strings, ...
    std::string str() const;            // "name(value = desc)"
};

}  // namespace capa

namespace std {
template <>
struct hash<capa::Feature> {
    size_t operator()(const capa::Feature& f) const noexcept { return f.hash(); }
};
}  // namespace std
