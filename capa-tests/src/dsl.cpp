#include "dsl.h"

#include <optional>
#include <regex>

namespace capa::dsl {

namespace {

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v'; }

std::string strip(const std::string& s) {
    std::size_t a = 0, b = s.size();
    while (a < b && is_space(s[a])) ++a;
    while (b > a && is_space(s[b - 1])) --b;
    return s.substr(a, b - a);
}

bool starts_with(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }

std::string strip_prefix(const std::string& text, const std::string& prefix) {
    return strip(text.substr(prefix.size()));
}

std::string strip_quotes(const std::string& v) {
    if (v.size() >= 2 && v.front() == v.back() && (v.front() == '"' || v.front() == '\'')) return v.substr(1, v.size() - 2);
    return v;
}

// _split_feature_line: "<scope>: <feature>[ -> <target>]". The feature may itself
// contain ": "; the target is split off the right.
struct Split {
    std::string scope, feature;
    std::optional<std::string> target;
};

Split split_feature_line(const std::string& text) {
    Split out;
    std::string body = text;
    const auto arrow = text.rfind(" -> ");
    if (arrow != std::string::npos) {
        body = text.substr(0, arrow);
        out.target = text.substr(arrow + 4);
    }
    const auto sep = body.find(": ");
    if (sep == std::string::npos) throw DslError("expected '<scope>: <feature>': " + text);
    out.scope = body.substr(0, sep);
    out.feature = body.substr(sep + 2);
    return out;
}

Feature with_int(Feature f, const Int& v) {
    f.i = v.v;
    f.big = v.big;
    return f;
}

std::string from_hex(const std::string& in) {
    std::string hex;
    for (char c : in)
        if (c != ' ') hex += c;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (hex.size() % 2) throw DslError("invalid bytes: " + in);
    std::string out;
    for (std::size_t k = 0; k < hex.size(); k += 2) {
        if (nibble(hex[k]) < 0 || nibble(hex[k + 1]) < 0) throw DslError("invalid bytes: " + in);
        out.push_back(static_cast<char>((nibble(hex[k]) << 4) | nibble(hex[k + 1])));
    }
    return out;
}

// _parse_number_literal: hex is an int, anything with . e E is a float, else an int.
Feature number_literal(Feature f, const std::string& raw) {
    const std::string value = strip(raw);
    std::string unsigned_part = value;
    while (!unsigned_part.empty() && (unsigned_part[0] == '+' || unsigned_part[0] == '-')) unsigned_part.erase(0, 1);
    const bool hex = unsigned_part.size() >= 2 && unsigned_part[0] == '0' &&
                     (unsigned_part[1] == 'x' || unsigned_part[1] == 'X');
    if (!hex && value.find_first_of(".eE") != std::string::npos) {
        f.vkind = ValueKind::Float;
        try {
            f.f = std::stod(value);
        } catch (const std::exception&) {
            throw DslError("invalid number: " + value);
        }
        return f;
    }
    return with_int(f, parse_int0(value));
}

}  // namespace

Int parse_int0(const std::string& in) {
    const std::string s = strip(in);
    std::size_t k = 0;
    bool negative = false;
    if (k < s.size() && (s[k] == '+' || s[k] == '-')) negative = s[k++] == '-';
    int base = 10;
    bool prefixed = false;
    if (k + 1 < s.size() && s[k] == '0') {
        const char p = static_cast<char>(s[k + 1] | 0x20);
        if (p == 'x' || p == 'o' || p == 'b') {
            base = p == 'x' ? 16 : p == 'o' ? 8 : 2;
            k += 2;
            prefixed = true;
        }
    }
    std::string digits;
    bool last_us = false;
    for (std::size_t j = k; j < s.size(); ++j) {
        if (s[j] == '_') {
            if (last_us || (digits.empty() && !prefixed)) throw DslError("invalid integer: " + in);
            last_us = true;
            continue;
        }
        last_us = false;
        digits += s[j];
    }
    if (digits.empty() || last_us) throw DslError("invalid integer: " + in);
    // base 0 forbids a leading zero on a non-zero decimal
    if (base == 10 && digits.size() > 1 && digits[0] == '0' && digits.find_first_not_of('0') != std::string::npos)
        throw DslError("invalid integer: " + in);
    std::uint64_t magnitude = 0;
    for (char c : digits) {
        int d = c >= '0' && c <= '9' ? c - '0' : (c | 0x20) >= 'a' && (c | 0x20) <= 'z' ? (c | 0x20) - 'a' + 10 : 99;
        if (d >= base) throw DslError("invalid integer: " + in);
        if (magnitude > (UINT64_MAX - static_cast<std::uint64_t>(d)) / static_cast<std::uint64_t>(base))
            throw DslError("integer out of range: " + in);
        magnitude = magnitude * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(d);
    }
    Int out;
    if (negative) {
        if (magnitude > (std::uint64_t{1} << 63)) throw DslError("integer out of range: " + in);
        out.v = static_cast<std::int64_t>(std::uint64_t{0} - magnitude);
    } else {
        out.v = static_cast<std::int64_t>(magnitude);
        out.big = magnitude >= (std::uint64_t{1} << 63);
    }
    return out;
}

Address parse_address(const std::string& spec) {
    static const std::regex token_offset(R"(token\((.+)\)\+(.+))");
    static const std::regex token(R"(token\((.+)\))");
    static const std::regex proc2(R"(process\{ppid:(\d+),pid:(\d+)\})");
    static const std::regex proc1(R"(process\{pid:(\d+)\})");
    static const std::regex thread3(R"(process\{ppid:(\d+),pid:(\d+),tid:(\d+)\})");
    static const std::regex thread2(R"(process\{pid:(\d+),tid:(\d+)\})");
    static const std::regex call4(R"(process\{ppid:(\d+),pid:(\d+),tid:(\d+),call:(\d+)\})");
    static const std::regex call3(R"(process\{pid:(\d+),tid:(\d+),call:(\d+)\})");

    auto u = [](const std::string& s) { return static_cast<std::uint64_t>(parse_int0(s).v); };
    auto u32 = [](const std::string& s) { return static_cast<std::uint32_t>(std::stoul(s)); };
    std::smatch m;
    if (spec == "global" || spec == "no address") return Address::no_address();
    if (starts_with(spec, "base address+")) return Address::relative(u(spec.substr(13)));
    if (starts_with(spec, "file+")) return Address::file_offset(u(spec.substr(5)));
    if (std::regex_match(spec, m, token_offset)) return Address::dn_token_offset(u(m[1]), u(m[2]));
    if (std::regex_match(spec, m, token)) return Address::dn_token(u(m[1]));
    if (std::regex_match(spec, m, proc2)) return Address::process(u32(m[2]), u32(m[1]));
    if (std::regex_match(spec, m, proc1)) return Address::process(u32(m[1]));
    if (std::regex_match(spec, m, thread3)) return Address::thread(Address::process(u32(m[2]), u32(m[1])), u32(m[3]));
    if (std::regex_match(spec, m, thread2)) return Address::thread(Address::process(u32(m[1])), u32(m[2]));
    if (std::regex_match(spec, m, call4))
        return Address::call(Address::thread(Address::process(u32(m[2]), u32(m[1])), u32(m[3])), std::stoull(m[4]));
    if (std::regex_match(spec, m, call3))
        return Address::call(Address::thread(Address::process(u32(m[1])), u32(m[2])), std::stoull(m[3]));
    const Int v = parse_int0(spec);
    if (!v.big && v.v < 0) throw DslError("negative address: " + spec);
    return Address::absolute(static_cast<std::uint64_t>(v.v));
}

Address parse_static_address(const std::string& spec) {
    const Address a = parse_address(spec);
    if (a.type == AddressType::PROCESS || a.type == AddressType::THREAD || a.type == AddressType::CALL)
        throw DslError("expected a static address, got " + spec);
    return a;
}

Feature parse_feature(const std::string& raw) {
    static const std::regex operand_number(R"(operand\[(\d+)\]\.number\((.*)\))");
    static const std::regex operand_offset(R"(operand\[(\d+)\]\.offset\((.*)\))");
    static const std::regex property(R"(property(?:/(read|write))?\((.*)\))");
    static const std::regex generic(R"(([a-z][a-z0-9\- ]*)\(([\s\S]*)\))");

    const std::string text = strip(raw);
    if (text == "basic block") return Feature::basic_block();
    std::smatch m;
    if (std::regex_match(text, m, operand_number))
        return number_literal(Feature::operand_number(std::stoi(m[1]), 0), m[2]);
    if (std::regex_match(text, m, operand_offset))
        return with_int(Feature::operand_offset(std::stoi(m[1]), 0), parse_int0(m[2]));
    if (std::regex_match(text, m, property))
        return Feature::property(strip_quotes(strip(m[2])), m[1].matched ? std::string(m[1]) : std::string());
    if (!std::regex_match(text, m, generic)) throw DslError("unsupported feature syntax: " + text);

    const std::string name = m[1];
    const std::string value = strip_quotes(strip(m[2]));
    if (name == "api") return Feature::api(value);
    if (name == "arch") return Feature::arch(value);
    if (name == "bytes") return Feature::bytes(from_hex(value));
    if (name == "characteristic") return Feature::characteristic(value);
    if (name == "class") return Feature::klass(value);
    if (name == "export") return Feature::export_(value);
    if (name == "format") return Feature::format(value);
    if (name == "function-name" || name == "function name") return Feature::function_name(value);
    if (name == "import") return Feature::import_(value);
    if (name == "match") return Feature::matched_rule(value);
    if (name == "mnemonic") return Feature::mnemonic(value);
    if (name == "namespace") return Feature::namespace_(value);
    if (name == "number") return number_literal(Feature::number(0), value);
    if (name == "offset") return with_int(Feature::offset(0), parse_int0(value));
    if (name == "os") return Feature::os(value);
    if (name == "section") return Feature::section(value);
    if (name == "string") return Feature::string(value);
    if (name == "substring") return Feature::substring(value);
    throw DslError("unsupported feature type: " + name);
}

std::vector<std::string> feature_lines(const std::string& block) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= block.size()) {
        std::size_t nl = block.find('\n', start);
        if (nl == std::string::npos) nl = block.size();
        const std::string line = strip(block.substr(start, nl - start));
        if (!line.empty() && line[0] != '#') out.push_back(line);
        start = nl + 1;
    }
    return out;
}

std::unique_ptr<NullStaticFeatureExtractor> parse_static(const std::vector<std::string>& lines,
                                                         const Address& base_address) {
    auto ex = std::make_unique<NullStaticFeatureExtractor>();
    ex->base_address = base_address;
    std::optional<Address> function, basic_block;

    for (const std::string& line : lines) {
        if (starts_with(line, "global:")) {
            std::string rest = strip_prefix(line, "global:");
            if (starts_with(rest, "global: ")) rest = rest.substr(8);
            ex->global_features.emplace_back(parse_feature(rest), Address::no_address());
        } else if (starts_with(line, "file:")) {
            const Split s = split_feature_line(strip_prefix(line, "file:"));
            if (s.target) throw DslError("file feature lines do not support relocated addresses");
            ex->file_features.emplace_back(parse_feature(s.feature), parse_static_address(s.scope));
        } else if (starts_with(line, "func:")) {
            const std::string rest = strip_prefix(line, "func:");
            if (rest.find(": ") == std::string::npos) {
                function = parse_static_address(rest);
                ex->functions[*function];
                basic_block.reset();
                continue;
            }
            const Split s = split_feature_line(rest);
            function = parse_static_address(s.scope);
            const Address at = s.target ? parse_static_address(*s.target) : *function;
            ex->functions[*function].features.emplace_back(parse_feature(s.feature), at);
            basic_block.reset();
        } else if (starts_with(line, "bb:")) {
            if (!function) throw DslError("basic block line without current function: " + line);
            const Split s = split_feature_line(strip_prefix(line, "bb:"));
            const Address bb = parse_static_address(s.scope);
            const Address at = s.target ? parse_static_address(*s.target) : bb;
            ex->functions[*function].basic_blocks[bb].features.emplace_back(parse_feature(s.feature), at);
            basic_block = bb;
        } else if (starts_with(line, "insn:")) {
            if (!function || !basic_block) throw DslError("instruction line without current basic block: " + line);
            const Split s = split_feature_line(strip_prefix(line, "insn:"));
            const Address insn = parse_static_address(s.scope);
            const Address at = s.target ? parse_static_address(*s.target) : insn;
            ex->functions[*function].basic_blocks[*basic_block].instructions[insn].features.emplace_back(
                parse_feature(s.feature), at);
        } else {
            throw DslError("unsupported static feature line: " + line);
        }
    }
    return ex;
}

DynamicListing parse_dynamic(const std::vector<std::string>& lines) {
    static const std::regex header(R"(^(.+) \((?:ppid=(\d+), )?pid=(\d+)\)$)");
    DynamicListing out;
    out.extractor = std::make_unique<NullDynamicFeatureExtractor>();
    NullDynamicFeatureExtractor& ex = *out.extractor;
    std::optional<Address> process, thread;

    auto ensure_process = [&](const Address& a, const std::string* name) -> NullProcess& {
        auto it = ex.processes.find(a);
        if (it == ex.processes.end()) {
            NullProcess p;
            p.name = name ? *name : "process-" + std::to_string(a.pid);
            it = ex.processes.emplace(a, std::move(p)).first;
        } else if (name) {
            it->second.name = *name;
        }
        return it->second;
    };
    auto ensure_thread = [&](const Address& t) -> NullThread& {
        return ensure_process(t.process_part(), nullptr).threads[t];
    };

    for (const std::string& line : lines) {
        if (starts_with(line, "global:")) {
            std::string rest = strip_prefix(line, "global:");
            if (starts_with(rest, "global: ")) rest = rest.substr(8);
            ex.global_features.emplace_back(parse_feature(rest), Address::no_address());
        } else if (starts_with(line, "file:")) {
            const Split s = split_feature_line(strip_prefix(line, "file:"));
            if (s.target) throw DslError("file feature lines do not support relocated addresses");
            ex.file_features.emplace_back(parse_feature(s.feature), parse_address(s.scope));
        } else if (starts_with(line, "proc:")) {
            const std::string rest = strip_prefix(line, "proc:");
            std::smatch m;
            if (std::regex_match(rest, m, header)) {
                const std::uint32_t ppid = m[2].matched ? static_cast<std::uint32_t>(std::stoul(m[2])) : 0;
                const Address a = Address::process(static_cast<std::uint32_t>(std::stoul(m[3])), ppid);
                const std::string name = m[1];
                ensure_process(a, &name);
                process = a;
                thread.reset();
                continue;
            }
            if (!process) throw DslError("process feature line without current process: " + line);
            const Split s = split_feature_line(rest);
            NullProcess& p = ensure_process(*process, nullptr);
            if (p.name != s.scope) throw DslError("process feature line does not match current process: " + line);
            const Address at = s.target ? parse_address(*s.target) : *process;
            p.features.emplace_back(parse_feature(s.feature), at);
        } else if (starts_with(line, "thread:")) {
            if (!process) throw DslError("thread line without current process: " + line);
            const std::string rest = strip_prefix(line, "thread:");
            if (rest.find(": ") == std::string::npos) {
                thread = Address::thread(*process, static_cast<std::uint32_t>(parse_int0(rest).v));
                ensure_thread(*thread);
                continue;
            }
            const Split s = split_feature_line(rest);
            const Address t = Address::thread(*process, static_cast<std::uint32_t>(parse_int0(s.scope).v));
            const Address at = s.target ? parse_address(*s.target) : t;
            ensure_thread(t).features.emplace_back(parse_feature(s.feature), at);
            thread = t;
        } else if (starts_with(line, "call:")) {
            if (!thread) throw DslError("call line without current thread: " + line);
            const Split s = split_feature_line(strip_prefix(line, "call:"));
            const std::uint64_t id = static_cast<std::uint64_t>(parse_int0(s.scope).v);
            const Address c = Address::call(*thread, id);
            auto known = out.calls_by_id.find(id);
            if (known != out.calls_by_id.end() && known->second != c)
                throw DslError("dynamic fixture call IDs must be unique within a test: " + std::to_string(id));
            out.calls_by_id[id] = c;
            NullCall& call = ensure_thread(*thread).calls[c];
            if (call.name.empty()) call.name = "call-" + std::to_string(id);
            const Address at = s.target ? parse_address(*s.target) : c;
            call.features.emplace_back(parse_feature(s.feature), at);
        } else {
            throw DslError("unsupported dynamic feature line: " + line);
        }
    }
    ex.index_calls();
    return out;
}

}  // namespace capa::dsl
