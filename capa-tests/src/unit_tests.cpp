// Checks of the places where a C++ port most easily drifts from capa.
//
// Each expectation below was taken from capa itself (9.4.0): the rule snippet was loaded
// with capa.rules.Rule.from_yaml + RuleSet (so subscope extraction and the optimizer have
// run) and its statement tree printed; each regex was compiled with capa.features.common
// .Regex and searched. They pin down behavior capa has no data-driven fixture for --
// PyYAML's typing of rule values, inline descriptions, the optimizer's child order, COM
// expansion -- and record *why* it is the way it is, so the knowledge survives the port.
#include "tests.h"

#include <cstdio>
#include <fstream>
#include <sstream>

#include "engine.h"
#include "freeze.h"
#include "pyregex.h"
#include "rules.h"

namespace capa::tests {

namespace {

std::string py_str_repr(const std::string& s) {
    return "'" + s + "'";
}

std::string py_bytes_repr(const std::string& raw) {
    std::string out = "b'";
    char buf[8];
    for (unsigned char c : raw) {
        if (c == '\\' || c == '\'') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c == '\t') {
            out += "\\t";
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c >= 0x20 && c < 0x7f) {
            out += static_cast<char>(c);
        } else {
            std::snprintf(buf, sizeof(buf), "\\x%02x", c);
            out += buf;
        }
    }
    return out + "'";
}

const char* class_name(FeatureType t) {
    switch (t) {
        case FeatureType::API: return "API";
        case FeatureType::Number: return "Number";
        case FeatureType::Offset: return "Offset";
        case FeatureType::Mnemonic: return "Mnemonic";
        case FeatureType::OperandNumber: return "OperandNumber";
        case FeatureType::OperandOffset: return "OperandOffset";
        case FeatureType::Property: return "Property";
        case FeatureType::Export: return "Export";
        case FeatureType::Import: return "Import";
        case FeatureType::Section: return "Section";
        case FeatureType::FunctionName: return "FunctionName";
        case FeatureType::String: return "String";
        case FeatureType::Substring: return "Substring";
        case FeatureType::Regex: return "Regex";
        case FeatureType::Bytes: return "Bytes";
        case FeatureType::MatchedRule: return "MatchedRule";
        case FeatureType::Characteristic: return "Characteristic";
        case FeatureType::Class: return "Class";
        case FeatureType::Namespace: return "Namespace";
        case FeatureType::OS: return "OS";
        case FeatureType::Arch: return "Arch";
        case FeatureType::Format: return "Format";
        case FeatureType::BasicBlock: return "BasicBlock";
    }
    return "?";
}

// The same rendering the expectations were printed with from capa.
std::string fmt_feature(const Feature& f) {
    std::string v;
    switch (f.vkind) {
        case ValueKind::Str: v = py_str_repr(f.s); break;
        case ValueKind::Bytes: v = py_bytes_repr(f.s); break;
        case ValueKind::Int: v = f.int_decimal(); break;
        case ValueKind::Float: v = std::to_string(f.f); break;
        case ValueKind::None: v = "None"; break;
    }
    std::string out = std::string(class_name(f.type)) + ":" + v;
    if (!f.description.empty()) out += " desc=" + py_str_repr(f.description);
    if (!f.access.empty()) out += " access=" + f.access;
    return out;
}

std::string fmt(const Node& n) {
    if (!n.is_statement) return fmt_feature(n.feature);
    const Statement& s = *n.stmt;
    std::string name, extra;
    std::vector<std::string> kids;
    switch (s.type) {
        case StatementType::And: name = "and"; break;
        case StatementType::Or: name = "or"; break;
        case StatementType::Not: name = "not"; break;
        case StatementType::Some:
            name = "some";
            extra = " count=" + std::to_string(s.count);
            break;
        case StatementType::Range:
            name = "range";
            extra = " min=" + std::to_string(s.range_min) + " max=" + std::to_string(s.range_max);
            kids.push_back(fmt_feature(s.range_child));
            break;
        case StatementType::Subscope: name = "subscope"; break;
    }
    for (const Node& c : s.children) kids.push_back(fmt(c));
    std::string out = name + extra + "(";
    for (std::size_t i = 0; i < kids.size(); ++i) out += (i ? ", " : "") + kids[i];
    return out + ")";
}

std::string rule_yaml(const std::string& features, const std::string& scope) {
    std::string indented;
    std::istringstream in(features);
    std::string line;
    while (std::getline(in, line)) indented += "    " + line + "\n";
    return "rule:\n  meta:\n    name: t\n    scopes:\n      static: " + scope +
           "\n      dynamic: unsupported\n  features:\n" + indented;
}

// The rule's tree as capa's RuleSet leaves it, or "ERROR <message>".
std::string parse(const std::string& features, const std::string& scope) {
    try {
        std::vector<std::shared_ptr<Rule>> rules{std::make_shared<Rule>(Rule::from_yaml(rule_yaml(features, scope)))};
        RuleSet rs(std::move(rules));
        return fmt(rs.get("t")->root);
    } catch (const InvalidRule& e) {
        return "ERROR " + e.message;
    }
}

struct RuleCase {
    const char* why;
    const char* features;
    const char* scope;
    const char* expected;  // exact, or "ERROR" for any InvalidRule
};

const RuleCase kRuleCases[] = {
    {"PyYAML reads a plain 010 as YAML 1.1 octal", "- number: 010", "function", "Number:8"},
    {"an inline description on a number", "- number: 0x10 = foo", "function", "Number:16 desc='foo'"},
    {"an unquoted number is not a string feature", "- string: 123", "function", "ERROR"},
    {"count with an integer value is an exact count", "- count(mnemonic(mov)): 2", "function",
     "range min=2 max=2(Mnemonic:'mov')"},
    {"count 'or more' is open-ended up to 2^64-1", "- count(mnemonic(mov)): 2 or more", "function",
     "range min=2 max=18446744073709551615(Mnemonic:'mov')"},
    {"substring takes an inline description, string does not", "- substring: foo = bar", "function",
     "Substring:'foo' desc='bar'"},
    {"string keeps ' = ' as part of its value", "- string: foo = bar", "function", "String:'foo = bar'"},
    {"numbers reach past INT64_MAX", "- number: 0xFFFFFFFFFFFFFFFF", "function", "Number:18446744073709551615"},
    {"os/arch/format values are checked before descriptions are split", "- os: windows = x", "function", "ERROR"},
    {"the optimizer sorts children by cost, stably: os 0, hash lookups 1, scans 2",
     "- and:\n  - substring: y\n  - api: kernel32.CreateFileA\n  - os: windows\n  - number: 1", "function",
     "and(OS:'windows', API:'CreateFileA', Number:1, Substring:'y')"},
    {"a bare `property` has no access", "- property: Foo::Bar", "instruction", "Property:'Foo::Bar'"},
    {"characteristics are validated against the scope", "- characteristic: loop", "instruction", "ERROR"},
    {"duplicate features are dropped, the first one (and its description) kept",
     "- or:\n  - description: d\n  - number: 1\n    description: one\n  - number: 1", "function",
     "or(Number:1 desc='one')"},
    {"count(string(...)) goes through the regex factory", "- count(string(/foo/i)): 1", "function",
     "range min=1 max=1(Regex:'/foo/i')"},
    {"N or more", "- 2 or more:\n  - api: a\n  - api: b", "function", "some count=2(API:'a', API:'b')"},
    {"YAML 1.1 underscores", "- number: 1_000", "function", "Number:1000"},
    {"YAML 1.1 sexagesimal", "- number: 12:30", "function", "Number:750"},
    {"bytes", "- bytes: 01 02 03", "function", "Bytes:b'\\x01\\x02\\x03'"},
    {"an ordinal import keeps its dll", "- api: ws2_32.#1", "function", "API:'ws2_32.#1'"},
    {"com/ expands to GUID strings and bytes, strings first after optimizing",
     "- com/class: InternetExplorer", "function",
     "or(String:'0002DF01-0000-0000-C000-000000000046' desc='CLSID_InternetExplorer as GUID string', "
     "Bytes:b'\\x01\\xdf\\x02\\x00\\x00\\x00\\x00\\x00\\xc0\\x00\\x00\\x00\\x00\\x00\\x00F' "
     "desc='CLSID_InternetExplorer as bytes')"},
};

struct RegexCase {
    const char* why;
    const char* value;
    const char* subject;
    bool matches;
};

const RegexCase kRegexCases[] = {
    {"capa compiles every regex with re.DOTALL", "/a.b/", "a\nb", true},
    {"Python's $ also matches before a final newline", "/ab$/", "ab\n", true},
    {"\\A", "/\\Aab/", "ab", true},
    {"named groups and backreferences", "/(?P<x>a)(?P=x)/", "aa", true},
    {"{,n} is {0,n}", "/a{,2}c/", "aac", true},
    {"a brace that is not a quantifier is literal", "/{x}/", "{x}", true},
    {"a leading ] in a class is literal", "/[]a]/", "]", true},
    {"leading inline flags", "/(?i)abc/", "ABC", true},
    {"/i", "/abc/i", "ABC", true},
    {"no DOTALL leak into classes", "/a[.]b/", "a\nb", false},
    {"$ is not a line end without MULTILINE", "/ab$/", "ab\nc", false},
};

}  // namespace

int run_unit_tests(const Options& opts) {
    Tally tally;

    for (const RuleCase& c : kRuleCases) {
        const std::string id = std::string("rules: ") + c.why;
        if (!opts.filter.empty() && id.find(opts.filter) == std::string::npos) continue;
        const std::string actual = parse(c.features, c.scope);
        const bool ok = std::string(c.expected) == "ERROR" ? actual.rfind("ERROR", 0) == 0 : actual == c.expected;
        if (ok)
            tally.pass(id, opts.verbose);
        else
            tally.fail(id, std::string("expected ") + c.expected + "\n        actual   " + actual);
    }

    for (const RegexCase& c : kRegexCases) {
        const std::string id = std::string("regex: ") + c.why + " " + c.value;
        if (!opts.filter.empty() && id.find(opts.filter) == std::string::npos) continue;
        std::string why;
        const std::regex* re = compile_capa_regex(c.value, &why);
        if (!re) {
            tally.fail(id, "does not compile: " + why);
            continue;
        }
        const bool actual = std::regex_search(std::string(c.subject), *re);
        if (actual == c.matches)
            tally.pass(id, opts.verbose);
        else
            tally.fail(id, std::string("expected ") + (c.matches ? "a match" : "no match"));
    }

    {
        // capa.engine.Some: an `optional:` with no children fails the short-circuit
        // evaluation (the threshold is tested only after a child), so match() drops it.
        const std::string id = "engine: empty optional short-circuits to false";
        Statement s;
        s.type = StatementType::Some;
        s.count = 0;
        FeatureSet none;
        const bool sc = eval_statement(s, none, true).success;
        const bool full = eval_statement(s, none, false).success;
        if (!sc && full)
            tally.pass(id, opts.verbose);
        else
            tally.fail(id, "short-circuit " + std::to_string(sc) + ", full " + std::to_string(full));
    }

    return tally.report("unit tests");
}

// Loads each freeze file and writes it back out. The JSON must come back byte for byte
// as capa wrote it -- same members, same spellings, same order, same sorting -- when capa
// wrote it with --reproducible (an empty extractor version); otherwise it must at least
// survive a second round trip unchanged.
int run_freeze_roundtrip(const std::vector<std::string>& paths, const Options& opts) {
    Tally tally;
    for (const std::string& path : paths) {
        try {
            std::ifstream in(path, std::ios::binary);
            std::ostringstream ss;
            ss << in.rdbuf();
            const std::string original = freeze::decompress_document(ss.str());
            const freeze::Frozen a = freeze::loads(original);
            const bool reproducible = a.extractor_version.empty();
            std::string first, second;
            if (a.static_extractor) {
                first = freeze::dumps(*a.static_extractor, a.extractor_name, reproducible);
                second = freeze::dumps(*freeze::loads(first).static_extractor, a.extractor_name, reproducible);
            } else {
                first = freeze::dumps(*a.dynamic_extractor, a.extractor_name, reproducible);
                second = freeze::dumps(*freeze::loads(first).dynamic_extractor, a.extractor_name, reproducible);
            }
            if (first != second) {
                tally.fail(path, "dump(load(dump(x))) != dump(x)");
            } else if (reproducible && first != original) {
                std::size_t at = 0;
                while (at < first.size() && at < original.size() && first[at] == original[at]) ++at;
                const std::size_t from = at > 80 ? at - 80 : 0;
                tally.fail(path, "differs from capa's own serialization at byte " + std::to_string(at) +
                                     "\n        capa:     ..." + original.substr(from, 160) +
                                     "\n        capa-cpp: ..." + first.substr(from, 160));
            } else {
                tally.pass(path, opts.verbose);
            }
        } catch (const std::exception& e) {
            tally.fail(path, e.what());
        }
    }
    return tally.report("freeze round trips");
}

}  // namespace capa::tests
