// The show-features DSL that capa's matcher fixtures are written in.
//
// Ports the parsers in capa's tests/test_match_fixtures.py: a listing like
//
//     func: 0x401000
//      bb: 0x401000: basic block
//       insn: 0x401000: mnemonic(mov)
//       insn: 0x401000: offset(0x402000) -> 0x402000
//
// (or, for dynamic fixtures, `proc:` / `thread:` / `call:` lines) becomes a
// NullStaticFeatureExtractor or NullDynamicFeatureExtractor: a human-readable alternative
// to raw freeze JSON; a parsed listing can be
// written out as a freeze file with freeze::dump.
#pragma once

#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "address.h"
#include "feature.h"
#include "null_extractor.h"

namespace capa::dsl {

struct DslError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Python's int(s, 0): optional sign, 0x / 0o / 0b prefixes, underscores between digits.
// The value is returned as capa-cpp represents capa's ints (see Feature::big).
struct Int {
    std::int64_t v = 0;
    bool big = false;
};
Int parse_int0(const std::string& s);

// _parse_address: an integer (absolute), `global` / `no address`, `base address+N`,
// `file+N`, `token(N)`, `token(N)+M`, or `process{[ppid:P,]pid:N[,tid:T[,call:C]]}`.
Address parse_address(const std::string& spec);
Address parse_static_address(const std::string& spec);

// _parse_feature: `api(CreateFileA)`, `number(0x10)`, `operand[0].offset(4)`,
// `property/read(Foo::Bar)`, `basic block`, ...
Feature parse_feature(const std::string& text);

// A listing's non-empty, non-comment lines, stripped.
std::vector<std::string> feature_lines(const std::string& block);

std::unique_ptr<NullStaticFeatureExtractor> parse_static(const std::vector<std::string>& lines,
                                                         const Address& base_address);

struct DynamicListing {
    std::unique_ptr<NullDynamicFeatureExtractor> extractor;
    std::map<std::uint64_t, Address> calls_by_id;  // fixture call ids are unique per test
};
DynamicListing parse_dynamic(const std::vector<std::string>& lines);

}  // namespace capa::dsl
