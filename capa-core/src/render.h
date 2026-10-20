// Renderers for capa-cpp.
//
// Ports capa/render/{result_document,json,default,vverbose}.py. Produces:
//   - the JSON ResultDocument (`-j`): capa's schema exactly, member for member -- the
//     contract a port of capa is held to ("same rules + same binary + same backend =
//     same JSON output"). capa-cpp's own additions (marked "capa-cpp extension" below)
//     appear only when a run asks for the feature they describe.
//   - the default capabilities table
//   - the vverbose match-tree view (`-vv`)
//
// Backend-neutral: the renderers see a `Doc` of already-resolved analysis metadata
// plus the raw `MatchResults`, never a concrete extractor. result_document.h builds a
// `Doc` from any static or dynamic extractor the way capa's loader does; backends with
// metadata of their own (the minidump regions) add to it.
#pragma once

#include <unordered_set>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "address.h"
#include "engine.h"
#include "feature_extractor.h"  // SampleHashes
#include "rules.h"

namespace capa::render {

enum class Flavor { Static, Dynamic };

// ---- dynamic layout (capa loader.compute_dynamic_layout) ----
struct DynCall {
    Address address;
    std::string name;
};
struct DynThread {
    Address address;
    std::vector<DynCall> matched_calls;
};
struct DynProcess {
    Address address;
    std::string name;
    std::vector<DynThread> matched_threads;
};

// ---- static layout (capa loader.compute_static_layout) ----
struct StaticFunction {
    Address address;
    std::vector<Address> matched_basic_blocks;
    // capa-cpp extension: the memory region this function was recovered from.
    // Empty for a single-image static run; set by the minidump backend.
    std::string region;
};

// capa-cpp extension: the memory regions a minidump run scanned. Empty otherwise,
// and omitted from the JSON when empty so a plain run's document is unchanged.
struct RegionInfo {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string name;  // "evil.dll" / "shellcode 0x1f0000"
    std::string kind;  // "module" | "private" | "mapped"
    std::string path;  // full NT path, for modules
    std::string arch;  // "i386" | "amd64"
};

// Everything the renderers need to know about an analysis, independent of backend.
// Exactly one of `dyn_layout` / `static_layout` is populated, per `flavor`.
struct Doc {
    Flavor flavor = Flavor::Dynamic;
    // meta.analysis.extractor: capa writes the extractor's class name, so a freeze file
    // reports "NullStaticFeatureExtractor" and the IDA backend "IdaFeatureExtractor".
    std::string extractor_name;
    SampleHashes hashes;
    std::string os = "unknown";
    std::string arch = "unknown";
    std::string format = "unknown";
    std::vector<std::string> rule_paths;  // meta.analysis.rules

    std::vector<DynProcess> dyn_layout;         // Flavor::Dynamic
    std::vector<StaticFunction> static_layout;  // Flavor::Static

    // Flavor::Static only: meta.analysis.base_address and .library_functions.
    Address base_address;
    std::vector<std::pair<Address, std::string>> library_functions;

    // Set when the backend deliberately did not compute the layout (`--matches-only`).
    // An empty layout otherwise means "nothing matched", which is a very different
    // statement, so the document says which of the two it is.
    bool layout_omitted = false;

    // The lean shape: `rules[*].matches` is a flat list of addresses rather than a list
    // of (address, evidence) pairs. Reported in the document as `meta.analysis
    // .matches_only`, because it is the one part of the schema this changes and a reader
    // must not have to infer it from the shape of the first element it happens to see.
    bool matches_only = false;

    // The third shape: `rules[*].matches` is a list of (address, leaf) pairs, where the
    // leaf is the one feature node that completed the match rather than the whole tree.
    // Wins over `matches_only`, which describes a shape this is not; the document says
    // `meta.analysis.match_evidence` instead, so exactly one of the two names the element
    // shape and neither means the default (address, tree) pair.
    bool match_evidence = false;

    // The mixed shape: a match whose tree `--max-match-trees` dropped is emitted as its
    // address alone, where the default emits (address, placeholder) and the placeholder
    // says only "no evidence was kept" -- which `meta.analysis` says once already.
    //
    // Opt-in, because it is the one shape where elements of a single array differ: a
    // reader that unpacks every element as a pair does not merely miss the point, it
    // fails. Reported as `meta.analysis.sparse_evidence`, and not reported when either
    // flag above is in force, since neither shape produces a placeholder to drop.
    bool sparse_evidence = false;

    std::size_t file_feature_count = 0;
    // per-process (dynamic) or per-function (static) feature counts, in walk order
    std::vector<std::pair<Address, std::size_t>> scope_feature_counts;
    // True when the counts above were taken after the ruleset feature filter ran, so a
    // reader can tell "this many features mattered" from "this many were extracted".
    bool feature_counts_filtered = false;

    std::vector<RegionInfo> regions;
};

// Context shared by all renderers.
struct RenderInput {
    const RuleSet& ruleset;
    const MatchResults& matches;
    const Doc& doc;
    std::string input_path;         // as passed on the CLI (for meta.sample.path)
    std::vector<std::string> argv;  // program arguments (meta.argv)

    // Rules named by a `match:` feature somewhere, gathered while every tree was still
    // whole. Empty means "not supplied", and the renderer falls back to walking
    // `matches` -- which is correct only when no tree was capped.
    const std::unordered_set<std::string>* subrule_matches = nullptr;
};

// Receives the document in order, in chunks of no particular size.
using JsonWriter = std::function<void(const char* data, std::size_t size)>;

// How the ResultDocument is encoded. The document is the same either way -- same members,
// same order, same values; MessagePack is roughly a third of the bytes and costs a
// consumer far less to parse, which matters when the consumer is another program rather
// than a person.
enum class DocFormat { Json, MsgPack };

// Writes the ResultDocument as JSON, streaming.
//
// The document is never materialized: `meta` is serialized on its own and each
// [address, match-tree] pair is serialized, written and dropped before the next one is
// built. Building the whole thing first and dumping it costs two complete copies of the
// output -- a `nlohmann::json` DOM, which is several times the size of the bytes it
// prints, and then a single contiguous `std::string` holding every one of them -- and on
// a large trace that is the largest allocation the program ever makes and the one that
// ends the run. The bytes are identical either way; see `render_json`.
void render_json_to(const RenderInput& in, const JsonWriter& write,
                    DocFormat format = DocFormat::Json);

// The same document, collected into a string. Convenience for callers with small
// documents and somewhere in memory to put them; a large run should stream.
std::string render_json(const RenderInput& in);

std::string render_default(const RenderInput& in);
std::string render_vverbose(const RenderInput& in);

}  // namespace capa::render
