// capa-cpp: C++ reimplementation of CAPA's TTD dynamic backend path.
//
// Usage:
//   capa-cpp <report.ttd.json> -r <rules-dir> [-j | -vv] [-o <out.json>]
//   capa-cpp <report.ttd.json> -r <rules-dir> --matches-only -o <out.json>
//   capa-cpp <report.ttd.json> --dump-features      (extractor parity dump)
//   capa-cpp --rules <rules-dir>                    (rule-load smoke test)
//
// -f ttd is accepted and ignored (TTD is the only supported format).

#define _CRT_SECURE_NO_WARNINGS  // std::getenv for the optional CAPA_CPP_TIMING probe

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <exception>
#include <fstream>
#include <map>
#include <new>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "capabilities.h"
#include "feature_filter.h"
#include "match_retention.h"
#include "memprobe.h"
#include "module_filter.h"
#include "minidump/mdmp.h"
#include "minidump/analysis.h"
#include "minidump/context.h"
#include "minidump/discover.h"
#include "minidump/process.h"
#include "static/extractor.h"
#include "render.h"
#include "rules.h"
#include "static/capabilities.h"
#include "static/manifest.h"
#include "static/trace_image.h"
#include "ttd/extractor.h"
#include "ttd/models.h"
#include "ttd/sax_reader.h"

#include <filesystem>
#include <map>
#include <set>

#if defined(_WIN32)
#include <fcntl.h>  // _O_BINARY, for handing MessagePack to stdout untranslated
#include <io.h>     // _setmode, _fileno
#endif

using nlohmann::json;
using namespace capa;

// Wall clock alone cannot tell you which stage runs the machine out of memory, and the
// biggest structures here are transient -- a JSON DOM freed as soon as the model is
// built, a match corpus copied and dropped -- so a current-usage reading between stages
// sees none of them. The peak counters do.
static std::string timing_memory_suffix() {
    const capa::MemUsage m = capa::process_memory();
    if (m.peak_working_set == 0) return {};
    char buf[96];
    int n = std::snprintf(buf, sizeof(buf), "  rss %6.0f MB  peak %6.0f MB",
                          m.working_set / 1048576.0, m.peak_working_set / 1048576.0);
    if (m.peak_commit != 0)
        std::snprintf(buf + n, sizeof(buf) - n, "  commit %6.0f MB", m.peak_commit / 1048576.0);
    return buf;
}

static bool load_report(const std::string& path, ttd::Report& out) {
    // Streamed straight into the model rather than decoded into a document first: the
    // DOM is the largest allocation in the program and every byte of it is discarded
    // once the model exists. See ttd/sax_reader.h.
    std::string error;
    if (!ttd::read_report_streaming(path, out, error)) {
        std::fprintf(stderr, "error: %s\n", error.c_str());
        return false;
    }
    return true;
}

// The document-decoding path, kept for --check-report-parse.
static bool load_report_dom(const std::string& path, ttd::Report& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "error: cannot open %s\n", path.c_str());
        return false;
    }
    json j;
    try {
        in >> j;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: failed to parse JSON: %s\n", e.what());
        return false;
    }
    // sanity: TTD report has top-level trace + processes
    if (!j.contains("trace") || !j.contains("processes"))
        std::fprintf(stderr, "warning: input does not look like a TTD report\n");
    out = ttd::Report::from_json(j);
    return true;
}

// Parses a report both ways and reports whether the two models agree.
//
// The streaming reader replaces the document one on every real run, so "it reads the same
// schema" has to be a thing that is checked against an actual report rather than argued
// from the shape of the code. Run it on any report and it either says they match or names
// the first field that does not.
static int check_report_parse(const std::string& path) {
    ttd::Report sax, dom;
    if (!load_report(path, sax)) return 1;
    if (!load_report_dom(path, dom)) return 1;

    auto fail = [&](const std::string& what) {
        std::fprintf(stderr, "MISMATCH: %s\n", what.c_str());
        return 1;
    };

    if (sax.version != dom.version) return fail("version");
    if (sax.trace.path != dom.trace.path || sax.trace.arch != dom.trace.arch ||
        sax.trace.os != dom.trace.os)
        return fail("trace");
    if (sax.sample.md5 != dom.sample.md5 || sax.sample.sha1 != dom.sample.sha1 ||
        sax.sample.sha256 != dom.sample.sha256 || sax.sample.name != dom.sample.name)
        return fail("sample");

    if (sax.file.strings != dom.file.strings) return fail("file.strings");
    if (sax.file.imports.size() != dom.file.imports.size()) return fail("file.imports size");
    for (std::size_t i = 0; i < sax.file.imports.size(); ++i)
        if (sax.file.imports[i].dll != dom.file.imports[i].dll ||
            sax.file.imports[i].name != dom.file.imports[i].name ||
            sax.file.imports[i].va != dom.file.imports[i].va)
            return fail("file.imports[" + std::to_string(i) + "]");
    if (sax.file.exports.size() != dom.file.exports.size()) return fail("file.exports size");
    for (std::size_t i = 0; i < sax.file.exports.size(); ++i)
        if (sax.file.exports[i].name != dom.file.exports[i].name ||
            sax.file.exports[i].va != dom.file.exports[i].va)
            return fail("file.exports[" + std::to_string(i) + "]");
    if (sax.file.sections.size() != dom.file.sections.size()) return fail("file.sections size");
    for (std::size_t i = 0; i < sax.file.sections.size(); ++i)
        if (sax.file.sections[i].name != dom.file.sections[i].name ||
            sax.file.sections[i].va != dom.file.sections[i].va)
            return fail("file.sections[" + std::to_string(i) + "]");

    if (sax.processes.size() != dom.processes.size()) return fail("processes size");
    std::size_t total_calls = 0;
    for (std::size_t p = 0; p < sax.processes.size(); ++p) {
        const ttd::Process& a = sax.processes[p];
        const ttd::Process& b = dom.processes[p];
        const std::string at = "processes[" + std::to_string(p) + "]";
        if (a.pid != b.pid || a.ppid != b.ppid || a.name != b.name) return fail(at);
        if (a.environ_strings != b.environ_strings) return fail(at + ".environ");
        if (a.threads != b.threads) return fail(at + ".threads");
        if (a.calls.size() != b.calls.size()) return fail(at + ".calls size");
        for (std::size_t c = 0; c < a.calls.size(); ++c) {
            const ttd::Call& x = a.calls[c];
            const ttd::Call& y = b.calls[c];
            // Compared by resolved text, not by pool index: the two parsers intern in
            // whatever order they meet the strings, so equal reports can and do carry
            // different indices for the same name. The index is an implementation
            // detail; the string is the model.
            if (x.tid != y.tid || x.seq != y.seq || x.position != y.position ||
                sax.str(x.module) != dom.str(y.module) || sax.str(x.api) != dom.str(y.api) ||
                x.ret != y.ret)
                return fail(at + ".calls[" + std::to_string(c) + "]");
            const std::span<const ttd::Arg> xa = sax.args_of(x);
            const std::span<const ttd::Arg> ya = dom.args_of(y);
            if (xa.size() != ya.size())
                return fail(at + ".calls[" + std::to_string(c) + "].args size");
            for (std::size_t g = 0; g < xa.size(); ++g) {
                const ttd::Arg& ax = xa[g];
                const ttd::Arg& ay = ya[g];
                // `i` is a value for Int/Bool and a pool index for Str, so it is only
                // comparable directly for the first two.
                const bool same = ax.kind == ay.kind &&
                                  (ax.kind == ttd::Arg::Kind::Str
                                       ? sax.arg_str(ax) == dom.arg_str(ay)
                                       : ax.i == ay.i);
                if (!same)
                    return fail(at + ".calls[" + std::to_string(c) + "].args[" +
                                std::to_string(g) + "]");
            }
        }
        total_calls += a.calls.size();
    }

    std::printf("streaming and document parses agree: %zu process(es), %zu call(s), "
                "%zu import(s), %zu export(s), %zu section(s), %zu string(s)\n",
                sax.processes.size(), total_calls, sax.file.imports.size(),
                sax.file.exports.size(), sax.file.sections.size(), sax.file.strings.size());
    return 0;
}

static int dump_features(const std::string& path) {
    ttd::Report report;
    if (!load_report(path, report)) return 1;
    ttd::TtdExtractor extractor(std::move(report));

    std::printf("== global ==\n");
    for (const auto& [feat, addr] : extractor.extract_global_features())
        std::printf("  %s @ %s\n", feat.str().c_str(), addr.repr().c_str());
    std::printf("== file ==\n");
    for (const auto& [feat, addr] : extractor.extract_file_features())
        std::printf("  %s @ %s\n", feat.str().c_str(), addr.repr().c_str());
    for (const auto& ph : extractor.get_processes()) {
        std::printf("== process %s %s ==\n", extractor.get_process_name(ph).c_str(),
                    ph.address.repr().c_str());
        for (const auto& [feat, addr] : extractor.extract_process_features(ph))
            std::printf("  %s @ %s\n", feat.str().c_str(), addr.repr().c_str());
        for (const auto& th : extractor.get_threads(ph)) {
            std::printf("  -- thread %s --\n", th.address.repr().c_str());
            const std::size_t calls = extractor.call_count(ph, th);
            for (std::size_t idx = 0; idx < calls; ++idx) {
                const ttd::CallHandle ch = extractor.call_at(ph, th, idx);
                std::printf("    call: %s\n", extractor.get_call_name(ph, th, ch).c_str());
                for (const auto& [feat, addr] : extractor.extract_call_features(ph, th, ch))
                    std::printf("      %s @ %s\n", feat.str().c_str(), addr.repr().c_str());
            }
        }
    }
    return 0;
}

static int load_rules_smoke(const std::string& dir) {
    try {
        RuleSet rs = RuleSet::load_from_directory(dir);
        std::printf("loaded %zu source rules (%zu total incl. subscope rules)\n",
                    rs.source_rule_count(), rs.size());
        std::printf("  call/span/thread/process/file rules: %zu/%zu/%zu/%zu/%zu\n",
                    rs.rules_for_scope(Scope::CALL).size(),
                    rs.rules_for_scope(Scope::SPAN_OF_CALLS).size(),
                    rs.rules_for_scope(Scope::THREAD).size(),
                    rs.rules_for_scope(Scope::PROCESS).size(),
                    rs.rules_for_scope(Scope::FILE).size());
        return 0;
    } catch (const InvalidRule& e) {
        std::fprintf(stderr, "error: %s\n", e.message.c_str());
        return 1;
    }
}

// ---- static path: scan the regions in a `--scan-code` manifest ----
//
// Snapshots are not read here: TraceImage maps them all, so a scan of one region can
// follow a call into another.

struct RegionHit {
    std::string rule;
    std::string namespace_;
    std::string position;
    std::uint64_t base = 0;
    std::string classification;
    bool has_offset = false;
    std::int64_t offset = 0;
    int scans_matched = 0;
    std::vector<std::uint64_t> vas;  // union of executable match VAs across the region's snapshots
    std::string scope;               // the rule's static scope; same for every snapshot
    // container VA -> the rule's own feature addresses there, unioned across snapshots
    std::map<std::uint64_t, std::vector<std::uint64_t>> feature_vas;
};

static int run_scan_code(const std::string& manifest_path, const std::string& rules_dir,
                         const std::string& dumps_dir_opt, const std::string& out_path, bool quiet,
                         bool feature_filter) {
    namespace fs = std::filesystem;

    std::ifstream mf(manifest_path, std::ios::binary);
    if (!mf) {
        std::fprintf(stderr, "error: manifest not found: %s\n", manifest_path.c_str());
        return 1;
    }
    json mj;
    try {
        mf >> mj;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: failed to parse manifest JSON: %s\n", e.what());
        return 1;
    }
    capa::stat::Manifest manifest = capa::stat::Manifest::from_json(mj);
    // the manifest's arch decides how the dumped bytes are decoded; getting it wrong
    // yields plausible-looking but entirely wrong instructions.
    const capa::stat::Arch arch = capa::stat::arch_from_string(manifest.arch);

    fs::path dumps_dir = dumps_dir_opt.empty() ? fs::path(manifest_path).parent_path()
                                               : fs::path(dumps_dir_opt);

    // The trace's export map, if the recorder wrote one. This is what lets a region's
    // runtime-resolved function-pointer table become `api:` features; without it the
    // ~500 rules written against `api:` can never fire on a reconstructed region.
    capa::stat::SymbolMap symbols = capa::stat::build_symbol_map(manifest);
    const capa::stat::SymbolMap* syms = symbols.empty() ? nullptr : &symbols;
    if (syms) {
        std::fprintf(stderr, "[ttd-static] %zu module(s), %zu export(s) for API resolution\n",
                     manifest.modules.size(), symbols.export_count());
    } else {
        std::fprintf(stderr,
                     "[ttd-static] manifest carries no module list; api: features are "
                     "unavailable (re-run the code scan to record one)\n");
    }

    // Every snapshot mapped at once, so a call out of the region being scanned into
    // another reconstructed region resolves instead of stopping at the boundary.
    capa::stat::TraceImage image(manifest, dumps_dir.string());
    for (const std::string& m : image.missing())
        std::fprintf(stderr, "[ttd-static] missing dump %s, skipping\n", m.c_str());
    std::fprintf(stderr, "[ttd-static] mapped %zu snapshot(s), %llu MB across %zu region(s)\n",
                 image.mapped_count(),
                 static_cast<unsigned long long>(image.mapped_bytes() / (1024 * 1024)),
                 manifest.regions.size());

    std::fprintf(stderr, "[ttd-static] loading rules from %s (arch: %s) ...\n", rules_dir.c_str(),
                 arch == capa::stat::Arch::X86 ? "x86" : "x64");
    RuleSet ruleset;
    try {
        ruleset = RuleSet::load_from_directory(rules_dir);
    } catch (const InvalidRule& e) {
        std::fprintf(stderr, "error: %s\n", e.message.c_str());
        return 1;
    }

    // Built from the loaded rules and handed to every snapshot scan. On the static path
    // this bounds two things at once: the strings carved out of a region (a module-sized
    // snapshot yields one `string:` feature per printable run, uncapped, once per
    // snapshot) and the per-operand number/offset features bubbling up from instruction
    // scope. See feature_filter.h.
    FeatureFilter filter = FeatureFilter::from_ruleset(ruleset);
    if (!feature_filter) filter.disable();
    std::fprintf(stderr, "[ttd-static] feature filter: %zu exact, %zu substring, %zu regex%s\n",
                 filter.exact_count(), filter.substring_count(), filter.regex_count(),
                 filter.enabled() ? "" : " (disabled)");

    std::vector<RegionHit> records;
    std::size_t matched_regions = 0;

    for (std::size_t ri = 0; ri < manifest.regions.size(); ++ri) {
        const capa::stat::Region& region = manifest.regions[ri];
        std::map<std::string, RegionHit> region_hits;

        for (std::size_t di = 0; di < region.dumps.size(); ++di) {
            const capa::stat::Dump& dump = region.dumps[di];
            const capa::stat::MappedFile* snap = image.snapshot(ri, di);
            if (snap == nullptr) continue;  // already reported by image.missing()
            std::fprintf(stderr,
                         "[ttd-static] scanning %s (region 0x%llx @ %s, %zu seed(s)) ...\n",
                         dump.file.c_str(), static_cast<unsigned long long>(region.base),
                         dump.position.c_str(), region.executed.size());

            // The address space as this snapshot saw it: every other region at its own
            // newest snapshot that had already happened.
            capa::stat::MemoryImage mem = image.at(ri, di);
            auto found = capa::stat::scan_dump(ruleset, mem, region.base, snap->size(),
                                               region.entries, region.executed, arch, syms,
                                               &filter);

            for (const auto& [rule_name, hit] : found) {
                auto it = region_hits.find(rule_name);
                if (it == region_hits.end()) {
                    RegionHit rh{rule_name,     hit.namespace_,
                                 dump.position,  region.base,
                                 region.classification, hit.has_offset,
                                 hit.offset,     1};
                    rh.vas = hit.vas;
                    rh.scope = hit.scope;
                    rh.feature_vas = hit.feature_vas;
                    region_hits.emplace(rule_name, std::move(rh));
                } else {
                    RegionHit& rh = it->second;
                    rh.scans_matched += 1;
                    rh.vas.insert(rh.vas.end(), hit.vas.begin(), hit.vas.end());  // union; dedup at emit
                    // Same union across snapshots as `vas`: a later snapshot decodes
                    // more of the region and can find the rule's features at addresses
                    // an earlier, half-written one could not reach.
                    for (const auto& [va, fvas] : hit.feature_vas) {
                        std::vector<std::uint64_t>& dst = rh.feature_vas[va];
                        dst.insert(dst.end(), fvas.begin(), fvas.end());
                    }
                    // keep the earliest position (and the offset that goes with it)
                    if (capa::stat::position_key(dump.position) < capa::stat::position_key(rh.position)) {
                        rh.position = dump.position;
                        rh.has_offset = hit.has_offset;
                        rh.offset = hit.offset;
                    }
                }
            }
        }

        if (!region_hits.empty()) ++matched_regions;

        if (!region_hits.empty() || !quiet) {
            std::printf("[!] Region 0x%llx (%zu snapshot(s)) [%s] - ",
                        static_cast<unsigned long long>(region.base), region.dumps.size(),
                        region.classification.c_str());
            if (region_hits.empty()) {
                std::printf("no matches.\n");
            } else {
                std::printf("%zu rule(s) matched:\n", region_hits.size());
                std::vector<const RegionHit*> sorted;
                for (const auto& [_, h] : region_hits) sorted.push_back(&h);
                std::sort(sorted.begin(), sorted.end(), [](const RegionHit* a, const RegionHit* b) {
                    return capa::stat::position_key(a->position) < capa::stat::position_key(b->position);
                });
                for (const RegionHit* h : sorted) {
                    std::string off = h->has_offset ? (" +0x" + [&] {
                        char b[32];
                        std::snprintf(b, sizeof(b), "%llx",
                                      static_cast<unsigned long long>(h->offset));
                        return std::string(b);
                    }()) : std::string();
                    // The scope is what the offset above is an offset *to*: on a
                    // function-scope rule it is a function entry, not the behaviour.
                    // Naming it here is the difference between a reader trusting the
                    // address and knowing what it addresses.
                    std::string scope = h->scope.empty() ? std::string() : " [" + h->scope + "]";
                    std::size_t fcount = 0;
                    for (const auto& [_, fvas] : h->feature_vas) fcount += fvas.size();
                    std::string feats;
                    if (fcount != 0) {
                        char b[64];
                        std::snprintf(b, sizeof(b), ", %zu feature site(s)", fcount);
                        feats = b;
                    }
                    std::printf("    [!] %s/%s%s (first seen %s, %d scan(s) matched%s)%s\n",
                                h->namespace_.c_str(), h->rule.c_str(), scope.c_str(),
                                h->position.c_str(), h->scans_matched, feats.c_str(), off.c_str());
                }
            }
        }

        for (const auto& [_, h] : region_hits) records.push_back(h);
    }

    std::fprintf(stderr, "\n[ttd-static] scanned %zu region(s), %zu matched at least one rule.%s\n",
                 manifest.regions.size(), matched_regions, timing_memory_suffix().c_str());

    if (!out_path.empty()) {
        json arr = json::array();
        for (const RegionHit& h : records) {
            capa::stat::CapabilityRecord rec;
            rec.rule = h.rule;
            rec.namespace_ = h.namespace_;
            rec.position = h.position;
            rec.base = h.base;
            rec.classification = h.classification;
            rec.has_offset = h.has_offset;
            rec.offset = h.offset;
            rec.scans_matched = h.scans_matched;
            // dedup + sort the unioned VAs; kind follows from whether any are executable
            std::vector<std::uint64_t> vs = h.vas;
            std::sort(vs.begin(), vs.end());
            vs.erase(std::unique(vs.begin(), vs.end()), vs.end());
            rec.vas = std::move(vs);
            rec.scope = h.scope;
            rec.feature_vas = h.feature_vas;
            for (auto& [_, fvas] : rec.feature_vas) {
                std::sort(fvas.begin(), fvas.end());
                fvas.erase(std::unique(fvas.begin(), fvas.end()), fvas.end());
            }
            rec.kind = rec.vas.empty() ? "data" : "insn";
            arr.push_back(rec.to_json());
        }
        std::ofstream of(out_path, std::ios::binary);
        if (!of) {
            std::fprintf(stderr, "error: cannot write %s\n", out_path.c_str());
            return 1;
        }
        of << arr.dump(2) << "\n";
        std::fprintf(stderr, "[ttd-static] wrote %zu capability record(s) to %s\n", records.size(),
                     out_path.c_str());
    }

    return 0;
}

// debug: dump every static feature for a single reconstructed dump (first region/dump,
// or the region/dump whose base matches --base). Grep-friendly: lines are prefixed with
// the enclosing function VA.
// This mode takes no ruleset, so it cannot build a FeatureFilter and lists every feature
// the extractor produces. A rule scan filters that down to what the rules can read, so the
// two no longer agree exactly -- and this is the more complete of the two, which is what
// makes it useful for working out why a rule did not fire.
static int dump_static_features(const std::string& manifest_path, const std::string& dumps_dir_opt,
                                std::uint64_t want_base) {
    namespace fs = std::filesystem;
    std::ifstream mf(manifest_path, std::ios::binary);
    if (!mf) {
        std::fprintf(stderr, "error: manifest not found: %s\n", manifest_path.c_str());
        return 1;
    }
    json mj;
    mf >> mj;
    capa::stat::Manifest manifest = capa::stat::Manifest::from_json(mj);
    const capa::stat::Arch arch = capa::stat::arch_from_string(manifest.arch);
    fs::path dumps_dir = dumps_dir_opt.empty() ? fs::path(manifest_path).parent_path()
                                               : fs::path(dumps_dir_opt);
    std::fprintf(stderr,
                 "[ttd-static] listing every extracted feature; a rule scan keeps only the ones "
                 "some rule can read\n");
    // Same inputs as the rule scan, so this stays an account of what that scan sees
    // rather than of a plainer analysis that happens to share a decoder -- the feature
    // filter aside, which needs rules this mode is not given.
    capa::stat::SymbolMap symbols = capa::stat::build_symbol_map(manifest);
    const capa::stat::SymbolMap* syms = symbols.empty() ? nullptr : &symbols;
    capa::stat::TraceImage image(manifest, dumps_dir.string());
    for (const std::string& m : image.missing())
        std::fprintf(stderr, "[ttd-static] missing dump %s, skipping\n", m.c_str());
    for (std::size_t ri = 0; ri < manifest.regions.size(); ++ri) {
        const capa::stat::Region& region = manifest.regions[ri];
        if (want_base && region.base != want_base) continue;
        if (region.dumps.empty()) continue;
        const capa::stat::MappedFile* snap = image.snapshot(ri, 0);
        if (snap == nullptr) continue;  // already reported by image.missing()
        capa::stat::MemoryImage mem = image.at(ri, 0);
        capa::stat::RegionScan scan(mem, region.base, snap->size(), region.entries,
                                    region.executed, arch, syms);
        const capa::stat::StaticExtractor& ex = scan.extractor();
        std::printf("== region 0x%llx (%s%s): %zu functions ==\n",
                    static_cast<unsigned long long>(region.base),
                    scan.arch() == capa::stat::Arch::X86 ? "x86" : "x64",
                    scan.is_pe() ? ", pe" : "", ex.functions().size());
        for (const auto& [feat, addr] : ex.extract_file_features())
            std::printf("0x%llx FILE %s @ %s\n", static_cast<unsigned long long>(region.base),
                        feat.str().c_str(), addr.repr().c_str());
        for (const auto& f : ex.functions()) {
            unsigned long long fva = static_cast<unsigned long long>(f.va);
            for (const auto& [feat, addr] : ex.extract_function_features(f))
                std::printf("0x%llx FUNC %s @ %s\n", fva, feat.str().c_str(), addr.repr().c_str());
            for (const auto& bb : f.blocks) {
                for (const auto& [feat, addr] : ex.extract_basic_block_features(f, bb))
                    std::printf("0x%llx BB %s @ %s\n", fva, feat.str().c_str(), addr.repr().c_str());
                for (const auto& insn : bb.insns)
                    for (const auto& [feat, addr] : ex.extract_insn_features(f, bb, insn))
                        std::printf("0x%llx INSN %s @ %s\n", fva, feat.str().c_str(),
                                    addr.repr().c_str());
            }
        }
        if (want_base) break;
    }
    return 0;
}


// ---- ResultDocument metadata for the dynamic/TTD path ----
//
// The renderers are backend-neutral, so each backend materializes its own Doc.
// This is capa's loader.compute_dynamic_layout plus the global-feature scan that
// used to live inside render.cpp.
//
// `with_layout` off skips the matched-call walk. The layout names every call any rule
// matched at, which on a large trace is most of the document's `meta` and the only part
// of it whose size follows the trace rather than the ruleset; `--matches-only` exists
// precisely for a consumer that reads addresses, so it does not pay for the names.
static render::Doc build_dynamic_doc(const ttd::TtdExtractor& extractor,
                                     const Capabilities& caps,
                                     const std::vector<std::string>& argv,
                                     bool with_layout = true) {
    render::Doc doc;
    doc.flavor = render::Flavor::Dynamic;
    doc.extractor_name = "TtdExtractor";

    const auto& r = extractor.report();
    doc.hashes = SampleHashes{r.sample.md5, r.sample.sha1, r.sample.sha256};

    for (const auto& [f, addr] : extractor.extract_global_features()) {
        if (f.type == FeatureType::OS) doc.os = f.s;
        else if (f.type == FeatureType::Arch) doc.arch = f.s;
        else if (f.type == FeatureType::Format) doc.format = f.s;
    }

    // the rules directory/directories, as given on the command line
    for (std::size_t k = 0; k + 1 < argv.size(); ++k)
        if (argv[k] == "-r" || argv[k] == "--rules-dir") doc.rule_paths.push_back(argv[k + 1]);

    doc.file_feature_count = caps.file_feature_count;
    doc.scope_feature_counts = caps.process_feature_counts;
    doc.feature_counts_filtered = caps.feature_counts_filtered;

    if (!with_layout) {
        doc.layout_omitted = true;
        doc.matches_only = true;
        return doc;
    }

    // layout: only the calls a rule matched at, and only the threads/processes that
    // still have any (capa drops the empty ones).
    //
    // Collected and sorted in bulk rather than inserted one at a time. This is a lookup
    // table, not a location set: the addresses arrive grouped by rule and so in no
    // particular order overall, and hundreds of thousands of positioned inserts into a
    // flat container is quadratic -- it cost five seconds here before it was done this
    // way round.
    std::vector<Address> matched;
    for (const auto& [name, results] : caps.matches)
        for (const auto& [addr, res] : results)
            if (addr.type == AddressType::CALL) matched.push_back(addr);
    std::sort(matched.begin(), matched.end());
    matched.erase(std::unique(matched.begin(), matched.end()), matched.end());

    for (const auto& ph : extractor.get_processes()) {
        render::DynProcess proc{ph.address, extractor.get_process_name(ph), {}};
        for (const auto& th : extractor.get_threads(ph)) {
            render::DynThread thread{th.address, {}};
            // Indexed rather than materialized: get_calls builds a handle per call in
            // the thread before the first one is looked at, and this walk keeps at most
            // the few that a rule matched at.
            const std::size_t calls = extractor.call_count(ph, th);
            for (std::size_t idx = 0; idx < calls; ++idx) {
                const ttd::CallHandle ch = extractor.call_at(ph, th, idx);
                if (!std::binary_search(matched.begin(), matched.end(), ch.address)) continue;
                thread.matched_calls.push_back({ch.address, extractor.get_call_name(ph, th, ch)});
            }
            if (!thread.matched_calls.empty()) proc.matched_threads.push_back(std::move(thread));
        }
        if (!proc.matched_threads.empty()) doc.dyn_layout.push_back(std::move(proc));
    }
    return doc;
}


// Strict integer option parsing: the WHOLE argument must be consumed, so a typo is an
// error rather than a silently truncated number.
//
// `hex_default` picks the base for a bare value. An address is documented and printed
// in hex, so `--region 7ff714980000` has to mean what it looks like; a size is
// naturally decimal, and accepts a K/M/G suffix. A leading `0x` always forces hex.
static std::optional<std::uint64_t> parse_u64(const std::string& s, bool hex_default) {
    if (s.empty()) return std::nullopt;
    std::string body = s;
    int base = hex_default ? 16 : 10;
    if (body.size() > 2 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X')) {
        body = body.substr(2);
        base = 16;
    }
    std::uint64_t mult = 1;
    if (!hex_default && !body.empty()) {
        switch (body.back()) {
            case 'k': case 'K': mult = 1024ull; break;
            case 'm': case 'M': mult = 1024ull * 1024; break;
            case 'g': case 'G': mult = 1024ull * 1024 * 1024; break;
            default: break;
        }
        if (mult != 1) body.pop_back();
    }
    if (body.empty()) return std::nullopt;
    // strtoull skips leading whitespace and accepts a sign, and the
    // whole-string-consumed test below cannot see either. `--max-region-size -1` would
    // otherwise parse as ULLONG_MAX and be accepted as "no limit at all" -- the exact
    // opposite of rejecting it.
    const char first = body.front();
    const bool digit = (first >= '0' && first <= '9') ||
                       (base == 16 && ((first >= 'a' && first <= 'f') ||
                                       (first >= 'A' && first <= 'F')));
    if (!digit) return std::nullopt;

    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(body.c_str(), &end, base);
    if (errno == ERANGE || end != body.c_str() + body.size()) return std::nullopt;
    if (mult != 1 && v > UINT64_MAX / mult) return std::nullopt;
    return static_cast<std::uint64_t>(v) * mult;
}

// ---- minidump path ----

// `--dump-info`: what the container actually contains. This is the first thing to
// reach for when a dump yields nothing, and it is diffable against WinDbg's `lm`,
// `!address` and `~*k`.
static int dump_minidump_info(const std::string& path) {
    using namespace capa::mdmp;
    Dump dump = Dump::open(path);

    std::printf("dump      %s\n", path.c_str());
    std::printf("cpu       %s\n", cpu_name(dump.cpu()));
    std::printf("pid       %u\n", dump.pid());
    std::printf("os        %u.x build %u\n", dump.os_major(), dump.os_build());
    std::printf("memory    %zu range(s), %.1f MiB dumped\n", dump.ranges().size(),
                static_cast<double>(dump.dumped_bytes()) / (1024.0 * 1024.0));
    if (auto ea = dump.exception_address())
        std::printf("exception at 0x%llx\n", static_cast<unsigned long long>(*ea));
    if (dump.truncated())
        std::printf("WARNING: this dump is truncated -- a stream runs past the end of the\n"
                    "         file. Analysing what was captured anyway.\n");
    else if (dump.looks_like_normal_dump())
        std::printf("WARNING: no module image memory present -- this looks like a\n"
                    "         MiniDumpNormal dump. Re-capture with `procdump -ma`.\n");

    std::printf("\n== %zu module(s) ==\n", dump.modules().size());
    for (const Module& m : dump.modules())
        std::printf("  0x%016llx  %8llu KiB  %s\n", static_cast<unsigned long long>(m.base),
                    static_cast<unsigned long long>(m.size / 1024), m.path.c_str());

    std::printf("\n== %zu thread(s) ==\n", dump.threads().size());
    for (const ThreadCtx& t : dump.threads())
        std::printf("  tid %-6u pc 0x%016llx  sp 0x%016llx  cs 0x%02x%s\n", t.tid,
                    static_cast<unsigned long long>(t.pc),
                    static_cast<unsigned long long>(t.sp), t.cs, t.wow64_32 ? "  (wow64)" : "");

    if (dump.meminfo().empty()) {
        std::printf("\n== no MemoryInfoList stream (region protections unknown) ==\n");
    } else {
        std::size_t exec = 0;
        for (const MemInfo& mi : dump.meminfo())
            if (mi.state == kMemCommit && region_is_exec(mi.protect, mi.alloc_protect, mi.type))
                ++exec;
        std::printf("\n== %zu region(s), %zu executable ==\n", dump.meminfo().size(), exec);
        for (const MemInfo& mi : dump.meminfo()) {
            if (mi.state != kMemCommit) continue;
            if (!region_is_exec(mi.protect, mi.alloc_protect, mi.type)) continue;
            const char* type = mi.type == kMemImage     ? "image"
                               : mi.type == kMemMapped  ? "mapped"
                               : mi.type == kMemPrivate ? "private"
                                                        : "?";
            std::printf("  0x%016llx  %8llu KiB  %-7s %s (alloc %s) @0x%llx\n",
                        static_cast<unsigned long long>(mi.base),
                        static_cast<unsigned long long>(mi.size / 1024), type,
                        protect_str(mi.protect).c_str(), protect_str(mi.alloc_protect).c_str(),
                        static_cast<unsigned long long>(mi.alloc_base));
        }
    }
    return 0;
}

// `--dump-modules`: the module list and how the shared filter classifies it.
//
// This exists to make the IDA plugin's system-module filter checkable. The plugin runs
// the same classify_modules() over the same module list read from the same .dmp, so
// what this prints is exactly what it will scan and what it will skip -- and unlike
// the plugin, this can be run without IDA open.
static int dump_minidump_modules(const std::string& path) {
    using namespace capa::mdmp;
    Dump dump = Dump::open(path);

    std::vector<capa::ModuleEntry> mods;
    for (const Module& m : dump.modules()) {
        if (m.size == 0) continue;
        mods.push_back({m.base, m.size, m.path, m.name});
    }
    // The main module is whichever the loader mapped first; a dump carries no
    // ImageBase of its own, so classify_modules falls back to the first .exe.
    capa::classify_modules(mods);

    std::size_t scanned = 0, skipped = 0;
    for (const capa::ModuleEntry& m : mods) {
        const bool skip = m.cls == capa::ModuleClass::SystemModule;
        skip ? ++skipped : ++scanned;
        std::printf("%-7s %-4s 0x%016llx  %8llu KiB  %s\n", capa::module_class_name(m.cls),
                    skip ? "skip" : "scan", static_cast<unsigned long long>(m.base),
                    static_cast<unsigned long long>(m.size / 1024), m.path.c_str());
    }
    std::printf("\n%zu module(s): %zu scanned, %zu skipped as system.\n", mods.size(), scanned,
                skipped);
    std::printf("Memory in no module at all is always scanned (IDA shows it as debugNNN).\n");

    // The same map the IDA plugin builds, and the reason it can resolve `api:` at all
    // on a database IDA parsed no import directory for. If these counts are zero the
    // plugin will only see the APIs IDA itself managed to name, which for a dump is
    // usually none -- and roughly half of capa's rules are written against `api:`.
    SymbolMap syms = build_symbol_map(dump);
    std::printf("\napi: resolution source: %zu export(s), %zu import slot(s) across all "
                "modules.\n",
                syms.export_count(), syms.import_count());
    return 0;
}

// `--dump-symbols`: the region table plus the export/import maps that drive API
// resolution. Diffable against `dumpbin /exports` and `dumpbin /imports` for the
// on-disk copy of any module in the dump.
static int dump_minidump_symbols(const std::string& path, bool verbose) {
    using namespace capa::mdmp;
    ProcessImage img = build_process_image(Dump::open(path));

    std::printf("%zu region(s), %zu export(s), %zu import slot(s)\n\n", img.regions.size(),
                img.symbols.export_count(), img.symbols.import_count());

    for (const Region& reg : img.regions) {
        std::printf("0x%016llx  %8llu KiB  %-14s %-5s %s\n",
                    static_cast<unsigned long long>(reg.base),
                    static_cast<unsigned long long>(reg.size / 1024),
                    region_kind_name(reg.kind),
                    reg.arch == capa::stat::Arch::X86 ? "x86" : "x64",
                    reg.path.empty() ? reg.name.c_str() : reg.path.c_str());
        if (!reg.pe) {
            if (reg.is_module()) std::printf("      (no readable PE header)\n");
            continue;
        }
        const PeImage& pe = *reg.pe;
        std::printf("      %zu section(s), %zu export(s), %zu import(s), %zu pdata start(s)"
                    " (+%zu fragment(s)), %zu tls\n",
                    pe.sections.size(), pe.exports.size(), pe.imports.size(),
                    pe.pdata_starts.size(), pe.pdata_fragments.size(), pe.tls_callbacks.size());
        if (pe.is_dotnet) std::printf("      .NET module: image holds IL, not machine code\n");
        if (pe.aslr_delta() != 0)
            std::printf("      relocated by 0x%llx from preferred base 0x%llx\n",
                        static_cast<unsigned long long>(pe.aslr_delta()),
                        static_cast<unsigned long long>(pe.preferred_base));
        if (!pe.pdb_path.empty()) std::printf("      pdb %s\n", pe.pdb_path.c_str());

        // Cross-check the IAT: read each slot's *value* and look it up in the
        // process-wide export map. This exercises the whole resolution chain the
        // insn-scope api: handler will use, and a slot whose stored pointer names a
        // different function than its import entry does is an IAT hook.
        std::size_t agree = 0, elsewhere = 0, offmodule = 0;
        std::vector<std::string> redirected;
        const int psize = pe.pe32plus ? 8 : 4;
        for (const PeImport& i : pe.imports) {
            auto p = img.memory.read_pointer(i.slot_va, psize);
            if (!p || *p == 0) {
                ++offmodule;
                continue;
            }
            const SymRef* s = img.symbols.export_at(*p);
            if (!s) {
                // Not an export entry point. Usually the target module's image was
                // not fully dumped, or the slot points at an internal stub.
                (img.region_at(*p) ? elsewhere : offmodule)++;
            } else if (img.symbols.symbol(*s) == i.symbol) {
                ++agree;
            } else {
                // A different export: nearly always a forwarder chain
                // (kernel32.HeapAlloc -> ntdll.RtlAllocateHeap), but an IAT hook
                // looks exactly like this too, which is why it is worth printing.
                redirected.push_back(i.dll + "." + i.symbol + " -> " +
                                     img.symbols.symbol(*s));
            }
        }
        if (!pe.imports.empty())
            std::printf("      IAT: %zu/%zu named export, %zu forwarded/redirected, "
                        "%zu in-module non-export, %zu unmapped\n",
                        agree, pe.imports.size(), redirected.size(), elsewhere, offmodule);
        for (std::size_t k = 0; k < redirected.size() && k < 8; ++k)
            std::printf("        redirected: %s\n", redirected[k].c_str());

        if (!verbose) continue;
        for (const PeSection& s : pe.sections)
            std::printf("        section %-10s 0x%llx (%u bytes)\n", s.name.c_str(),
                        static_cast<unsigned long long>(s.va), s.vsize);
        for (const PeExport& e : pe.exports) {
            if (e.forwarded.empty())
                std::printf("        export  0x%llx  %s\n",
                            static_cast<unsigned long long>(e.va), e.name.c_str());
            else
                std::printf("        export  %-18s %s -> %s\n", "(forwarded)", e.name.c_str(),
                            e.forwarded.c_str());
        }
        for (const PeImport& i : pe.imports)
            std::printf("        import  slot 0x%llx  %s.%s%s\n",
                        static_cast<unsigned long long>(i.slot_va), i.dll.c_str(),
                        i.symbol.c_str(), i.delay_load ? "  (delay)" : "");
    }
    return 0;
}

enum class OutputMode { Default, Json, VVerbose };

// Writes the chosen rendering to `out_path`, or to stdout when it is empty.
//
// JSON is streamed rather than rendered into a string first. On a large trace the
// document is the biggest thing the program ever holds -- bigger than the report, the
// rules and the matches together -- and holding it whole, twice, is what used to end the
// run. The text renderers produce a human-sized page and stay as they are.
static int emit(const render::RenderInput& in, OutputMode mode, const std::string& out_path,
                render::DocFormat format) {
    std::FILE* fp = stdout;
    if (!out_path.empty()) {
        fp = std::fopen(out_path.c_str(), "wb");
        if (fp == nullptr) {
            std::fprintf(stderr, "error: cannot write %s\n", out_path.c_str());
            return 1;
        }
    } else if (format == render::DocFormat::MsgPack) {
        // stdout is a text stream by default on Windows, which turns every 0x0A byte
        // into 0x0D 0x0A. Harmless for JSON, which has no bare newlines inside it, and
        // fatal for MessagePack, where 0x0A is just a byte like any other.
#if defined(_WIN32)
        std::fflush(stdout);
        if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
            std::fprintf(stderr, "error: cannot switch stdout to binary for MessagePack\n");
            return 1;
        }
#endif
    }

    bool ok = true;
    if (mode == OutputMode::Json) {
        // A short write here means a full disk or a closed pipe. Noting it and carrying
        // on would produce a truncated document that still parses down to the cut --
        // silently half an answer -- so the first one is remembered and reported.
        render::render_json_to(
            in,
            [&](const char* data, std::size_t size) {
                if (ok && std::fwrite(data, 1, size, fp) != size) ok = false;
            },
            format);
        // A trailing newline is a courtesy to whoever cats the file; MessagePack is not
        // read that way and a stray byte after the document is one a strict parser can
        // object to.
        if (ok && format == render::DocFormat::Json) ok = std::fputc('\n', fp) != EOF;
    } else {
        const std::string out = mode == OutputMode::VVerbose ? render::render_vverbose(in)
                                                             : render::render_default(in);
        ok = std::fwrite(out.data(), 1, out.size(), fp) == out.size();
        if (ok && !out.empty() && out.back() != '\n') ok = std::fputc('\n', fp) != EOF;
    }

    if (fp != stdout) {
        if (std::fclose(fp) != 0) ok = false;
    } else if (std::fflush(fp) != 0) {
        ok = false;
    }

    if (!ok) {
        std::fprintf(stderr, "error: failed to write %s\n",
                     out_path.empty() ? "output" : out_path.c_str());
        return 1;
    }
    return 0;
}

// The minidump analysis path: assemble the dump, pick the regions worth scanning,
// run capa's static engine over each, and render the merged result.
static int run_minidump(const std::string& path, const std::string& rules_dir, OutputMode mode,
                        const capa::mdmp::ScanOptions& sopts, bool dump_feats,
                        const std::vector<std::string>& argv) {
    using namespace capa::mdmp;
    const bool timing = std::getenv("CAPA_CPP_TIMING") != nullptr;
    auto t0 = std::chrono::steady_clock::now();
    auto lap = [&](const char* what) {
        if (!timing) return;
        auto now = std::chrono::steady_clock::now();
        std::fprintf(stderr, "[timing] %-22s %8.1f ms%s\n", what,
                     std::chrono::duration<double, std::milli>(now - t0).count(),
                     timing_memory_suffix().c_str());
        t0 = now;
    };

    Dump dump = Dump::open(path);
    if (dump.truncated())
        std::fprintf(stderr, "warning: %s is truncated; analysing what was captured\n",
                     path.c_str());
    if (dump.looks_like_normal_dump()) {
        std::fprintf(stderr,
                     "error: %s carries no module image memory (%.1f MiB over %zu range(s)).\n"
                     "       This looks like a MiniDumpNormal capture, which holds thread\n"
                     "       stacks but no code. Re-capture with `procdump -ma <pid>` or\n"
                     "       MiniDumpWithFullMemory.\n",
                     path.c_str(), static_cast<double>(dump.dumped_bytes()) / (1024.0 * 1024.0),
                     dump.ranges().size());
        return 1;
    }
    ProcessImage img = build_process_image(std::move(dump));
    lap("load+assemble dump");

    if (sopts.progress)
        std::fprintf(stderr, "[capa] %zu region(s), %zu export(s), %zu import slot(s)\n",
                     img.regions.size(), img.symbols.export_count(),
                     img.symbols.import_count());

    // debug: every feature of every selected region, without loading rules
    if (dump_feats) {
        const std::vector<std::uint64_t> stack_words =
            capa::mdmp::collect_stack_words(img.memory, img.dump.threads(), img.native_arch);
        for (const Region* r : select_regions(img, sopts)) {
            if (r->size > sopts.max_region_size) {
                std::fprintf(stderr, "[capa] skipping %s: exceeds --max-region-size\n",
                             r->name.c_str());
                continue;
            }
            // The same arch decision the real scan makes. This mode exists to show
            // what the scan sees, so a --region-arch that applied to one and not the
            // other would defeat the point -- a headerless 32-bit region would be
            // dumped as x64 nonsense while the scan read it correctly.
            const capa::stat::Arch arch =
                sopts.force_arch && !r->pe ? *sopts.force_arch : r->arch;

            DiscoverOptions dopts;
            dopts.linear_sweep = sopts.linear_sweep;
            dopts.stack_words = &stack_words;
            dopts.use_prologue_scan =
                !r->pe || r->pe->pdata_starts.empty() || arch == capa::stat::Arch::X86;
            dopts.sweep_seeds_are_entries = dopts.use_prologue_scan;
            Seeds seeds =
                discover(img.memory, r->base, r->size, arch, r->pe, img.dump.threads(), dopts);
            RegionContext ctx(img, *r);
            capa::stat::StaticExtractor ex(img.memory, r->base, r->size,
                                           std::move(seeds.entries),
                                           std::move(seeds.executed), arch, &ctx);
            std::printf("== region 0x%llx %s (%s): %zu function(s) ==\n",
                        static_cast<unsigned long long>(r->base), r->name.c_str(),
                        region_kind_name(r->kind), ex.functions().size());
            for (const auto& [feat, addr] : ex.extract_global_features())
                std::printf("GLOBAL %s @ %s\n", feat.str().c_str(), addr.repr().c_str());
            for (const auto& [feat, addr] : ex.extract_file_features())
                std::printf("FILE %s @ %s\n", feat.str().c_str(), addr.repr().c_str());
            for (const auto& f : ex.functions()) {
                unsigned long long fva = static_cast<unsigned long long>(f.va);
                for (const auto& [feat, addr] : ex.extract_function_features(f))
                    std::printf("0x%llx FUNC %s @ %s\n", fva, feat.str().c_str(),
                                addr.repr().c_str());
                for (const auto& bb : f.blocks) {
                    for (const auto& [feat, addr] : ex.extract_basic_block_features(f, bb))
                        std::printf("0x%llx BB %s @ %s\n", fva, feat.str().c_str(),
                                    addr.repr().c_str());
                    for (const auto& insn : bb.insns)
                        for (const auto& [feat, addr] : ex.extract_insn_features(f, bb, insn))
                            std::printf("0x%llx INSN %s @ %s\n", fva, feat.str().c_str(),
                                        addr.repr().c_str());
                }
            }
        }
        return 0;
    }

    if (rules_dir.empty()) {
        std::fprintf(stderr, "error: -r <rules-dir> is required for matching\n");
        return 2;
    }
    RuleSet ruleset;
    try {
        ruleset = RuleSet::load_from_directory(rules_dir);
    } catch (const InvalidRule& e) {
        std::fprintf(stderr, "error: %s\n", e.message.c_str());
        return 1;
    }
    lap("load+index rules");

    MinidumpCapabilities caps = scan(ruleset, img, sopts);
    lap("discover+match");

    if (caps.scanned_regions == 0) {
        std::fprintf(stderr,
                     "error: no region was scanned. The dump may carry no non-system code;\n"
                     "       try --all-modules, or --region <hex> to force one.\n");
        return 1;
    }

    render::Doc doc = build_doc(img, caps, argv);
    render::RenderInput in{ruleset, caps.matches, doc, path, argv};
    const int rc = emit(in, mode, /*out_path=*/"", render::DocFormat::Json);
    lap("render");
    return rc;
}

static int run(const std::string& report_path, const std::string& rules_dir, OutputMode mode,
               const std::vector<std::string>& argv, bool feature_filter,
               std::size_t max_match_trees, bool matches_only, bool match_evidence,
               bool sparse_evidence, const std::string& out_path,
               render::DocFormat format, bool top_level_calls) {
    const bool timing = std::getenv("CAPA_CPP_TIMING") != nullptr;
    auto t0 = std::chrono::steady_clock::now();
    auto lap = [&](const char* what) {
        if (!timing) return;
        auto now = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(now - t0).count();
        std::fprintf(stderr, "[timing] %-22s %8.1f ms%s\n", what, ms,
                     timing_memory_suffix().c_str());
        t0 = now;
    };

    ttd::Report report;
    if (!load_report(report_path, report)) return 1;
    lap("load+parse json");
    ttd::TtdExtractor extractor(std::move(report));
    lap("build extractor");

    RuleSet ruleset;
    try {
        ruleset = RuleSet::load_from_directory(rules_dir);
    } catch (const InvalidRule& e) {
        std::fprintf(stderr, "error: %s\n", e.message.c_str());
        return 1;
    }
    lap("load+index rules");

    // Built from the loaded rules, so it knows exactly which extracted features anything
    // can ever look at. Without it the thread- and process-scope feature sets grow one
    // entry per distinct call argument in the trace; see feature_filter.h.
    FeatureFilter filter = FeatureFilter::from_ruleset(ruleset);
    if (!feature_filter) filter.disable();
    if (timing)
        std::fprintf(stderr, "[timing] feature filter: %zu exact, %zu substring, %zu regex%s\n",
                     filter.exact_count(), filter.substring_count(), filter.regex_count(),
                     filter.enabled() ? "" : " (disabled)");
    lap("build feature filter");

    Capabilities caps =
        find_dynamic_capabilities(ruleset, extractor, filter, max_match_trees, match_evidence,
                                  top_level_calls);
    lap("match");
    if (timing)
        std::fprintf(stderr,
                     "[timing] largest scope: %zu feature(s), %zu location(s)%s\n",
                     caps.peak_scope_features, caps.peak_scope_locations,
                     caps.feature_counts_filtered ? "" : " (filter disabled)");
    // The mode and the tree cap are separate facts, and reporting them as one lied when
    // they disagreed: `--matches-only --max-match-trees 2` does keep two trees per rule,
    // and a note claiming the document has none contradicted the document itself.
    if (matches_only)
        std::fprintf(stderr, "note: --matches-only: no call layout in this document\n");

    if (matches_only && max_match_trees == 0) {
        // Said plainly rather than through the per-rule count below: here every match in
        // the run is a stub, so "N matches lost their evidence" tells the reader nothing
        // they did not ask for.
        std::fprintf(stderr,
                     match_evidence
                         ? "note: no evidence trees kept; every match carries its address, "
                           "its rule's metadata and one evidence leaf\n"
                         : "note: no evidence trees kept; every match carries its address and "
                           "its rule's metadata only\n");
    } else if (!caps.truncated_matches.empty()) {
        // Counted from the finished result, not from the retention tally: matches are
        // merged call-to-thread-to-process, so a tally incremented at each level counts
        // the same match three times and reports a number no reader can reconcile with
        // the match counts beside it.
        std::size_t stubs = 0;
        for (const auto& [name, results] : caps.matches)
            for (const auto& [addr, res] : results)
                if (is_truncated_match(res)) ++stubs;
        std::fprintf(stderr,
                     "note: kept %zu match tree(s) per rule; %zu further match(es) across "
                     "%zu rule(s) are reported without their evidence tree "
                     "(--max-match-trees 0 keeps every one)\n",
                     max_match_trees, stubs, caps.truncated_matches.size());
    }

    render::Doc doc = build_dynamic_doc(extractor, caps, argv, /*with_layout=*/!matches_only);
    doc.match_evidence = match_evidence;
    doc.sparse_evidence = sparse_evidence;
    lap("build document");
    render::RenderInput in{ruleset,     caps.matches, doc, report_path, argv,
                           &caps.subrule_matches};
    const int rc = emit(in, mode, out_path, format);
    // The phase that used to have no lap of its own, and the one that ended the run:
    // its cost had to be read as "total minus the other four".
    lap("render");
    return rc;
}

static int run_main(std::vector<std::string> args);

// What to do about it. Printed under either of the two ways running out of memory
// arrives, which say something different about the failure and so say it separately.
//
// The first line is not advice but a fact the exit code alone does not carry: the
// renderer streams, so a failure part-way through leaves a document that is cut off
// rather than absent, and a reader who only checks that the file exists would be reading
// half an answer.
static void report_out_of_memory_advice() {
    std::fputs("       Any output already written is truncated, not a complete document.\n"
               "       For a large TTD report: --matches-only writes just the rule metadata\n"
               "       and match addresses, which is what a caller reading positions needs;\n"
               "       --max-match-trees <n> keeps fewer evidence trees.\n"
               "       For a minidump: narrow the scan with --module <name> or --region <hex>,\n"
               "       or lower --max-region-size.\n",
               stderr);
}

// The last line of defence, and the reason the failure this file's callers see is a
// sentence rather than a hex code.
//
// The try/catch in main() only sees an exception that unwinds to it. Under memory
// exhaustion one often does not: a throw out of a noexcept function, or a second throw
// while the first is propagating -- both of which an allocation failure deep in a
// container operation can produce -- go straight to std::terminate, and MSVC's terminate
// calls abort(), which __fastfail()s. The process then disappears with
// STATUS_STACK_BUFFER_OVERRUN (0xC0000409), no message, and nothing flushed:
// indistinguishable, to whoever is running this, from memory corruption in the parser.
//
// This handler runs before that. It allocates nothing (the in-flight exception is
// inspected by type, and every string it prints is a literal) because the condition that
// brought it here is usually that allocation no longer works, and it leaves by _exit so
// no further destructor or handler can turn a diagnosed failure back into a fastfail.
[[noreturn]] static void on_terminate() {
    std::fflush(stdout);
    try {
        if (std::exception_ptr in_flight = std::current_exception())
            std::rethrow_exception(in_flight);
        std::fputs("error: terminated with no exception in flight.\n", stderr);
    } catch (const std::bad_alloc&) {
        // Distinct from the message main() prints for the same exception: this one could
        // not be unwound, so nothing after the failure ran -- no file was closed, no
        // buffer beyond the one flushed above was emptied.
        std::fputs("error: out of memory, unrecoverably -- the allocation failed where it\n"
                   "       could not be unwound.\n", stderr);
        report_out_of_memory_advice();
    } catch (const std::exception& e) {
        // e.what() is the exception's own storage, not something built here.
        std::fputs("error: fatal: ", stderr);
        std::fputs(e.what(), stderr);
        std::fputc('\n', stderr);
    } catch (...) {
        std::fputs("error: fatal: unknown exception.\n", stderr);
    }
    std::fflush(stderr);
    std::_Exit(1);
}

// Nothing below should ever leave an exception unhandled; see on_terminate() for what
// happens to the ones that cannot be caught here.
int main(int argc, char** argv) {
    std::set_terminate(&on_terminate);
#if defined(_MSC_VER)
    // Without this a stray abort() -- from the CRT, or from a failed assertion in a
    // dependency -- takes the same silent __fastfail exit that terminate used to.
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    try {
        return run_main(std::vector<std::string>(argv + 1, argv + argc));
    } catch (const std::bad_alloc&) {
        std::fputs("error: out of memory.\n", stderr);
        report_out_of_memory_advice();
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}

static int run_main(std::vector<std::string> args) {
    if (args.empty()) {
        std::fprintf(stderr,
                     "usage: capa-cpp <report.ttd.json> -r <rules-dir> [-j | -vv]\n"
                     "                [--matches-only] [--match-evidence] [--sparse-evidence]\n"
                     "                [--max-match-trees <n>] [-o <out.json>] [--top-level-calls]\n"
                     "       capa-cpp <report.ttd.json> --dump-features\n"
                     "       capa-cpp --scan-code-manifest <manifest.json> -r <rules-dir>\n"
                     "                [--dumps-dir <dir>] [-o <out.json>] [--quiet]\n"
                     "       capa-cpp --rules <rules-dir>\n");
        return 2;
    }

    if (args[0] == "--rules") {
        if (args.size() < 2) {
            std::fprintf(stderr, "error: --rules requires a directory\n");
            return 2;
        }
        return load_rules_smoke(args[1]);
    }

    // debug: dump every static feature for one reconstructed dump.
    if (args[0] == "--scan-dump-features") {
        if (args.size() < 2) {
            std::fprintf(stderr, "error: --scan-dump-features requires a manifest\n");
            return 2;
        }
        std::string manifest_path = args[1], dumps_dir;
        std::uint64_t want_base = 0;
        for (std::size_t k = 2; k < args.size(); ++k) {
            if (args[k] == "--dumps-dir" && k + 1 < args.size())
                dumps_dir = args[++k];
            else if (args[k] == "--base" && k + 1 < args.size())
                want_base = std::strtoull(args[++k].c_str(), nullptr, 0);
        }
        return dump_static_features(manifest_path, dumps_dir, want_base);
    }

    // minidump path. Detection is by magic, not extension: a dump is as likely to
    // be called `crash.bin` as `crash.dmp`.
    {
        std::string dmp;
        for (const std::string& a : args)
            if (!a.empty() && a[0] != '-' && capa::mdmp::looks_like_minidump(a)) {
                dmp = a;
                break;
            }
        if (!dmp.empty()) {
            try {
                auto has = [&](const char* f) {
                    return std::find(args.begin(), args.end(), f) != args.end();
                };
                // Returns "" for a flag that is absent, and sets `missing` for one
                // that is present but has no value after it. Without that second case
                // `capa-cpp dump.dmp --region` -- the value simply forgotten -- reads
                // as "no --region at all" and quietly scans everything.
                bool missing_value = false;
                const char* missing_flag = nullptr;
                auto val = [&](const char* f) -> std::string {
                    auto it = std::find(args.begin(), args.end(), f);
                    if (it == args.end()) return {};
                    // Any '-'-prefixed token, not just '--': `--region -r rules` must
                    // report the missing value rather than swallow the next flag.
                    // None of these options ever takes a negative value.
                    if (it + 1 == args.end() || (!(it + 1)->empty() && (it + 1)->front() == '-')) {
                        missing_value = true;
                        missing_flag = f;
                        return {};
                    }
                    return *(it + 1);
                };
                auto check_missing = [&]() {
                    if (!missing_value) return false;
                    std::fprintf(stderr, "error: %s needs a value\n", missing_flag);
                    return true;
                };
                if (has("--dump-info")) return dump_minidump_info(dmp);
                if (has("--dump-modules")) return dump_minidump_modules(dmp);
                if (has("--dump-symbols")) return dump_minidump_symbols(dmp, has("-v"));

                capa::mdmp::ScanOptions sopts;
                sopts.all_modules = has("--all-modules");
                sopts.linear_sweep = has("--linear-sweep");
                sopts.progress = !has("--quiet");
                sopts.feature_filter = !has("--no-feature-filter");
                sopts.only_module = val("--module");
                // Both of these are parsed strictly and rejected on the slightest
                // doubt. strtoull with base 0 read `7ff714980000` -- a base copied
                // straight out of --dump-info -- as the decimal 7, matched no region,
                // and produced an error telling the user to pass --region, which is
                // what they had just done. A wrong number here is worse than no
                // number: it looks like the dump has nothing in it.
                if (std::string reg = val("--region"); !reg.empty()) {
                    std::optional<std::uint64_t> v = parse_u64(reg, /*hex_default=*/true);
                    if (!v) {
                        std::fprintf(stderr, "error: --region %s is not a hex address\n",
                                     reg.c_str());
                        return 2;
                    }
                    sopts.only_region = *v;
                }
                // arch_from_string maps anything it does not recognise to x64, so a
                // typo would silently pick 64-bit decoding for a region the user was
                // explicitly telling us is 32-bit. Accept only the spellings it
                // actually understands.
                if (std::string a = val("--region-arch"); !a.empty()) {
                    const std::string lower_a = capa::stat::arch_from_string(a) ==
                                                        capa::stat::Arch::X86
                                                    ? a
                                                    : std::string();
                    if (lower_a.empty() && a != "x64" && a != "amd64" && a != "64" &&
                        a != "X64" && a != "AMD64") {
                        std::fprintf(stderr,
                                     "error: --region-arch %s is not an architecture "
                                     "(x86 / i386 / 32, or x64 / amd64 / 64)\n",
                                     a.c_str());
                        return 2;
                    }
                    sopts.force_arch = capa::stat::arch_from_string(a);
                }
                if (std::string m = val("--max-region-size"); !m.empty()) {
                    std::optional<std::uint64_t> v = parse_u64(m, /*hex_default=*/false);
                    if (!v || *v == 0) {
                        std::fprintf(stderr,
                                     "error: --max-region-size %s is not a byte count "
                                     "(decimal, 0x-prefixed hex, or a K/M/G suffix)\n",
                                     m.c_str());
                        return 2;
                    }
                    sopts.max_region_size = *v;
                }
                if (check_missing()) return 2;

                std::string rules_dir;
                for (std::size_t k = 0; k + 1 < args.size(); ++k)
                    if (args[k] == "-r" || args[k] == "--rules-dir") rules_dir = args[k + 1];

                OutputMode mode = OutputMode::Default;
                if (has("-j") || has("--json")) mode = OutputMode::Json;
                else if (has("-vv") || has("--vverbose")) mode = OutputMode::VVerbose;

                return run_minidump(dmp, rules_dir, mode, sopts, has("--dump-features"), args);
            } catch (const capa::mdmp::MdmpError& e) {
                std::fprintf(stderr, "error: %s\n", e.what());
                return 1;
            }
        }
    }

    // static path: scan a --scan-code manifest's reconstructed regions.
    {
        std::string manifest_path, rules_dir, dumps_dir, out_path;
        bool quiet = false, is_scan = false, feature_filter = true;
        for (std::size_t k = 0; k < args.size(); ++k) {
            const std::string& a = args[k];
            if (a == "--scan-code-manifest" && k + 1 < args.size()) {
                is_scan = true;
                manifest_path = args[++k];
            } else if ((a == "-r" || a == "--rules-dir") && k + 1 < args.size()) {
                rules_dir = args[++k];
            } else if (a == "--dumps-dir" && k + 1 < args.size()) {
                dumps_dir = args[++k];
            } else if ((a == "-o" || a == "--output") && k + 1 < args.size()) {
                out_path = args[++k];
            } else if (a == "--quiet") {
                quiet = true;
            } else if (a == "--no-feature-filter") {
                feature_filter = false;
            }
        }
        if (is_scan) {
            if (rules_dir.empty()) {
                std::fprintf(stderr, "error: --scan-code-manifest requires -r <rules-dir>\n");
                return 2;
            }
            return run_scan_code(manifest_path, rules_dir, dumps_dir, out_path, quiet,
                                 feature_filter);
        }
    }

    std::string report_path, rules_dir, out_path;
    OutputMode mode = OutputMode::Default;
    bool dump = false;
    bool check_parse = false;
    // The lean dynamic output: every rule's meta and every match's address, and nothing
    // else. See the `--matches-only` block below for what it turns off and why.
    bool matches_only = false;
    // One leaf per match instead of a tree: which feature completed it, the string it
    // captured, and where that feature was. Composes with --matches-only, which is how it
    // is meant to be used -- lean, plus the one thing a reader cannot work out for itself.
    bool match_evidence = false;
    bool top_level_calls = false;
    // Emit a match whose tree was capped as its address alone, rather than as a pair whose
    // second element is a placeholder saying the tree is not there. Opt-in: it is the one
    // shape whose elements are not all the same, and a reader that unpacks each of them as
    // a pair fails on the first bare address.
    bool sparse_evidence = false;
    // MessagePack rather than JSON: the same document, about a third of the bytes, and
    // much cheaper for a program to parse. An encoding, not a mode -- it composes with
    // everything else.
    render::DocFormat format = render::DocFormat::Json;
    // Escape hatch for parity runs: with the filter off, the feature counts and memory
    // profile are what they were before it existed. The matches are the same either way,
    // which is the property this flag exists to let you check.
    bool feature_filter = true;
    // Whole evidence trees kept per rule. A rule that matches hundreds of thousands of
    // times contributes hundreds of thousands of recursive Results, which is most of what
    // the matcher holds and more than -j can serialize; nothing reads past the first few.
    // 0 on the command line keeps all of them.
    std::size_t max_match_trees = 256;
    bool trees_given = false;
    // Whether a renderer was actually asked for. `--matches-only` overrides the choice,
    // and there is nothing to report when the thing overridden was only the default.
    bool mode_given = false;
    for (std::size_t k = 0; k < args.size(); ++k) {
        const std::string& a = args[k];
        if ((a == "-r" || a == "--rules-dir") && k + 1 < args.size()) {
            rules_dir = args[++k];
        } else if (a == "-f" && k + 1 < args.size()) {
            ++k;  // format flag accepted and ignored (only ttd supported)
        } else if ((a == "-o" || a == "--output") && k + 1 < args.size()) {
            // Named explicitly so the value cannot be mistaken for the report path, and
            // so a big document never has to survive a pipe.
            out_path = args[++k];
        } else if (a == "-j" || a == "--json") {
            mode = OutputMode::Json;
            mode_given = true;
        } else if (a == "-vv" || a == "--vverbose") {
            mode = OutputMode::VVerbose;
            mode_given = true;
        } else if (a == "--matches-only") {
            matches_only = true;
        } else if (a == "--match-evidence") {
            match_evidence = true;
        } else if (a == "--top-level-calls") {
            top_level_calls = true;
        } else if (a == "--sparse-evidence") {
            sparse_evidence = true;
        } else if (a == "--msgpack") {
            format = render::DocFormat::MsgPack;
        } else if (a == "--dump-features") {
            dump = true;
        } else if (a == "--check-report-parse") {
            check_parse = true;
        } else if (a == "--no-feature-filter") {
            feature_filter = false;
        } else if (a == "--max-match-trees" && k + 1 < args.size()) {
            // Rejected rather than half-read, the same way the other byte/count flags
            // are: a typo here silently changes how much evidence the run keeps.
            std::optional<std::uint64_t> parsed = parse_u64(args[++k], false);
            if (!parsed) {
                std::fprintf(stderr, "error: --max-match-trees expects a count, got %s\n",
                             args[k].c_str());
                return 2;
            }
            // 0 reads as "no limit" on the command line; the matcher counts trees, where
            // 0 means none. See MatchRetention::kKeepAll.
            max_match_trees =
                *parsed == 0 ? MatchRetention::kKeepAll : static_cast<std::size_t>(*parsed);
            trees_given = true;
        } else if (report_path.empty() && !a.empty() && a[0] != '-') {
            report_path = a;
        } else {
            // Refused rather than skipped: a flag this build predates would otherwise change
            // nothing and say nothing, and the caller would read the result as if it had.
            std::fprintf(stderr, "error: unknown option, missing value, or extra argument: %s\n",
                         a.c_str());
            return 2;
        }
    }

    if (matches_only) {
        // The document carries no match tree, so the matcher has no reason to build one:
        // the trees are the bulk of what it holds, and on a large trace they are what it
        // runs out of memory holding. An explicit --max-match-trees still wins -- asking
        // for both is asking to see how much the trees cost.
        if (!trees_given) max_match_trees = 0;
        // Anything but JSON prints the trees, which this mode does not have. Overriding
        // an explicit choice silently is worse than overriding it: a reader who asked for
        // -vv and got JSON should be told which flag won.
        if (mode_given && mode != OutputMode::Json)
            std::fprintf(stderr, "note: --matches-only implies -j; ignoring -vv\n");
        mode = OutputMode::Json;
    }

    // Said rather than overridden. --match-evidence shapes the JSON document and nothing
    // else, so with a text renderer it is not wrong, merely inert -- and a reader who
    // asked for evidence and got a capability table should be told why none appeared.
    if (match_evidence && mode != OutputMode::Json)
        std::fprintf(stderr,
                     "note: --match-evidence shapes the JSON document; add -j or "
                     "--matches-only to print it\n");
    if (sparse_evidence && mode != OutputMode::Json)
        std::fprintf(stderr,
                     "note: --sparse-evidence shapes the JSON document; add -j to print "
                     "it\n");
    // Inert rather than wrong, and worth saying so: both of those shapes give every match
    // a second element of its own, so there is no placeholder for this flag to drop.
    if (sparse_evidence && (matches_only || match_evidence))
        std::fprintf(stderr,
                     "note: --sparse-evidence has no effect with %s; that shape has no "
                     "evidence placeholders\n",
                     matches_only ? "--matches-only" : "--match-evidence");

    if (report_path.empty()) {
        std::fprintf(stderr, "error: no input report given\n");
        return 2;
    }
    if (check_parse) return check_report_parse(report_path);
    if (dump) return dump_features(report_path);
    if (rules_dir.empty()) {
        std::fprintf(stderr, "error: -r <rules-dir> is required for matching\n");
        return 2;
    }
    if (format == render::DocFormat::MsgPack && mode != OutputMode::Json) {
        // The text renderers produce a page for a person to read; there is nothing for a
        // binary encoding to do to them.
        std::fprintf(stderr, "error: --msgpack applies to the JSON document; add -j or "
                             "--matches-only\n");
        return 2;
    }
    return run(report_path, rules_dir, mode, args, feature_filter, max_match_trees, matches_only,
               match_evidence, sparse_evidence, out_path, format, top_level_calls);
}
