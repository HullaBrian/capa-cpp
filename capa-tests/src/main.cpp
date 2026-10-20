// capa-tests: capa's language-agnostic test suites, run against capa-cpp.
//
//   capa-tests                                   unit tests + every matcher fixture
//   capa-tests unit
//   capa-tests match-fixtures [<dir>]            default: tests/fixtures/matcher
//   capa-tests feature-fixtures --backend <name> --freeze <key>=<file.frz> [...]
//                               [--include-tag <t>] [--exclude-tag <t>] [<manifest.json> ...]
//                                                default manifest: tests/fixtures/features/static.json
//   capa-tests freeze-roundtrip <file.frz> [...]
//
// Common options: -k <substring> runs only tests whose id contains it; -v lists passes.
// Exit status is 0 only when nothing failed.
#include <filesystem>

#include "tests.h"

namespace fs = std::filesystem;
using namespace capa::tests;

namespace {

// The repo's tests/fixtures, found relative to the executable (build\<Config>\) or the
// working directory, so the default invocation works from either.
std::string fixtures_dir(const char* argv0) {
    std::vector<fs::path> candidates = {fs::current_path() / "tests" / "fixtures"};
    std::error_code ec;
    fs::path exe = fs::absolute(argv0, ec);
    for (fs::path p = exe.parent_path(); !p.empty() && p != p.parent_path(); p = p.parent_path())
        candidates.push_back(p / "tests" / "fixtures");
    for (const auto& c : candidates)
        if (fs::is_directory(c / "matcher", ec)) return c.string();
    return (fs::current_path() / "tests" / "fixtures").string();
}

int usage() {
    std::fprintf(stderr,
                 "usage: capa-tests [unit | match-fixtures [<dir>] |\n"
                 "                   feature-fixtures --backend <name> --freeze <key>=<file.frz> ...\n"
                 "                                    [--include-tag <t>] [--exclude-tag <t>] [<manifest.json> ...] |\n"
                 "                   freeze-roundtrip <file.frz> ...] [-k <substring>] [-v]\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    Options opts;
    std::vector<std::string> positional;
    FeatureFixtureOptions fopts;
    for (std::size_t k = 0; k < args.size(); ++k) {
        const std::string& a = args[k];
        if (a == "-k" && k + 1 < args.size()) {
            opts.filter = args[++k];
        } else if (a == "-v") {
            opts.verbose = true;
        } else if (a == "--backend" && k + 1 < args.size()) {
            fopts.backend = args[++k];
        } else if (a == "--include-tag" && k + 1 < args.size()) {
            fopts.include_tags.insert(args[++k]);
        } else if (a == "--exclude-tag" && k + 1 < args.size()) {
            fopts.exclude_tags.insert(args[++k]);
        } else if (a == "--freeze" && k + 1 < args.size()) {
            const std::string spec = args[++k];
            const auto eq = spec.find('=');
            if (eq == std::string::npos) return usage();
            fopts.freeze_by_key[spec.substr(0, eq)] = spec.substr(eq + 1);
        } else if (!a.empty() && a[0] == '-') {
            return usage();
        } else {
            positional.push_back(a);
        }
    }

    const std::string fixtures = fixtures_dir(argv[0]);
    const std::string command = positional.empty() ? "all" : positional[0];
    const std::vector<std::string> rest(positional.empty() ? positional.begin() : positional.begin() + 1,
                                        positional.end());
    try {
        if (command == "all") {
            const int a = run_unit_tests(opts);
            const int b = run_match_fixtures((fs::path(fixtures) / "matcher").string(), opts);
            return a || b ? 1 : 0;
        }
        if (command == "unit") return run_unit_tests(opts);
        if (command == "match-fixtures")
            return run_match_fixtures(rest.empty() ? (fs::path(fixtures) / "matcher").string() : rest[0], opts);
        if (command == "feature-fixtures") {
            if (fopts.backend.empty() || fopts.freeze_by_key.empty()) return usage();
            fopts.manifests = rest;
            if (fopts.manifests.empty()) fopts.manifests.push_back((fs::path(fixtures) / "features" / "static.json").string());
            return run_feature_fixtures(fopts, opts);
        }
        if (command == "freeze-roundtrip") {
            if (rest.empty()) return usage();
            return run_freeze_roundtrip(rest, opts);
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return usage();
}
