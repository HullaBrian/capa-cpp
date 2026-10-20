// capa-tests: capa's language-agnostic test suites, run against capa-cpp's engine.
#pragma once

#include <cstdio>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace capa::tests {

struct Options {
    std::string filter;  // run only tests whose id contains this
    bool verbose = false;
};

// Pass/fail bookkeeping and the summary line.
class Tally {
public:
    void pass(const std::string& id, bool verbose) {
        ++passed_;
        if (verbose) std::printf("PASS %s\n", id.c_str());
    }
    void fail(const std::string& id, const std::string& why) {
        ++failed_;
        std::printf("FAIL %s\n        %s\n", id.c_str(), why.c_str());
    }
    void skip(const std::string& id, const std::string& why, bool verbose) {
        ++skipped_;
        if (verbose) std::printf("SKIP %s (%s)\n", id.c_str(), why.c_str());
    }
    void xfail(const std::string& id, const std::string& why, bool verbose) {
        ++xfailed_;
        if (verbose) std::printf("XFAIL %s (%s)\n", id.c_str(), why.c_str());
    }
    int report(const char* what) const {
        std::printf("%s: %d passed, %d failed", what, passed_, failed_);
        if (skipped_) std::printf(", %d skipped", skipped_);
        if (xfailed_) std::printf(", %d expected failures", xfailed_);
        std::printf("\n");
        return failed_ ? 1 : 0;
    }

private:
    int passed_ = 0, failed_ = 0, skipped_ = 0, xfailed_ = 0;
};

// tests/fixtures/matcher: rule + feature listing + expected matches.
int run_match_fixtures(const std::string& dir, const Options& opts);

// tests/fixtures/features: does a backend extract feature F at location L of sample S,
// evaluated against that backend's freeze file for S.
struct FeatureFixtureOptions {
    std::vector<std::string> manifests;
    std::map<std::string, std::string> freeze_by_key;  // sample key -> .frz
    std::string backend;                               // for the fixtures' backend marks
    std::set<std::string> include_tags, exclude_tags;
};
int run_feature_fixtures(const FeatureFixtureOptions& fopts, const Options& opts);

// Checks of capa-cpp's own pieces against capa's behavior: rule parsing (PyYAML typing,
// descriptions, optimizer), the Python-regex translation, freeze round trips.
int run_unit_tests(const Options& opts);

// A freeze file loaded, re-dumped and re-loaded must hold the same features.
int run_freeze_roundtrip(const std::vector<std::string>& paths, const Options& opts);

}  // namespace capa::tests
