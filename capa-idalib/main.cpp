// capa-idalib: capa-cpp on IDA's analysis, headless.
//
// The preferred verification backend: run capa-cpp's IDA feature
// extractor through idalib, the same analysis capa's own `-b ida` backend uses, and the
// result document has to be the one capa writes for the same binary. Any difference is
// then the port's, not the disassembler's. `--dump-freeze` writes the extracted features
// in capa's freeze format instead, to compare against capa's
// (`python -m capa.features.freeze -b ida sample out.frz`) feature for feature.
//
//   capa-idalib <sample> -r <rules> [-r <rules> ...] [-j | -vv] [-o <out>]
//   capa-idalib <sample> --dump-freeze <out.frz>
//
// Needs an IDA Pro 9.x installation with idalib (ida.dll / idalib.dll on PATH, or run
// from the IDA directory), and a license that includes it.
#include <cstdio>
#include <string>
#include <vector>

// capa-core (and nlohmann/json with it) before the IDA SDK, whose pro.h redefines
// strtoull and friends as macros that nlohmann's headers then trip over.
#include "feature_filter.h"
#include "freeze.h"
#include "render.h"
#include "result_document.h"
#include "rules.h"
#include "static_caps.h"

#include "ida/sdk.h"

#include <auto.hpp>
#include <idalib.hpp>

#include "ida/extractor.h"

namespace {

enum class Mode { Default, Json, VVerbose };

int usage() {
    std::fprintf(stderr,
                 "usage: capa-idalib <sample> -r <rules> [-r <rules> ...] [-j | -vv] [-o <out>]\n"
                 "       capa-idalib <sample> --dump-freeze <out.frz>\n");
    return 2;
}

bool write_file(const std::string& path, const std::string& bytes) {
    std::FILE* fp = std::fopen(path.c_str(), "wb");
    if (!fp) return false;
    const bool ok = std::fwrite(bytes.data(), 1, bytes.size(), fp) == bytes.size();
    return std::fclose(fp) == 0 && ok;
}

// Closes the database on every way out, unsaved: capa never writes to it either.
struct Database {
    bool open = false;
    ~Database() {
        if (open) close_database(false);
    }
};

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    std::string sample, out_path, freeze_out;
    std::vector<std::string> rule_paths;
    Mode mode = Mode::Default;
    for (std::size_t k = 0; k < args.size(); ++k) {
        const std::string& a = args[k];
        if ((a == "-r" || a == "--rules") && k + 1 < args.size())
            rule_paths.push_back(args[++k]);
        else if ((a == "-o" || a == "--output") && k + 1 < args.size())
            out_path = args[++k];
        else if (a == "--dump-freeze" && k + 1 < args.size())
            freeze_out = args[++k];
        else if (a == "-j" || a == "--json")
            mode = Mode::Json;
        else if (a == "-vv" || a == "--vverbose")
            mode = Mode::VVerbose;
        else if (sample.empty() && !a.empty() && a[0] != '-')
            sample = a;
        else
            return usage();
    }
    if (sample.empty() || (freeze_out.empty() && rule_paths.empty())) return usage();

    if (init_library() != 0) {
        std::fprintf(stderr, "error: idalib failed to initialize (is IDA installed and licensed?)\n");
        return 1;
    }
    enable_console_messages(false);

    // As capa's ida backend opens it: Lumina off (it can overwrite names that came from
    // debug info), -R to load resources (where embedded PEs live).
    Database db;
    if (open_database(sample.c_str(), true, "-Olumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0 -R") != 0) {
        std::fprintf(stderr, "error: failed to analyze %s\n", sample.c_str());
        return 1;
    }
    db.open = true;
    auto_wait();

    try {
        // Every function, as capa's IdaFeatureExtractor sees them: the system-module
        // filter is for databases of process dumps, which capa does not open.
        capa::ida::IdaExtractor extractor(/*skip_system_modules=*/false);

        if (!freeze_out.empty()) {
            if (!write_file(freeze_out, capa::freeze::dump(extractor, "IdaFeatureExtractor"))) {
                std::fprintf(stderr, "error: cannot write %s\n", freeze_out.c_str());
                return 1;
            }
            if (rule_paths.empty()) return 0;
        }

        capa::RuleSet ruleset = capa::RuleSet::load_from_paths(rule_paths);
        capa::FeatureFilter filter = capa::FeatureFilter::from_ruleset(ruleset);
        filter.disable();  // the reported feature counts must be capa's
        capa::StaticCapabilities caps = capa::find_static_capabilities(ruleset, extractor, filter);
        capa::render::Doc doc = capa::render::build_static_doc(ruleset, extractor, caps,
                                                               "IdaFeatureExtractor", rule_paths);
        capa::render::RenderInput in{ruleset, caps.matches, doc, capa::render::capa_path(sample), args};

        std::string text;
        if (mode == Mode::Json)
            text = capa::render::render_json(in) + "\n";
        else if (mode == Mode::VVerbose)
            text = capa::render::render_vverbose(in);
        else
            text = capa::render::render_default(in);
        if (out_path.empty()) {
            std::fwrite(text.data(), 1, text.size(), stdout);
        } else if (!write_file(out_path, text)) {
            std::fprintf(stderr, "error: cannot write %s\n", out_path.c_str());
            return 1;
        }
        return 0;
    } catch (const capa::InvalidRule& e) {
        std::fprintf(stderr, "error: %s\n", e.message.c_str());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
