// The capa freeze format: `capa0000` + zlib(utf-8(json(features))).
//
// Ports capa/features/freeze/{__init__,features}.py. A freeze file is every feature a
// backend extracted from one sample, scope by scope; capa keeps it as the interchange
// format between feature extraction and matching, so that an engine can be built and
// verified with no analysis backend at all -- freeze in, result document out.
//
// The JSON spellings here are capa's *field* names ("import_", "function_name",
// "basic_blocks", "global_", ...), which is what capa writes. Both the field names and the
// aliases ("import", "function name", "basic blocks", "global", ...) are accepted on load,
// as capa's pydantic models accept both.
//
// The feature and address encodings are shared with the result document (render.cpp),
// where capa embeds the same models.
#pragma once

#include <memory>
#include <string>

#include <nlohmann/json.hpp>

#include "feature_extractor.h"
#include "null_extractor.h"

namespace capa::freeze {

inline constexpr int CURRENT_VERSION = 3;
inline constexpr char MAGIC[] = "capa0000";
inline constexpr std::size_t MAGIC_SIZE = 8;

struct FreezeError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// ---- models ----

// capa.features.freeze.Address, without `value` for "no address" (capa writes it with
// exclude_none).
nlohmann::ordered_json address_to_json(const Address& a);
Address address_from_json(const nlohmann::json& j);

// capa.features.freeze.features.Feature: {"type": ..., <value>, "description"?}.
nlohmann::ordered_json feature_to_json(const Feature& f);
Feature feature_from_json(const nlohmann::json& j);

// capa's frz.Address.__lt__: by type *name*, then by value. Used to sort a dump.
bool address_less(const Address& a, const Address& b);

// ---- files ----

struct Frozen {
    int version = CURRENT_VERSION;
    std::string flavor;          // "static" | "dynamic"
    std::string extractor_name;  // e.g. "VivisectFeatureExtractor"
    std::string extractor_version;
    std::unique_ptr<NullStaticFeatureExtractor> static_extractor;    // flavor == static
    std::unique_ptr<NullDynamicFeatureExtractor> dynamic_extractor;  // flavor == dynamic
};

// Whether `buf` starts with the freeze magic.
bool is_freeze(const std::string& buf);
// Reads just enough of a file to answer is_freeze.
bool is_freeze_file(const std::string& path);

// capa.features.freeze.loads: the JSON document. Throws FreezeError.
Frozen loads(const std::string& json_text);
// capa.features.freeze.load: magic + zlib. Throws FreezeError.
Frozen load(const std::string& buf);
// The JSON document inside a freeze file's bytes (magic stripped, inflated).
std::string decompress_document(const std::string& buf);
Frozen load_file(const std::string& path);

// capa.features.freeze.dumps_static / dumps_dynamic, as capa sorts and spells them.
// `reproducible` leaves the extractor version empty, like capa's --reproducible.
std::string dumps(const StaticFeatureExtractor& extractor, const std::string& extractor_name,
                  bool reproducible = false);
std::string dumps(const DynamicFeatureExtractor& extractor, const std::string& extractor_name,
                  bool reproducible = false);
// MAGIC + zlib(dumps(...)).
std::string dump(const StaticFeatureExtractor& extractor, const std::string& extractor_name,
                 bool reproducible = false);
std::string dump(const DynamicFeatureExtractor& extractor, const std::string& extractor_name,
                 bool reproducible = false);

// The version string written into a freeze's extractor record.
const char* engine_version();

}  // namespace capa::freeze
