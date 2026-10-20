// Common includes for the ida-capa plugin.
//
// Include ordering matters, and it is the same trap ida-dotnet documents:
//
//   1. Windows first (Windows only), with lean/nominmax so it does not clobber the
//      SDK or the STL. Nothing here is needed on Linux/Mac.
//   2. nlohmann/json and yaml-cpp BEFORE the IDA SDK. pro.h carries a VS2010
//      compatibility shim, `#define strtoull _strtoui64`; those headers call
//      std::strtoull, which the macro rewrites into the non-existent
//      std::_strtoui64. Compiling them first means they are done before the macro
//      exists.
//   3. the IDA SDK, via ida/sdk.h (which also sets the USE_DANGEROUS_FUNCTIONS /
//      USE_STANDARD_FILE_FUNCTIONS defines pro.h needs to leave <fstream> alone).
#ifndef IDA_CAPA_PCH_H
#define IDA_CAPA_PCH_H

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif  // _WIN32

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include "ida/sdk.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#endif  // IDA_CAPA_PCH_H
