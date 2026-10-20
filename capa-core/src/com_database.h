// capa's COM class and interface database (capa/features/com).
//
// A rule may say `com/class: InternetExplorer` or `com/interface: IWebBrowser2`; capa
// translates that into an `or:` of every GUID registered under the name, each as a
// string and as its in-memory bytes (capa.rules.translate_com_feature). The names and
// GUIDs are capa's own data, embedded by scripts/gen_com_database.py.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace capa {

enum class ComType { Class, Interface };

// "CLSID_" / "IID_": the symbol prefix capa puts in the generated features' descriptions.
const char* com_prefix(ComType type);

// The GUIDs ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx") registered under `name`, or none.
// The database is inflated on first use.
const std::vector<std::string>* com_guids(ComType type, const std::string& name);

namespace com_data {
extern const char* const kClasses[];
extern const std::size_t kClassesCount;
extern const char* const kInterfaces[];
extern const std::size_t kInterfacesCount;
}  // namespace com_data

}  // namespace capa
