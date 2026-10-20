// Python `re` semantics on std::regex.
//
// capa's `string: /pattern/` features are Python regular expressions, compiled with
// re.DOTALL always and re.IGNORECASE for a trailing `/i` (capa.features.common.Regex).
// std::regex speaks ECMAScript, which differs in ways that change what matches:
//
//   Python                      ECMAScript                  translated to
//   .  (DOTALL: any char)       any char but line breaks    [\s\S]
//   $  (end, or before a final  end only                    (?=\n?$)
//       newline)
//   \A  \Z                      not supported               ^  $
//   (?P<name>...)  (?P=name)    not supported               (...)  \N
//   (?i) (?s) (?m) at the start not supported               regex flags
//   {,n}                        not supported               {0,n}
//   a lone { or } is literal    error                       \{  \}
//   []] (first ] is literal)    empty class                 [\]]
//   (?#comment)                 not supported               removed
//
// Constructs with no ECMAScript equivalent -- lookbehind, atomic groups, possessive
// quantifiers, scoped flags like (?i:...), conditionals -- are reported as errors rather
// than approximated. Matching is over UTF-8 bytes where Python matches code points, so
// `.` and `\w` only agree on ASCII text; no capa rule depends on the difference today.
#pragma once

#include <optional>
#include <regex>
#include <string>

namespace capa {

struct TranslatedRegex {
    std::string pattern;  // ECMAScript
    bool icase = false;
    bool multiline = false;
};

// Translate the body of a Python regex (no surrounding slashes). Returns nullopt and sets
// `error` when the pattern uses a construct std::regex cannot express.
std::optional<TranslatedRegex> translate_python_regex(const std::string& pattern, bool icase,
                                                      std::string* error = nullptr);

// "/pat/" or "/pat/i" as a capa rule writes it, compiled with capa's flags. Null when it
// cannot be compiled (`error` says why). Cached by value; the matcher is single-threaded.
const std::regex* compile_capa_regex(const std::string& value, std::string* error = nullptr);

}  // namespace capa
