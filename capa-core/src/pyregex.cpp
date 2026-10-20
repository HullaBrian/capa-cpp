#include "pyregex.h"

#include <cctype>
#include <map>
#include <memory>
#include <unordered_map>

namespace capa {

namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }

bool fail(std::string* error, const std::string& why) {
    if (error) *error = why;
    return false;
}

// At `pos` (just past a '{'), Python reads a repetition only for {m}, {m,}, {,n} and
// {m,n} with decimal digits; anything else is a literal brace. Returns the length of the
// quantifier body including the closing brace, and the ECMAScript spelling of it.
std::size_t quantifier_at(const std::string& p, std::size_t pos, std::string& spelled) {
    std::size_t k = pos;
    std::string lo, hi;
    while (k < p.size() && is_digit(p[k])) lo += p[k++];
    bool comma = false;
    if (k < p.size() && p[k] == ',') {
        comma = true;
        ++k;
        while (k < p.size() && is_digit(p[k])) hi += p[k++];
    }
    if (k >= p.size() || p[k] != '}') return 0;
    if (!comma && lo.empty()) return 0;  // "{}" is literal
    if (comma && lo.empty() && hi.empty()) return 0;  // "{,}" is literal
    spelled = "{" + (lo.empty() ? std::string("0") : lo) + (comma ? "," + hi : "") + "}";
    return k - pos + 1;
}

}  // namespace

std::optional<TranslatedRegex> translate_python_regex(const std::string& p, bool icase,
                                                      std::string* error) {
    TranslatedRegex out;
    out.icase = icase;
    std::string& o = out.pattern;
    o.reserve(p.size() + 16);

    std::size_t i = 0;
    const std::size_t n = p.size();

    // Global inline flags, which Python only accepts at the very start of the pattern.
    while (i + 2 < n && p[i] == '(' && p[i + 1] == '?' && std::isalpha(static_cast<unsigned char>(p[i + 2]))) {
        std::size_t k = i + 2;
        bool ok = true;
        bool im = false, mm = false;
        while (k < n && std::isalpha(static_cast<unsigned char>(p[k]))) {
            switch (p[k]) {
                case 'i': im = true; break;
                case 'm': mm = true; break;
                case 's':  // DOTALL: already always on
                case 'a':  // ASCII: std::regex is ASCII-only anyway
                case 'u':
                case 'L':
                    break;
                default: ok = false;  // 'x' (verbose) and anything unknown
            }
            ++k;
        }
        if (!ok || k >= n || p[k] != ')') break;  // scoped flags "(?i:...)" handled below
        out.icase = out.icase || im;
        out.multiline = out.multiline || mm;
        i = k + 1;
    }

    std::map<std::string, int> named;
    int groups = 0;

    while (i < n) {
        const char c = p[i];
        if (c == '\\') {
            if (i + 1 >= n) {
                fail(error, "trailing backslash");
                return std::nullopt;
            }
            const char e = p[i + 1];
            if (e == 'A') {
                o += '^';
            } else if (e == 'Z') {
                o += '$';  // \Z is the true end, which is what ECMAScript's $ already is
            } else {
                o += c;
                o += e;
            }
            i += 2;
            continue;
        }
        if (c == '[') {
            // A character class: copied through, with a leading ']' made explicit.
            o += '[';
            ++i;
            if (i < n && p[i] == '^') {
                o += '^';
                ++i;
            }
            if (i < n && p[i] == ']') {
                o += "\\]";
                ++i;
            }
            bool closed = false;
            while (i < n) {
                const char d = p[i];
                if (d == '\\' && i + 1 < n) {
                    o += d;
                    o += p[i + 1];
                    i += 2;
                    continue;
                }
                if (d == ']') {
                    o += ']';
                    ++i;
                    closed = true;
                    break;
                }
                if (d == '[') {
                    o += "\\[";  // literal in Python (a FutureWarning, not a nested set)
                    ++i;
                    continue;
                }
                o += d;
                ++i;
            }
            if (!closed) {
                fail(error, "unterminated character set");
                return std::nullopt;
            }
            continue;
        }
        if (c == '.') {
            o += "[\\s\\S]";
            ++i;
            continue;
        }
        if (c == '$') {
            o += out.multiline ? "$" : "(?=\\n?$)";
            ++i;
            continue;
        }
        if (c == '{') {
            std::string spelled;
            const std::size_t len = quantifier_at(p, i + 1, spelled);
            if (len) {
                o += spelled;
                i += 1 + len;
                if (i < n && p[i] == '+') {
                    fail(error, "possessive quantifier");
                    return std::nullopt;
                }
            } else {
                o += "\\{";
                ++i;
            }
            continue;
        }
        if (c == '}') {
            o += "\\}";
            ++i;
            continue;
        }
        if ((c == '*' || c == '+' || c == '?') && i + 1 < n && p[i + 1] == '+') {
            fail(error, "possessive quantifier");
            return std::nullopt;
        }
        if (c == '(') {
            if (i + 1 < n && p[i + 1] == '?') {
                const std::string rest = p.substr(i + 2, 3);
                if (rest.rfind(":", 0) == 0 || rest.rfind("=", 0) == 0 || rest.rfind("!", 0) == 0) {
                    o += p.substr(i, 3);
                    i += 3;
                    continue;
                }
                if (rest.rfind("P<", 0) == 0) {
                    const std::size_t close = p.find('>', i + 4);
                    if (close == std::string::npos) {
                        fail(error, "unterminated group name");
                        return std::nullopt;
                    }
                    named[p.substr(i + 4, close - (i + 4))] = ++groups;
                    o += '(';
                    i = close + 1;
                    continue;
                }
                if (rest.rfind("P=", 0) == 0) {
                    const std::size_t close = p.find(')', i + 4);
                    if (close == std::string::npos) {
                        fail(error, "unterminated group reference");
                        return std::nullopt;
                    }
                    auto it = named.find(p.substr(i + 4, close - (i + 4)));
                    if (it == named.end()) {
                        fail(error, "unknown group name");
                        return std::nullopt;
                    }
                    o += "(?:\\" + std::to_string(it->second) + ")";
                    i = close + 1;
                    continue;
                }
                if (rest.rfind("#", 0) == 0) {
                    const std::size_t close = p.find(')', i + 2);
                    if (close == std::string::npos) {
                        fail(error, "unterminated comment");
                        return std::nullopt;
                    }
                    i = close + 1;
                    continue;
                }
                if (rest.rfind("<=", 0) == 0 || rest.rfind("<!", 0) == 0) {
                    fail(error, "lookbehind is not supported by std::regex");
                    return std::nullopt;
                }
                fail(error, "unsupported group construct (?" + rest.substr(0, 1) + "...)");
                return std::nullopt;
            }
            ++groups;
            o += '(';
            ++i;
            continue;
        }
        o += c;
        ++i;
    }
    return out;
}

const std::regex* compile_capa_regex(const std::string& value, std::string* error) {
    struct Entry {
        std::unique_ptr<std::regex> re;
        std::string error;
    };
    static std::unordered_map<std::string, Entry> cache;
    auto it = cache.find(value);
    if (it != cache.end()) {
        if (error) *error = it->second.error;
        return it->second.re.get();
    }

    Entry entry;
    // capa.features.common.Regex: value[1:-1], or value[1:-2] with IGNORECASE for "/i".
    bool icase = false;
    std::string pat;
    if (value.size() >= 2 && value.front() == '/' && value.compare(value.size() - 2, 2, "/i") == 0) {
        icase = true;
        pat = value.substr(1, value.size() - 3 + (value.size() == 2 ? 1 : 0));
        if (value.size() == 2) pat.clear();
    } else if (!value.empty() && value.front() == '/' && value.back() == '/') {
        pat = value.size() >= 2 ? value.substr(1, value.size() - 2) : std::string();
    } else {
        entry.error = "not a /regex/";
    }
    if (entry.error.empty()) {
        std::string why;
        auto translated = translate_python_regex(pat, icase, &why);
        if (!translated) {
            entry.error = why;
        } else {
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (translated->icase) flags |= std::regex::icase;
            if (translated->multiline) flags |= std::regex::multiline;
            try {
                entry.re = std::make_unique<std::regex>(translated->pattern, flags);
            } catch (const std::regex_error& e) {
                entry.error = e.what();
            }
        }
    }
    if (error) *error = entry.error;
    const std::regex* ptr = entry.re.get();
    cache.emplace(value, std::move(entry));
    return ptr;
}

}  // namespace capa
