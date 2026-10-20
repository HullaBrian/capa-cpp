#include "render_tree.h"

#include "match_retention.h"

#include <cstdio>
#include <set>
#include <sstream>
#include <string>

namespace capa::render {

namespace {

// find rule `name`'s match whose address is one of `locs` (else the first match).
//
// Returns the slot rather than the tree, so "there is no such match" (null return) stays
// distinguishable from "the match is there and its evidence was capped" (a slot holding
// null) -- the two print differently, and collapsing them would silently drop the note
// that says why a subrule expanded into nothing.
const MatchEvidence* find_submatch(const MatchCtx& ctx, const std::string& name,
                                   const AddressSet& locs) {
    auto it = ctx.matches.find(name);
    if (it == ctx.matches.end() || it->second.empty()) return nullptr;
    for (const auto& [addr, evidence] : it->second)
        if (locs.count(addr)) return &evidence;
    return &it->second.front().second;
}

// One match: its tree, or the line that stands in for a tree that was not kept.
//
// Said in words, the same way the JSON serializer says `"truncated": true`. Without it a
// capped match renders as nothing at all under its address, which reads as a rendering
// bug rather than as a deliberate omission.
void render_match(std::ostringstream& os, const MatchCtx& ctx, const Result& res, int indent);

void render_evidence(std::ostringstream& os, const MatchCtx& ctx, const MatchEvidence& evidence,
                     int indent) {
    if (evidence) {
        render_match(os, ctx, *evidence, indent);
        return;
    }
    os << std::string(2 * static_cast<std::size_t>(indent), ' ')
       << "<evidence not kept; --max-match-trees 0 keeps every tree>\n";
}

// render one match-tree node as indented text (success mode only; skips failures)
void render_match(std::ostringstream& os, const MatchCtx& ctx, const Result& res, int indent) {
    if (!res.success) return;
    std::string pad(2 * indent, ' ');

    if (res.node_is_statement) {
        const Statement& s = *res.stmt;
        std::string line;
        switch (s.type) {
            case StatementType::And: line = "and:"; break;
            case StatementType::Or: line = "or:"; break;
            case StatementType::Not: line = "not:"; break;
            case StatementType::Some:
                line = s.count == 0 ? "optional:" : (std::to_string(s.count) + " or more:");
                break;
            case StatementType::Range: {
                line = "count(" + res.stmt->range_child.str() + "): ";
                for (const auto& a : res.locations) { line += format_address(a) + " "; }
                break;
            }
            case StatementType::Subscope: line = scope_to_string(s.subscope) + ":"; break;
        }
        if (!s.description.empty()) line += " = " + s.description;
        os << pad << line << "\n";
        for (const auto& c : res.children) render_match(os, ctx, c, indent + 1);
        return;
    }

    const Feature& f = res.feature;

    // splice subscope match: references into their scope block (like capa vverbose)
    if (f.type == FeatureType::MatchedRule) {
        auto rule = ctx.ruleset.get(f.s);
        if (rule && rule->is_subscope) {
            const MatchEvidence* sub = find_submatch(ctx, f.s, res.locations);
            Scope sc = rule->scopes.dynamic_scope.value_or(
                rule->scopes.static_scope.value_or(Scope::CALL));
            os << pad << scope_to_string(sc) << ":\n";
            if (sub) render_evidence(os, ctx, *sub, indent + 1);
            return;
        }
        // named rule / namespace match: show and expand if we have its match
        os << pad << "match: " << f.s << "\n";
        if (rule && !rule->is_subscope) {
            const MatchEvidence* sub = find_submatch(ctx, f.s, res.locations);
            if (sub) render_evidence(os, ctx, *sub, indent + 1);
        }
        return;
    }

    std::string line = f.get_name_str() + ": " + f.get_value_str();
    if (!f.description.empty()) line += " = " + f.description;
    os << pad << line;
    if (!res.captures.empty()) {
        os << "\n";
        for (const auto& [str, locs] : res.captures) os << pad << "  - \"" << str << "\"\n";
    } else if (!f.is_global() && !res.locations.empty()) {
        os << " @ ";
        int shown = 0;
        for (const auto& a : res.locations) {
            if (shown++) os << ", ";
            if (shown > 4) { os << "..."; break; }
            os << format_address(a);
        }
        os << "\n";
    } else {
        os << "\n";
    }
    for (const auto& c : res.children) render_match(os, ctx, c, indent + 1);
}

}  // namespace

// capa.render.verbose.format_address. Integers in capa.helpers.hex style (upper-case
// digits) except a bare virtual address, which capa-cpp has always printed in lower case.
std::string format_address(const Address& a) {
    char buf[128];
    switch (a.type) {
        case AddressType::PROCESS:
            std::snprintf(buf, sizeof(buf), "process{pid:%u}", a.pid);
            return buf;
        case AddressType::THREAD:
            std::snprintf(buf, sizeof(buf), "process{pid:%u,tid:%u}", a.pid, a.tid);
            return buf;
        case AddressType::CALL:
            std::snprintf(buf, sizeof(buf), "process{pid:%u,tid:%u,call:%llu}", a.pid, a.tid,
                          static_cast<unsigned long long>(a.id));
            return buf;
        case AddressType::ABSOLUTE:
            std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(a.value));
            return buf;
        case AddressType::FILE_OFFSET:
            std::snprintf(buf, sizeof(buf), "file(0x%llx)",
                          static_cast<unsigned long long>(a.value));
            return buf;
        case AddressType::RELATIVE_VA:
            std::snprintf(buf, sizeof(buf), "base address+0x%llX",
                          static_cast<unsigned long long>(a.value));
            return buf;
        case AddressType::DN_TOKEN:
            std::snprintf(buf, sizeof(buf), "token(0x%llX)",
                          static_cast<unsigned long long>(a.value));
            return buf;
        case AddressType::DN_TOKEN_OFFSET:
            std::snprintf(buf, sizeof(buf), "token(0x%llX)+0x%llX",
                          static_cast<unsigned long long>(a.value),
                          static_cast<unsigned long long>(a.id));
            return buf;
        case AddressType::NO_ADDRESS:
            return "global";
    }
    return "?";
}

std::string render_match_tree(const MatchCtx& ctx, const Result& res, int indent) {
    std::ostringstream os;
    render_match(os, ctx, res, indent);
    return os.str();
}

std::string render_match_tree(const MatchCtx& ctx, const MatchEvidence& evidence, int indent) {
    std::ostringstream os;
    render_evidence(os, ctx, evidence, indent);
    return os.str();
}

}  // namespace capa::render
