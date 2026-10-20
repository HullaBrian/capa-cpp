#!/usr/bin/env python3
"""
Compare two capa result documents (`capa -j`) for substantive equality.

The porting contract is "same rules + same binary + same backend = same JSON output",
with timestamps and report metadata allowed to differ. This compares exactly that:
everything except the run metadata (timestamp, version, argv, sample path, rule paths),
with the orderings that capa itself does not fix put into a canonical order first:

  - `locations` and capture location lists: capa serializes a Python set, whose order
    is hash order;
  - the children spliced under a `match:` (or subscope) node: capa appends them in the
    order it iterates that same set.

Everything else -- rule names, rule metadata and source, match addresses and their
order, every match tree node and child order (which capa's optimizer fixes), the layout,
feature counts, library functions -- must be identical.

usage:
    compare_results.py expected.json actual.json [--max-diffs N]
exit status: 0 when equivalent, 1 otherwise.
"""

import re
import sys
import json
import argparse

RUN_METADATA = [
    ("timestamp",),
    ("version",),
    ("argv",),
    ("sample", "path"),
    ("analysis", "rules"),
]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


# capa names the rule it extracts from a subscope "<parent>/<uuid4 hex>", fresh on every
# run, and capa-cpp "<parent>/subscope-<n>". The name only shows where a `match:` of one
# failed (a successful one is rewritten to its subscope statement), and it means nothing
# to a reader either way.
SUBSCOPE_NAME = re.compile(r"/(?:[0-9a-f]{32}|subscope-\d+)$")


def normalize_match(m):
    """normalize a result-document Match, recursively, in place."""
    if not isinstance(m, dict) or "children" not in m:
        return m
    for child in m["children"]:
        normalize_match(child)
    feature = (m.get("node") or {}).get("feature") or {}
    if feature.get("type") == "match":
        feature["match"] = SUBSCOPE_NAME.sub("/<subscope>", feature["match"])
    m["locations"] = sorted(m.get("locations", []), key=canonical)
    m["captures"] = {k: sorted(v, key=canonical) for k, v in m.get("captures", {}).items()}

    node = m.get("node") or {}
    spliced = (node.get("type") == "feature" and node.get("feature", {}).get("type") == "match") or (
        node.get("type") == "statement" and node.get("statement", {}).get("type") == "subscope"
    )
    if spliced:
        m["children"] = sorted(m["children"], key=canonical)
    return m


def normalize(doc):
    meta = doc["meta"]
    for path in RUN_METADATA:
        d = meta
        for k in path[:-1]:
            d = d.get(k, {})
        d.pop(path[-1], None)
    for rule in doc["rules"].values():
        for entry in rule["matches"]:
            if isinstance(entry, list) and len(entry) == 2:
                normalize_match(entry[1])
    return doc


def diff(a, b, path, out, limit):
    if len(out) >= limit:
        return
    if type(a) is not type(b):
        out.append(f"{path}: type {type(a).__name__} != {type(b).__name__}: {str(a)[:200]} != {str(b)[:200]}")
        return
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append(f"{path}.{k}: missing in expected (actual: {canonical(b[k])[:200]})")
            elif k not in b:
                out.append(f"{path}.{k}: missing in actual (expected: {canonical(a[k])[:200]})")
            else:
                diff(a[k], b[k], f"{path}.{k}", out, limit)
            if len(out) >= limit:
                return
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append(f"{path}: length {len(a)} != {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            diff(x, y, f"{path}[{i}]", out, limit)
            if len(out) >= limit:
                return
    elif a != b:
        out.append(f"{path}: {str(a)[:200]!r} != {str(b)[:200]!r}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("expected")
    parser.add_argument("actual")
    parser.add_argument("--max-diffs", type=int, default=40)
    args = parser.parse_args(argv)

    with open(args.expected, "rb") as f:
        expected = normalize(json.load(f))
    with open(args.actual, "rb") as f:
        actual = normalize(json.load(f))

    out: list[str] = []
    a_rules, b_rules = set(expected["rules"]), set(actual["rules"])
    for name in sorted(a_rules - b_rules):
        out.append(f"rule only in expected: {name} ({len(expected['rules'][name]['matches'])} matches)")
    for name in sorted(b_rules - a_rules):
        out.append(f"rule only in actual: {name} ({len(actual['rules'][name]['matches'])} matches)")
    diff(expected["meta"], actual["meta"], "meta", out, args.max_diffs)
    for name in sorted(a_rules & b_rules):
        diff(expected["rules"][name], actual["rules"][name], f"rules[{name!r}]", out, args.max_diffs)
        if len(out) >= args.max_diffs:
            break

    if out:
        for line in out[: args.max_diffs]:
            print(line)
        print(f"DIFFERENT ({len(a_rules)} vs {len(b_rules)} rules)")
        return 1
    print(f"equivalent ({len(a_rules)} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
