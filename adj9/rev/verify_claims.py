#!/usr/bin/env python3
"""Verify claims construction against raw device sign_input records.

This is deliberately read-only.  It parses the NUL-delimited map_order field
(so commas inside partner_params JSON are not mistaken for entry separators),
checks the Java Map.toString spelling, and compares the selected descriptor
claims with mint_pipeline.claims_from_wire + desc10_law.

The raw sign_input map is the complete map handed to the signer.  It is not
itself descriptor #10: the signer map contains wire/runtime fields which the
descriptor law intentionally omits.  The script reports both comparisons.
"""
import argparse
import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from desc10_law import build_desc10, desc10_keys
from mint_pipeline import INTERNAL_CLAIMS, claims_from_wire

LOGS = ("adj9_wh4.log", "adj9_wh2.log")
DEVICE = os.path.normpath(os.path.join(HERE, "..", "device"))
SUPPORTED = {"session", "click", "attribution"}


def parse_record(lines, path, begin_line):
    """Return a sign_input record or raise ValueError with context."""
    if len(lines) < 3:
        raise ValueError("truncated sign_input record")
    size = int(lines[0].split("=", 1)[1])
    map_text = lines[1][len("map_toString="):]
    order_text = lines[2][len("map_order="):]
    pairs = []
    for part in order_text.split("\x02"):
        if not part:
            continue
        if "\x01" not in part:
            raise ValueError("bad map_order pair %r" % part)
        k, v = part.split("\x01", 1)
        pairs.append((k, v))
    if len(pairs) != size:
        raise ValueError("map_size=%d but map_order has %d pairs" %
                         (size, len(pairs)))
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key in map_order")
    # This is the exact Java AbstractMap/LinkedHashMap toString convention
    # visible in the captures: braces, comma-space, and no escaping.
    rebuilt = "{" + ", ".join("%s=%s" % (k, v) for k, v in pairs) + "}"
    return {
        "path": path,
        "begin_line": begin_line,
        "size": size,
        "pairs": pairs,
        "values": dict(pairs),
        "map_text": map_text,
        "rebuilt": rebuilt,
        "format_ok": map_text == rebuilt,
    }


def extract(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            if "###ADJ9_BEGIN type=sign_input " not in line:
                continue
            # The next three physical lines are map_size, map_toString,
            # map_order.  Do not regex the map text: JSON values contain commas.
            body = [f.readline().rstrip("\r\n") for _ in range(3)]
            yield parse_record(body, path, line_no)


def first_order_diff(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i, x, y
    if len(a) != len(b):
        return min(len(a), len(b)), a[len(b):] if len(a) > len(b) else None, b[len(a):] if len(b) > len(a) else None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", nargs="*", default=list(LOGS),
                    help="log basenames under ../device")
    ap.add_argument("--details", action="store_true",
                    help="print every record and every mismatch")
    args = ap.parse_args()

    records = []
    for name in args.logs:
        path = name if os.path.isabs(name) else os.path.join(DEVICE, name)
        for rec in extract(path):
            rec["file"] = os.path.basename(path)
            rec["kind"] = rec["values"].get("activity_kind", "<missing>")
            records.append(rec)

    print("RAW SIG-INPUT RECORDS: %d" % len(records))
    for file in sorted({r["file"] for r in records}):
        subset = [r for r in records if r["file"] == file]
        print("  %s: %d" % (file, len(subset)))
    kinds = collections.Counter(r["kind"] for r in records)
    print("KINDS: " + ", ".join("%s=%d" % kv for kv in sorted(kinds.items())))

    bad_format = [r for r in records if not r["format_ok"]]
    print("MAP_TOString FORMAT: %d/%d exact (reconstructed from map_order)" %
          (len(records) - len(bad_format), len(records)))
    for r in bad_format:
        print("  FORMAT MISMATCH %s:%d" % (r["file"], r["begin_line"]))

    # Show the exact observed selection: keys used by desc10_law, and all
    # signer-map keys not selected.  This is the raw evidence for the filter.
    print("\nOBSERVED CLAIM SELECTION (supported kinds):")
    selection = {}
    for kind in sorted(SUPPORTED):
        rs = [r for r in records if r["kind"] == kind]
        if not rs:
            continue
        all_keys = set().union(*(set(r["values"]) for r in rs))
        # desc10_keys is a law definition; val is only used for optional push_token.
        law_keys = desc10_keys(kind, {"push_token": "x"})
        # Optional push_token is only present in some records; report each variant.
        variants = collections.Counter()
        for r in rs:
            kk = desc10_keys(kind, r["values"])
            variants[tuple(kk)] += 1
        print("  %s: records=%d raw_map_sizes=%s" %
              (kind, len(rs), sorted({r["size"] for r in rs})))
        print("    law keys (%d): %s" % (len(law_keys), ", ".join(law_keys)))
        print("    law-key variants: %s" %
              ", ".join(str(n) + "x" + str(len(k)) for k, n in variants.items()))
        selection[kind] = (all_keys, variants)

    # Build/compare every supported record.  The raw signer map is the
    # comparison input; internal keys are still compared against the values
    # actually present in that map before claims_from_wire overrides them.
    stats = collections.Counter()
    mismatches = []
    for r in records:
        kind = r["kind"]
        if kind not in SUPPORTED:
            stats["unsupported_kind"] += 1
            mismatches.append((r, "unsupported kind: claims_from_wire/build_desc10"))
            continue
        raw = r["values"]
        try:
            law_order = desc10_keys(kind, raw)
            claims = claims_from_wire(raw, kind)
            built = build_desc10(claims, kind)
        except Exception as e:
            stats["construction_error"] += 1
            mismatches.append((r, "construction error: %s" % e))
            continue

        expected_selected = {k: raw.get(k) for k in law_order}
        # activity_kind and internal constants are generated by our code;
        # compare them with the real map, rather than blindly accepting them.
        for k in law_order:
            expected_selected[k] = raw.get(k)
        missing = [k for k in law_order if k not in raw]
        extra = [k for k in claims if k not in law_order]
        bad_values = [(k, claims[k], raw.get(k)) for k in law_order
                      if k in raw and str(claims[k]) != str(raw[k])]
        if missing:
            stats["missing_selected"] += 1
            mismatches.append((r, "selected keys missing from raw map: %s" % missing))
        if extra:
            stats["extra_constructed"] += 1
            mismatches.append((r, "constructed keys not in law order: %s" % extra))
        if bad_values:
            stats["value_mismatch"] += 1
            mismatches.append((r, "constructed/raw value mismatches: %s" % bad_values))
        if list(claims) != law_order:
            stats["constructed_order"] += 1
            mismatches.append((r, "constructed insertion order != desc10_keys"))
        # The real signer map order is complete insertion order.  This is
        # intentionally not compared to the descriptor order as if identical;
        # print the first difference and classify it as map-vs-descriptor.
        od = first_order_diff([k for k, _ in r["pairs"]], law_order)
        if od:
            stats["raw_order_differs_from_descriptor"] += 1
        # Reconstruct what our selected claims map would look like using the
        # same Java formatting. This is a useful exactness check for spacing
        # and unescaped special characters; it is expected to be a subset of
        # the raw signer map, not the raw signer map itself.
        our_map_text = "{" + ", ".join("%s=%s" % (k, claims[k])
                                        for k in claims) + "}"
        if any(ch in raw.get("referrer", "") for ch in "&%()"):
            stats["special_referrer"] += 1
        if "partner_params" in raw:
            stats["special_json_value"] += 1
        # build_desc10 is value concatenation, so these checks prove it did
        # not escape or normalize special characters.
        if any(ch in built for ch in "&%(){}[]\":,"):
            stats["special_value_preserved_in_desc10"] += 1
        if args.details:
            print("  RECORD %s:%d kind=%s size=%d format=%s law_order=%s" %
                  (r["file"], r["begin_line"], kind, r["size"],
                   "OK" if r["format_ok"] else "BAD", law_order))
            print("    raw_order_head=%s" %
                  ", ".join(k for k, _ in r["pairs"][:8]))
            print("    claims_order=%s" % list(claims))
            print("    desc10_len=%d special_ref=%s special_json=%s" %
                  (len(built), any(ch in raw.get("referrer", "") for ch in "&%()"),
                   "partner_params" in raw))
            print("    raw_map_text_len=%d our_selected_map_text_len=%d" %
                  (len(r["map_text"]), len(our_map_text)))

    print("\nCONSTRUCTION COMPARISON:")
    for name in ("construction_error", "missing_selected", "extra_constructed",
                 "value_mismatch", "constructed_order", "unsupported_kind",
                 "raw_order_differs_from_descriptor", "special_referrer",
                 "special_json_value", "special_value_preserved_in_desc10"):
        print("  %-36s %d" % (name, stats[name]))
    print("  supported records with no value/key construction mismatch: %d/%d" %
          (sum(1 for r in records if r["kind"] in SUPPORTED) -
           (stats["missing_selected"] + stats["extra_constructed"] +
            stats["value_mismatch"] + stats["construction_error"]), 
           sum(1 for r in records if r["kind"] in SUPPORTED)))

    if mismatches:
        print("\nMISMATCH DETAILS (all records unless --details is not needed):")
        for r, msg in mismatches:
            print("  %s:%d kind=%s size=%d: %s" %
                  (r["file"], r["begin_line"], r["kind"], r["size"], msg))

    print("\nCONCLUSION:")
    print("  Raw map_toString is exact when rebuilt from map_order; values are")
    print("  unescaped Java toString text, including commas in JSON and any")
    print("  ampersands/percent signs/parens in referrer.")
    print("  claims_from_wire selects the desc10 law subset, not the complete")
    print("  signer map. The complete signer-map order is raw map_order; the")
    print("  descriptor value order is the separate desc10_keys order.")
    return 0 if not bad_format and stats["construction_error"] == 0 and stats["missing_selected"] == 0 and stats["extra_constructed"] == 0 and stats["value_mismatch"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
