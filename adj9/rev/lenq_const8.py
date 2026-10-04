"""lenq_const8.py - is CONST8 (the assumed #8) actually read by seg27's signing?

KEYS lacked bfffffff, so its LENQ reads were never checked. If CONST8 is
never LENQ-read (or only by other signings' slots), the true #8 differs
and that alone explains the click FinEx failure.
Also checks W0 fdda97ce concentration for comparison.
"""
import json, os, sys
from collections import Counter, defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
L = d.get("lenq", [])


def be4(v):
    return "%08x" % (v & 0xFFFFFFFF)


for target, nm in (("bfffffff", "#8w0"), ("fffffd1f", "#8w1"),
                   ("00070000", "#8w2"), ("fdda97ce", "W0"),
                   ("00000019", "x19"), ("000000c0", "xc0"),
                   ("00000090", "x90")):
    loc = Counter()
    for e in L:
        if be4(e[2] & 0xFFFFFFFF) == target:
            loc[(e[0], e[1])] += 1
    tot = sum(loc.values())
    print("== %s=%s total=%d distinct=%d ==" % (nm, target, tot, len(loc)))
    for (st, n), k in loc.most_common(10):
        print("   %dx %s slot=%s" % (k, st, n))
