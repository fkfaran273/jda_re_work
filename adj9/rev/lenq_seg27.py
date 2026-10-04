"""lenq_seg27.py - which LENQ reads belong to seg27's own signing?

Problem: app_dump.json has NO timestamps on LENQ reads, and streams are
reused across signings (the 16k-read ..4380 walks everything). So isolate
by VALUE: reads returning seg27's own descriptor words.

For each seg27 role value, list (stream, slot) pairs that ever return it,
with total read counts. A concentrated (stream,slot) for MANY role words =
the memory/descriptor table this signing actually reads.
"""
import json, os, sys
from collections import Counter, defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
L = d.get("lenq", [])


def be4(v):
    return "%08x" % (v & 0xFFFFFFFF)


# seg27 descriptor words (EMIT plane)
TILE = ["fdda97ce", "b559bc7d", "4f8635e7", "c61cd669", "3cc346a2"]
A4 = ["00010201", "00080801", "08882281", "4a0962c8", "6898201b",
      "72ca1951", "7345899a", "f3fba7a0"]
D2C, D7 = "cd9d3a91", "00000183"
KEYS = set(TILE + A4 + [D2C, D7, "4b6c6341", "fad0f10d"])
print("role values: %d" % len(KEYS))
loc = defaultdict(Counter)   # value -> Counter((st,slot))
for e in L:
    v = be4(e[2] & 0xFFFFFFFF)
    if v in KEYS:
        loc[v][(e[0], e[1])] += 1
for v in sorted(KEYS):
    c = loc[v]
    tot = sum(c.values())
    print("== %s total=%d distinct-slots=%d ==" % (v, tot, len(c)))
    for (st, n), k in c.most_common(12):
        print("   %dx %s slot=%s" % (k, st, n))
