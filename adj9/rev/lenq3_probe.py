"""lenq3_probe.py - WHERE is the true #2 read? per-signing LENQ drill-down.

lenq2 found:
  * 233 stable (stream,slot)->value slots (reads>=5, 1 value) on the main
    stream 0x...3300 -- but values are small indices (queue positions).
  * stream 0x...4e30 (204 reads): top values b559bc7d/4f8635e7/c61cd669 =
    seg27's OWN #0 tile words (10 reads each) + 00010201 (a[6]hi's word, 4x):
    THIS stream walks the descriptor memory of seg27's signing.
  * seg27 role values ARE LENQ-read: d2cand 5x, a6hi-word 11x.
This probe: dump every read of stream 0x...4e30 (slot->value, in order) and
of any stream whose reads include d2cand/cd9d3a91, plus all slots that ever
returned a seg27 tile/#4 word. Goal: the exact read sequence that feeds #2.
"""
import json, os, sys
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
L = d.get("lenq", [])


def be4(v):
    return "%08x" % (v & 0xFFFFFFFF)


# seg27 roles
TILE = ["fdda97ce", "b559bc7d", "4f8635e7", "c61cd669"]
A4 = ["00010201", "00080801", "08882281", "4a0962c8", "2488c810",
      "6828a4c9", "5b422d6e", "8dcf8081"]
D2C = 0xcd9d3a91
KEYS = set(TILE + A4 + ["%08x" % D2C, "4b6c6341"])
print("key roles:", sorted(KEYS))
streams = sorted(set(e[0] for e in L))
print("streams:", len(streams))
for st in streams:
    reads = [(e[1], e[2] & 0xFFFFFFFF) for e in L if e[0] == st]
    hit = [(n, v) for n, v in reads if be4(v) in KEYS]
    if hit:
        print("--- stream %s reads=%d keyhits=%d ---" % (st, len(reads), len(hit)))
        for n, v in hit[:60]:
            print("   slot=%s val=%s" % (n, be4(v)))
# all reads returning d2cand, with stream context
print("--- every read returning d2cand ---")
for e in L:
    if (e[2] & 0xFFFFFFFF) == D2C:
        print("   stream=%s slot=%s" % (e[0], e[1]))
# slots on stream 4e30 that returned tile words, in read order
print("--- stream ..4e30 full read order (first 120) ---")
for e in L:
    if str(e[0]).endswith("4e30"):
        print("   slot=%s val=%s%s" % (e[1], be4(e[2] & 0xFFFFFFFF),
              "  <--KEY" if be4(e[2] & 0xFFFFFFFF) in KEYS else ""))
        break
n = 0
for e in L:
    if str(e[0]).endswith("4e30"):
        if n >= 1:
            print("   slot=%s val=%s%s" % (e[1], be4(e[2] & 0xFFFFFFFF),
                  "  <--KEY" if be4(e[2] & 0xFFFFFFFF) in KEYS else ""))
        n += 1
        if n > 120:
            print("   ... (truncated, total %d)" % sum(1 for x in L if str(x[0]).endswith("4e30")))
            break
