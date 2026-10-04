# h_in_trace.py - DOES THE VM CONSUME THE KEYSTORE MAC AT ALL?
#
# The device log gives, for the golden signing (nsign ts 1789240514238, blob
# verified identical):
#     H = arg3 = 2236e4e66d0e2968289f2aa32e8006ad43b8b197bc103e24d9903afc5b157ede
#     descriptor #4 = 00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e
# and #4 != H (device's own pairing, rev/gold_h.log). This script searches the
# Frida EMIT trace for H's dwords, which decides whether the 192-byte blob is
# KEYED by the TEE MAC (then no offline forging is possible) or not (then the
# remaining inputs are the per-call descriptors only).
import json
import os
import re
import struct
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
H = "2236e4e66d0e2968289f2aa32e8006ad43b8b197bc103e24d9903afc5b157ede"
D4 = "00100400041440008000c44088104c050025c852cc6e00b101e76c80427bf58e"
F = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))
T = F["target"]
GOLD = T["blob_hex"]


def words(hx):
    return [hx[i:i + 8] for i in range(0, len(hx), 8)]


search = {"H(arg3)": words(H), "#4(descriptor)": words(D4),
          "golden blob": words(GOLD)}

d = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
evs = [e for e in d if isinstance(e, dict) and e.get("tag") == "emit"]
print("emit events: %d" % len(evs))
print("event keys: %s" % sorted(evs[0].keys()))
print("sample: %s" % json.dumps(evs[0]))

vals = [int(e["val"], 16) for e in evs]
cnt = Counter(vals)
print("\n=== do these values occur in the trace? ===")
for name, ws in search.items():
    hits = [(w, cnt.get(int(w, 16), 0)) for w in ws]
    present = sum(1 for _, n in hits if n)
    print("  %-16s dwords present in trace: %d/%d  %s"
          % (name, present, len(ws),
             " ".join("%s:%d" % (w[:8], n) for w, n in hits[:8])))
    if present and present < len(ws):
        missing = [w for w, n in hits if not n]
        print("      missing: %s" % " ".join(m[:8] for m in missing))

# ---- ordering: where do the golden blob's dwords sit in the stream? ---------
print("\n=== the golden blob's dwords in stream order (first 24) ===")
gw = words(GOLD)
idx = {}
for i, v in enumerate(vals):
    idx.setdefault("%08x" % v, []).append(i)
for k, w in enumerate(gw[:24]):
    print("  dword %2d %s  at %s" % (k, w, idx.get(w, [])[:3]))