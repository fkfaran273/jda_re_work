"""gold_map.py - learn the stream->descriptor identification rule from the GOLDEN
capture (device/whcap_hits7.json), where fin_descs.json gives ground truth.

Golden: fin_descs[#0] = 13271271 db50f44c ...  -> the capture shows an EMIT stream
whose pos 0..2 values are exactly those. So find, per sink, (count, first words)
and match against fin_descs to fix the rule; then apply the same rule to our own
capture (rev/wh_out.json).
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.stdout.reconfigure(line_buffering=True)

cap = json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
desc = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))

S = {}
for r in cap:
    if r.get("tag") != "emit":
        continue
    sink = int(r["sink"], 16)
    S.setdefault(sink, {})[int(r["pos"], 16)] = int(r["val"], 16)

print("golden capture: %d emits, %d sinks" % (sum(len(v) for v in S.values()), len(S)))
print()
print("--- sinks (count, first 4 values) ---")
byc = {}
for sink, m in sorted(S.items(), key=lambda kv: -len(kv[1])):
    vs = [m[k] for k in sorted(m)]
    byc.setdefault(len(vs), []).append((sink, vs))
    print("  %-16s count=%-4d first=%s" %
          (("%x" % sink)[-8:], len(vs), ["%08x" % x for x in vs[:4]]))

print()
print("--- fin_descs ground truth (build_idx, len_dw, first 4 words as BE) ---")
for x in desc["descs"]:
    dh = x["data_hex"]
    w = [int(dh[i:i + 8], 16) for i in range(0, min(32, len(dh)), 8)]
    print("  #%-2d len_dw=%-4d first=%s" % (x["build_idx"], x["len_dw"],
                                            ["%08x" % y for y in w]))
print()
print("--- matching: descriptor -> sink (by length + first word) ---")
for x in desc["descs"]:
    dh = x["data_hex"]
    ln = x["len_dw"]
    first = int(dh[:8], 16) if len(dh) >= 8 else None
    cands = []
    for sink, vs in byc.get(ln, []):
        if first is None or vs[0] == first:
            cands.append(("%x" % sink)[-8:])
    print("  #%-2d len_dw=%-4d first=%s -> sinks %s" %
          (x["build_idx"], ln, "%08x" % first if first else "-", cands or "NONE"))