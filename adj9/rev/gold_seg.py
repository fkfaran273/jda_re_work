"""gold_seg.py - segment the golden capture per signing and print the ROLE TABLE:
which sink/stream plays which descriptor's role, using fin_descs.json as truth.

Segmentation rule (this data): a new signing starts when a sink that already has a
recorded pos>0 in the current segment is written again at pos 0.  Sink addresses are
recycled between signings, so unsegmented grouping mixes signings (that is why the
naive grouping showed two 36-slot streams and a 113-slot "CONST9" stream).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.stdout.reconfigure(line_buffering=True)

cap = [r for r in json.load(open(os.path.join(DEV, "whcap_hits7.json"), encoding="utf-8"))
       if isinstance(r, dict) and r.get("tag") == "emit"]
desc = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))

segs = []
cur = {}
for r in cap:
    sink = int(r["sink"], 16)
    pos = int(r["pos"], 16)
    if pos == 0 and sink in cur and cur[sink]:
        segs.append(cur)
        cur = {}
    cur.setdefault(sink, {})[pos] = int(r["val"], 16)
segs.append(cur)
print("segments: %d  (emits per segment: %s)" %
      (len(segs), [sum(len(v) for v in s.values()) for s in segs][:12]))

truth = {}
for x in desc["descs"]:
    dh = x["data_hex"]
    truth[x["build_idx"]] = (x["len_dw"], int(dh[:8], 16) if len(dh) >= 8 else None)


def role_table(seg, label):
    print()
    print("=== %s ===" % label)
    rows = []
    for sink, m in seg.items():
        vs = [m[k] for k in sorted(m)]
        rows.append((len(vs), vs[0], vs[:4], sink))
    rows.sort(key=lambda r: -r[0])
    for cnt, v0, first, sink in rows:
        tag = ""
        for bidx, (ln, fw) in truth.items():
            if ln == cnt and fw == v0:
                tag = " <= fin_descs #%d" % bidx
        print("  count=%-4d first=%08x %s%s" %
              (cnt, v0, ["%08x" % y for y in first], tag))
    return rows


rows = role_table(segs[0], "SEGMENT 0 (first signing)")
print()
print("--- fin_descs truth vs segment 0 ---")
for bidx in sorted(truth):
    ln, fw = truth[bidx]
    hit = [r for r in rows if r[0] == ln and (fw is None or r[1] == fw)]
    print("  #%-2d len_dw=%-4d first=%s -> %s" %
          (bidx, ln, "%08x" % fw if fw else "-",
           ["count=%d first=%08x" % (r[0], r[1]) for r in hit] or "NOT FOUND"))
# also: which streams does fin_descs #0's content get COPIED into?
z0 = [int(desc["descs"][0]["data_hex"][i:i + 8], 16) for i in range(0, 32, 8)]
print()
print("--- writes of #0's first word (%08x) in segment 0 ---" % z0[0])
for sink, m in segs[0].items():
    for pos, v in sorted(m.items()):
        if v == z0[0]:
            print("   sink %s pos %d" % (("%x" % sink)[-8:], pos))