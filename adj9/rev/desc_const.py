"""desc_const.py - are any descriptors CONSTANT across the 10 real signings?

If #9 (20 B) and #8 (16 B) are fixed tables, they can simply be hardcoded in an
offline signer; that removes two of the five unknowns.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
slots = ["d0", "d9", "d8", "d4", "d2", "d7", "d10", "d5", "d6"]
print("%-5s %-8s %-8s %s" % ("slot", "distinct", "len(B)", "values"))
for s in slots:
    vals = [x.get(s) for x in S]
    uniq = []
    for v in vals:
        if v not in uniq:
            uniq.append(v)
    ln = len(uniq[0]) // 2 if uniq and uniq[0] else 0
    show = uniq if len(uniq) <= 4 else uniq[:3] + ["..."]
    print("%-5s %-8d %-8d %s" % (s, len(uniq), ln, [str(v)[:48] for v in show]))

print()
print("--- per-signing summary ---")
for i, x in enumerate(S):
    print("  [%d] %-16s d7=%-9s d2=%-9s d4=%-9s d0=%s..." %
          (i, x.get("src", "")[:16], x.get("d7"), x.get("d2"),
           (x.get("d4") or "")[:8], (x.get("d0") or "")[:8]))
print()
print("constancy: #9 %s | #8 %s | #5 %s | #6 %s" %
      (len(set(x.get("d9") for x in S)) == 1,
       len(set(x.get("d8") for x in S)) == 1,
       len(set(x.get("d5") for x in S)) == 1,
       len(set(x.get("d6") for x in S)) == 1))
# d7 vs claims length
print()
print("--- d7 vs d10 length ---")
for i, x in enumerate(S):
    dl = len(x.get("d10") or "") // 2
    print("  [%d] d7=%s (=%d)  d10=%dB" %
          (i, x.get("d7"), int(x.get("d7") or "0", 16), dl))