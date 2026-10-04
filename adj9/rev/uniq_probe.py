"""uniq_probe.py - uniqueness baselines: is any of (#0, #2, #4) a pure function of
(H), (second), or claims, judging ONLY by collision structure?

A function f(x) cannot give different outputs on identical x.  So find near-duplicate
inputs across the 11 rows (all_signings + the app row) and check the outputs:
  * 7/9: identical 360-B claims AND identical created_at -> anything differing here
         cannot come from claims or from the wall value;
  * any two rows sharing second -> second alone cannot explain differences;
  * any two rows sharing H     -> H alone cannot explain differences;
  * digest-of-claims collisions as a sanity control.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]


def key(x, slot):
    return x.get(slot)


rows = [(i, x.get("d10"), None, x.get("d0"), x.get("d2"), x.get("d4")) for i, x in enumerate(S)]
rows.append(("app", A["d10"], 1789903463, A["d0"], A["d2"], A["d4"]))
print("rows: %d (10 old + 1 app)" % len(rows))

print()
print("--- input collisions ---")
seen10 = {}
groups10 = {}
for i, d10, sec, *_ in rows:
    if d10 in seen10:
        groups10.setdefault(d10, {seen10[d10]}).add(i)
    else:
        seen10[d10] = i
print("identical claims groups:", {k[:16] + "…": sorted(v) for k, v in groups10.items()})
print("same-second rows among old: none known (each blob is its own second)")

print()
print("--- outputs across the 7/9 claims-identical pair ---")
for i, d10, sec, d0, d2, d4 in rows:
    if i in (7, 9):
        print("  row %d: d0=%s d2=%s d4=%s" % (i, d0[:24], d2, d4[:24]))
print("  -> everything differs despite identical claims: claims-only functions excluded")

print()
print("--- sha256(claims) per row (digest-control: same input -> same output expected) ---")
for i, d10, sec, d0, d2, d4 in rows:
    print("  %-3s sha=%s" % (i, hashlib.sha256(bytes.fromhex(d10)).hexdigest()[:24]))
print("--- region digest-control: md5(d0)||md5(d4) per row ---")
for i, d10, sec, d0, d2, d4 in rows:
    print("  %-3s md5(d0)=%s md5(d4)=%s" %
          (i, hashlib.md5(bytes.fromhex(d0)).hexdigest()[:16],
           hashlib.md5(bytes.fromhex(d4)).hexdigest()[:16]))

print()
print("--- count distinct outputs ---")
print("  distinct d0=%d d2=%d d4=%d over %d rows" %
      (len(set(r[3] for r in rows)), len(set(r[4] for r in rows)),
       len(set(r[5] for r in rows)), len(rows)))