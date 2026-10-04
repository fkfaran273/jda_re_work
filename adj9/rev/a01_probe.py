"""a01_probe.py - a[0]/a[1] internal structure: sparse bitfield + small int?

ent_probe: a0 popcount 2.4 (bits {0,1,2,4,5,7,8,10,15,16,17,18,20,25,26}),
a1 popcount 4.5. Hypotheses:
  1. a0 = bitmask over claim-presence (which optional claims in #10)?
  2. a0/a1 as LE u16 pairs = small ints? (lengths/counts?)
  3. a0 vs claims_len: a0 == f(len)? a1 == g(len)?
  4. a1 vs a0: is a1 a function of a0 (same row)?
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
def words(h, n):
    raw = bytes.fromhex(h)
    return [int.from_bytes(raw[j:j+4], "big") for j in range(0, 4*n, 4)]
print("row  claims  a0         a1         a0le0 a0le1 a1le0 a1le1")
for i, x in enumerate(S):
    a = words(x["d4"], 8)
    cl = len(bytes.fromhex(x["d10"]))
    b0 = a[0].to_bytes(4, "big"); b1 = a[1].to_bytes(4, "big")
    print("  [%d]  %-6d %08x   %08x   %-5d %-5d %-5d %-5d  bits=%s" % (
        i, cl, a[0], a[1],
        int.from_bytes(b0[0:2], "little"), int.from_bytes(b0[2:4], "little"),
        int.from_bytes(b1[0:2], "little"), int.from_bytes(b1[2:4], "little"),
        sorted(b for b in range(32) if (a[0] >> b) & 1)))
a = words(A["d4"], 8)
print("  [app] 360    %08x   %08x  bits=%s" % (a[0], a[1], sorted(b for b in range(32) if (a[0] >> b) & 1)))
print()
print("a0 distinct:", len(set(words(x["d4"], 1)[0] for x in S + [{"d4": A["d4"]}])))
print("a1 distinct:", len(set(words(x["d4"], 2)[1] for x in S + [{"d4": A["d4"]}])))
