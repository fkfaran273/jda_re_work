"""tilewalk_probe.py - tile XOR-walk structure + #4 vs stream bookkeeping + #2 membership.

1. Per row: K02 = tile2^tile0, K13 = tile3^tile1. Constant within row? Shared
   high bits across rows? K vs H/second?
2. #2 membership: does #2 appear (BE or LE dword) in its own blob / H / claims?
3. For app_dump.json seg0: stream acc (=max slot+1) per stream vs #4 words.
4. #4[0] bit positions across all 11 rows.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
M = 0xFFFFFFFF
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
A = json.load(open(os.path.join(HERE, "app_signings.json"), encoding="utf-8"))[0]
R = {r["i"]: r for r in
     json.load(open(os.path.join(HERE, "pair_h3.json"), encoding="utf-8"))}


def be(hexs, n=None):
    raw = bytes.fromhex(hexs)
    if n is None:
        n = len(raw) // 4
    return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, 4 * n, 4)]


def bits(v):
    return [b for b in range(32) if (v >> b) & 1]


print("--- 1. tile XOR-walk ---")
for i, x in enumerate(S):
    t = be(x["d0"])[1:5]
    k02, k13 = (t[2] ^ t[0]) & M, (t[3] ^ t[1]) & M
    print("  [%d] K02=%08x K13=%08x same=%s W0^t0=%08x" %
          (i, k02, k13, k02 == k13, (be(x["d0"])[0] ^ t[0]) & M))
ta = be(A["d0"])[1:5]
print("  [app] K02=%08x K13=%08x" % ((ta[2] ^ ta[0]) & M, (ta[3] ^ ta[1]) & M))

print()
print("--- 2. #2 membership in blob/H/claims (BE+LE dwords) ---")
for i, x in enumerate(S):
    d2 = int(x["d2"], 16)
    blob = bytes.fromhex(R[i]["blob"]) if i in R and R[i].get("blob") else b""
    H = bytes.fromhex(R[i]["H"]) if i in R and R[i].get("H") else b""
    cl = bytes.fromhex(x["d10"])
    f = []
    for nm, buf in (("blob", blob), ("H", H), ("claims", cl)):
        if not buf:
            continue
        dw_be = {int.from_bytes(buf[j:j + 4], "big") for j in range(0, len(buf) - 3)}
        dw_le = {int.from_bytes(buf[j:j + 4], "little") for j in range(0, len(buf) - 3)}
        if d2 in dw_be:
            f.append(nm + "-be")
        if d2 in dw_le:
            f.append(nm + "-le")
    # also unaligned byte-substring anywhere?
    b2 = d2.to_bytes(4, "big")
    sub = [nm for nm, buf in (("blob", blob), ("H", H), ("claims", cl))
           if buf and b2 in buf]
    print("  [%d] #2=%08x dword-hit=%s bytesub=%s" % (i, d2, f or "none", sub or "none"))

print()
print("--- 3. app seg0 stream acc vs #4 words ---")
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
segs, cur = [], {}
for st, n, v in d["emits"]:
    if n == 0 and st in cur and cur[st]:
        segs.append(cur)
        cur = {}
    cur.setdefault(st, {})[n] = v
segs.append(cur)
seg = segs[0]
acc = {}
for st, m in seg.items():
    ks = sorted(m)
    acc[len(m)] = acc.get(len(m), []) + [(st, max(ks) + 1)]
a4 = be(A["d4"], 8)
print("  #4 =", ["%08x" % v for v in a4])
print("  stream sizes present:", sorted(acc))
for cnt in sorted(acc):
    print("    size %3d: %s" % (cnt, [(hex(st), a) for st, a in acc[cnt][:8]]))
hit = [v for v in a4 if any(v == a for lst in acc.values() for _, a in lst)]
print("  #4 words equal to some stream acc:", ["%08x" % v for v in hit] or "none")
hit2 = [v for v in a4 if any((v & 0xFFFF) == (a & 0xFFFF) for lst in acc.values() for _, a in lst)]
print("  #4 words sharing low16 with some acc:", ["%08x" % v for v in hit2] or "none")

print()
print("--- 4. #4[0] bit positions, all 11 rows ---")
for i, x in enumerate(S):
    print("  [%d] %08x bits=%s" % (i, be(x["d4"], 1)[0], bits(be(x["d4"], 1)[0])))
print("  [app] %08x bits=%s" % (be(A["d4"], 1)[0], bits(be(A["d4"], 1)[0])))
