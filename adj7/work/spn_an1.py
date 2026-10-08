"""spn_an1.py — analyse the SPN round data from spn_footprint.txt + captures.

Extracts:
  A. the 254-byte per-iteration stream of chunk 0's 255-loop (pc 0x5102b4)
  B. the 13-round quad-op (in,out) maps, 0x1172/0x1177 I/O, tail I/O (chunk 0)
Then tests hypotheses: multiset vs KB362, GF(2^8) chains, AES MixColumns.
"""
import json
import os
import struct
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

KB = json.load(open(os.path.join(WORK, "adj7s4_immruns.json")))["d20a0"]
KBLE = b"".join(struct.pack("<I", w) for w in KB)

BLOB = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
IV = BLOB[:16]
C0 = BLOB[16:32]

CELLS = list(range(0x900f09c, 0x900f0dc, 4))


def load_footprint():
    st = []
    for line in open(os.path.join(HERE, "spn_footprint.txt")):
        f = line.split()
        if len(f) < 4 or f[1] != "W":
            continue
        st.append((int(f[0]), int(f[2].split("=")[1], 16),
                   int(f[3].split("=")[1], 16),
                   int(f[4].split("=")[1], 16) if len(f) > 4 else None))
    return st


def shiftrows(b):
    """observed 0x1168 law: new M[r][c] = old M[(r+c)%4][c], M[r][c]=b[4r+c]"""
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)


def gmul(a, b, poly):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= poly
        b >>= 1
    return p


def main():
    st = load_footprint()
    print("=== A. 255-loop per-iteration stream (pc 5102b4) ===")
    tbl = [s for s in st if s[1] == 0x5102B4 and 5418404 <= s[0] <= 6148189]
    vals = [s[3] for s in tbl]
    print("n =", len(vals))
    cnt = Counter(vals)
    dups = {k: v for k, v in cnt.items() if v > 1}
    missing = [v for v in range(256) if v not in cnt]
    print("dups:", dups, "missing:", missing)
    kbset = Counter(KBLE)
    print("multiset == KB362_LE multiset:", cnt == kbset)
    # which KB bytes are missing / extra
    extra = cnt - kbset
    lack = kbset - cnt
    print("vs KB: extra:", dict(extra), " missing-vs-kb:", dict(lack))
    # GF chain test: v[i+1] = g * v[i] for all 30 odd polys, all g
    polys = [0x11b, 0x11d, 0x12b, 0x12d, 0x139, 0x13f, 0x14d, 0x15f, 0x163,
             0x165, 0x169, 0x171, 0x177, 0x17b, 0x187, 0x18b, 0x18d, 0x19f,
             0x1a3, 0x1a9, 0x1b1, 0x1bd, 0x1c3, 0x1cf, 0x1d7, 0x1dd, 0x1e7,
             0x1f3, 0x1f5, 0x1f9]
    hit = None
    for poly in polys:
        for g in range(2, 256):
            ok = all(gmul(vals[i], g, poly) == vals[i + 1] for i in range(20))
            if ok:
                hit = (poly, g)
                break
        if hit:
            break
    print("GF chain hit (first 20):", hit)
    if hit:
        poly, g = hit
        okall = all(gmul(vals[i], g, poly) == vals[i + 1]
                    for i in range(len(vals) - 1))
        print("  full chain consistent:", okall)
    # integer chain mod 255 / 256
    for m in (255, 256, 251, 257):
        for g in range(2, m):
            if all(vals[i] * g % m == vals[i + 1] for i in range(20)):
                print("int chain mod %d g=%d" % (m, g))
                break

    print()
    print("=== B. chunk-0 round data ===")
    cells = set(CELLS)
    hist = [(wc, a, v) for wc, pc, a, v in st
            if a in cells and 6100000 <= wc <= 6640000]
    hist.sort()
    # replay through op boundaries
    ops = [(int(a) + 5300000, int(b, 16)) for a, b in
           (l.split() for l in open(os.path.join(HERE, "v9_ops.txt")))]
    c0 = ops[1022:1290]
    state = {}
    si = 0
    for wc, a, v in hist:
        if wc < c0[0][0]:
            state[a] = v
    cur = dict(state)
    si = sum(1 for h in hist if h[0] < c0[0][0])
    rounds = []   # per round: dict with sr_in, quad_in/out per op, m1_out, m2_out
    snap = []
    for i in range(len(c0) - 1):
        w0, o0 = c0[i]
        w1 = c0[i + 1][0]
        while si < len(hist) and hist[si][0] < w1:
            _, a, v = hist[si]
            cur[a] = v
            si += 1
        snap.append((o0, bytes(cur.get(a, 0) for a in CELLS)))
    # organise by round
    R = []
    r = None
    for o, sv in snap:
        if o == 0x1161:
            R.append({"init": sv})
            r = R[-1]
        elif o == 0x1168:
            r = {"sr_in": sv}
            R.append(r)
        elif o == 0x116d:
            r["post_sr"] = sv
        elif o in (0x1312, 0x1341, 0x1372, 0x13A5):
            r.setdefault("quad", []).append((o, sv))
        elif o == 0x1172:
            r["m1"] = sv
        elif o == 0x1177:
            r["m2"] = sv
        elif o == 0x117E:
            R.append({"sr_in": sv, "tail": True})
            r = R[-1]
        elif o == 0x1183:
            r["m1"] = sv
        elif o == 0x1188:
            r["end"] = sv
    # quad layer input = post_sr? note: 0x116d makes no buffer change, so
    # quad input (per buffer) = post_sr
    print("rounds parsed:", len(R))
    # op maps: for op c, samples (in_byte, out_byte) per round
    maps = {0x1312: [], 0x1341: [], 0x1372: [], 0x13A5: []}
    for rd in R:
        if "tail" in rd or "quad" not in rd:
            continue
        pre = rd["post_sr"]
        for c, (o, sv) in enumerate(rd["quad"]):
            # quad index = c//4, op-in-quad = c%4; cell = 4*(c//4) + (c%4)
            cell = 4 * (c // 4) + (c % 4)
            maps[o].append((pre[cell], sv[cell]))
    for o, mp in maps.items():
        xor_same = all((a ^ b) == (mp[0][0] ^ mp[0][1]) for a, b in mp)
        print("op %#06x: %d samples; constant-xor: %s (xor=%02x)"
              % (o, len(mp), xor_same, mp[0][0] ^ mp[0][1]))
    # 0x1172 mix: check AES MixColumns on columns
    AESM = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    def mixcol_aes(col, mat=AESM, poly=0x11B):
        return bytes(sum(gmul(col[j], mat[i][j], poly)
                         for j in range(4)) & 0xFF for i in range(4))
    ok = 0
    tot = 0
    for rd in R:
        if "m1" not in rd or "quad" not in rd:
            continue
        qout = rd["quad"][-1][1]
        for c in range(4):
            col = bytes(qout[4 * r_ + c] for r_ in range(4))
            ocol = bytes(rd["m1"][4 * r_ + c] for r_ in range(4))
            tot += 1
            if mixcol_aes(col) == ocol:
                ok += 1
    print("0x1172 == AES MixColumns: %d/%d columns" % (ok, tot))
    # tail 0x1183
    tail = [rd for rd in R if rd.get("tail")]
    if tail:
        rd = tail[0]
        ok2 = 0
        for c in range(4):
            col = bytes(rd["sr_in"][4 * r_ + c] for r_ in range(4))
            ocol = bytes(rd["m1"][4 * r_ + c] for r_ in range(4))
            if mixcol_aes(col) == ocol:
                ok2 += 1
        print("0x1183 == AES MixColumns: %d/4" % ok2)
        print("tail: sr_in", rd["sr_in"].hex())
        print("      m1   ", rd["m1"].hex(), " C0 =", C0.hex())
    # 0x1177 xor keys
    print("\n0x1177 candidate round keys (xor of in/out):")
    ks = []
    for rd in R:
        if "m1" in rd and "m2" in rd and "quad" in rd:
            k = bytes(a ^ b for a, b in zip(rd["m1"], rd["m2"]))
            ks.append(k)
    for i, k in enumerate(ks):
        off = KBLE.find(k)
        print("  r%02d %s  inKB@%s" % (i + 1, k.hex(), off))
    # init relation
    r1 = R[0]
    print("\nS_init =", r1["init"].hex())
    sr_init = shiftrows(r1["init"])
    print("ShiftRows(S_init) =", sr_init.hex())
    xk = bytes(a ^ b for a, b in zip(r1["init"], IV))
    off = KBLE.find(xk)
    print("S_init^IV in KB at", off)
    xk2 = bytes(a ^ b for a, b in zip(sr_init, IV))
    print("SR(S_init)^IV in KB at", KBLE.find(xk2))


if __name__ == "__main__":
    main()
