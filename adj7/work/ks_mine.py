"""ks_mine.py — all-chunk key extraction + schedule-window mining from the
EXISTING v3_writes.txt (line number = write counter since the 8th rand) and
v9_ops.txt (col0 + 5300000 = wc at op dispatch).

    python ks_mine.py
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX, AES_INV, CHUNK0_KEYS, mix_columns, shift_rows

blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
IV = blob[:16]
CELL0 = 0x900F09C                                    # + 0x40 per chunk

ops = []
for line in open(os.path.join(HERE, "v9_ops.txt")):
    a, b = line.split()
    ops.append((int(a) + 5300000, int(b, 16)))
s1161 = [i for i, (w, o) in enumerate(ops) if o == 0x1161]
assert len(s1161) == 16, s1161

# windows: round phase = first 268 ops from 0x1161; schedule phase = the rest
round_win = []    # (k, lo, hi) inclusive wc bounds
sched_win = []
for k in range(16):
    i0 = s1161[k]
    i1 = s1161[k + 1] if k < 15 else len(ops)
    round_win.append((k, ops[i0][0], ops[min(i0 + 267, i1 - 1)][0]))
    sched_win.append((k, ops[min(i0 + 267, i1 - 1)][0] + 1,
                      ops[i1 - 1][0] if k < 15 else 10 ** 12))
print("round windows:", [(k, lo, hi) for k, lo, hi in round_win[:3]], "...")

# single pass over v3_writes.txt, line idx (1-based) = wc
rd = {k: [] for k in range(16)}
sd = {k: [] for k in range(16)}
wi = 0
nr = ns = len(round_win), len(sched_win)
cur_r, cur_s = 0, 0
with open(os.path.join(HERE, "v3_writes.txt")) as f:
    wc = 0
    for line in f:
        wc += 1
        a, s, v = line.split()
        a = int(a, 16)
        while cur_r < 16 and wc > round_win[cur_r][2]:
            cur_r += 1
        if cur_r < 16 and wc >= round_win[cur_r][1]:
            base = CELL0 + 0x40 * cur_r
            if base <= a < base + 64:
                rd[cur_r].append((wc, a, int(v, 16)))
        while cur_s < 16 and wc > sched_win[cur_s][2]:
            cur_s += 1
        if cur_s < 16 and wc >= sched_win[cur_s][1] and a >= 0x9000000 \
                and a < 0x9020000:
            sd[cur_s].append((wc, a, int(v, 16)))
print("state writes per chunk:", {k: len(v) for k, v in rd.items()})
print("sched writes per chunk:", {k: len(v) for k, v in sd.items()})

# ---- replay each chunk's rounds ----
def replay(k, chunk_in, chunk_out):
    hist = rd[k]
    cells = [CELL0 + 0x40 * k + 4 * i for i in range(16)]
    i0 = s1161[k]
    cw = ops[i0:i0 + 268]
    cur, si, snap = {}, 0, []
    for i in range(len(cw) - 1):
        w1 = cw[i + 1][0]
        while si < len(hist) and hist[si][0] < w1:
            cur[hist[si][1]] = hist[si][2]
            si += 1
        snap.append((cw[i][1], bytes(cur.get(a, 0) for a in cells)))
    R, r = [], None
    for o, sv in snap:
        if o == 0x1161:
            R.append({"init": sv}); r = R[-1]
        elif o == 0x1168:
            r = {"sr_in": sv}; R.append(r)
        elif o == 0x116D:
            r["post_sr"] = sv
        elif o in (0x1312, 0x1341, 0x1372, 0x13A5):
            r.setdefault("quad", []).append((o, sv))
        elif o == 0x1172:
            r["m1"] = sv
        elif o == 0x1177:
            r["m2"] = sv
        elif o == 0x117E:
            R.append({"sr_in": sv, "tail": True}); r = R[-1]
        elif o == 0x1183:
            r["m1"] = sv
        elif o == 0x1188:
            r["end"] = sv
    ks = [bytes(a ^ AES_INV[b] for a, b in zip(chunk_in, R[0]["init"]))]
    for rd_ in [x for x in R[1:] if "quad" in x]:
        qout = rd_["quad"][-1][1]
        ks.append(bytes(AES_INV[rd_["m2"][i]] ^ qout[i] for i in range(16)))
    t = [x for x in R if x.get("tail")]
    tail_m1 = t[0]["m1"] if t else None
    return ks, R, tail_m1


allk = {}
for k in range(16):
    cin = IV if k == 0 else blob[16 * k:16 * k + 16]
    cout = blob[16 + 16 * k:32 + 16 * k]
    ks, R, tail_m1 = replay(k, cin, cout)
    allk[k] = [x.hex() for x in ks]
    rounds = [x for x in R[1:] if "quad" in x]
    m2_13 = rounds[-1]["m2"] if rounds else None
    k14 = bytes(a ^ b for a, b in zip(tail_m1, shift_rows(m2_13))) \
        if tail_m1 and m2_13 else None
    print("chunk %2d: keys=%2d K14(m1^SR(m2_13))=%s"
          % (k, len(ks), k14.hex() if k14 else None))

gt = [x.hex() for x in CHUNK0_KEYS]
print("chunk0 K0..K13 match ground truth:", allk[0][:14] == gt[:14])
json.dump({"keys": allk}, open(os.path.join(HERE, "ks_all2.json"), "w"),
          indent=1)

# ---- schedule-phase write summary (chunk 0's schedule = for chunk 1) ----
from collections import Counter
w = sd[0]
addrs = Counter(a for _, a, _ in w)
print("\nchunk-0 schedule phase: %d writes, %d distinct addrs"
      % (len(w), len(addrs)))
for a, c in addrs.most_common(12):
    print("   %#x x%d" % (a, c))
json.dump({str(k): [(hex(a), s, hex(v)) for _, a, s, v in
                    [(0, a, 4, v) for _, a, v in sd[k]]][:4000]
           for k in sd},
          open(os.path.join(HERE, "sched_writes.json"), "w"))
print("wrote ks_all2.json + sched_writes.json")
