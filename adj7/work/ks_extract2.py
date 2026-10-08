"""ks_extract2.py — corrected all-chunk key extraction (round-op windows only).

K0  = P_k ^ AES_INV(S_init)
K_r = AES_INV(m2_r) ^ MixColumns(ShiftRows(m2_{r-1}))   r = 1..13
K14 = AES_INV(wire) ^ ShiftRows(m2_13)

    python ks_extract2.py
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import (AES_SBOX, AES_INV, CHUNK0_KEYS, mix_columns,
                       shift_rows, spn_chunk)

blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
IV = blob[:16]

ops = []
for line in open(os.path.join(HERE, "v9_ops.txt")):
    a, b = line.split()
    ops.append((int(a) + 5300000, int(b, 16)))

stores = []
for line in open(os.path.join(HERE, "spn_footprint.txt")):
    f = line.split()
    if len(f) < 5 or f[1] != "W":
        continue
    stores.append((int(f[0]), int(f[3].split("=")[1], 16),
                   int(f[4].split("=")[1], 16)))
stores.sort()


def states_for_chunk(k):
    cell0 = 0x900F09C + 0x40 * k
    cells = [cell0 + 4 * i for i in range(16)]
    c0i = 1022 + 1287 * k
    cw = ops[c0i:c0i + 268]          # round ops only
    wc_lo, wc_hi = cw[0][0], cw[-1][0]
    hist = [(wc, a, v) for wc, a, v in stores
            if wc_lo <= wc <= wc_hi and a in cells]
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
    return R


def keys_for_chunk(k, cin, cout):
    R = states_for_chunk(k)
    ks = [bytes(a ^ AES_INV[b] for a, b in zip(cin, R[0]["init"]))]
    for rd in [rd for rd in R[1:] if "quad" in rd]:
        qout = rd["quad"][-1][1]
        ks.append(bytes(AES_INV[rd["m2"][i]] ^ qout[i] for i in range(16)))
    t = [rd for rd in R if rd.get("tail")]
    if t:
        ks.append(bytes(AES_INV[t[0]["m1"][i]]
                        ^ shift_rows(t[0]["sr_in"])[i] for i in range(16)))
    return ks, R


allk, meta = {}, {}
for k in range(16):
    cin = IV if k == 0 else blob[16 * k:16 * k + 16]
    cout = blob[16 + 16 * k:32 + 16 * k]
    ks, R = keys_for_chunk(k, cin, cout)
    ok = len(ks) == 15 and spn_chunk(cin, ks) == cout
    allk[k] = [x.hex() for x in ks]
    meta[k] = {"rounds": len([1 for rd in R if "quad" in rd]),
               "tail": bool([1 for rd in R if rd.get("tail")]),
               "replay": ok}
    print("chunk %2d keys=%2d replay=%s" % (k, len(ks), ok))

gt = [x.hex() for x in CHUNK0_KEYS]
print("chunk0 matches spn_round.CHUNK0_KEYS[:14]:", allk[0][:14] == gt[:14])
json.dump({"keys": allk, "meta": meta},
          open(os.path.join(HERE, "ks_all_chunks.json"), "w"), indent=1)
print("wrote ks_all_chunks.json")
