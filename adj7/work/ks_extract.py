"""ks_extract.py — extract K0..K14 for ALL 16 chunks from the footprint,
then probe the schedule law against KB362.

    python ks_extract.py
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX, AES_INV, gmul, mix_columns, shift_rows

blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
IV = blob[:16]

ops = []
for l in open(os.path.join(HERE, "v9_ops.txt")):
    a, b = l.split()
    ops.append((int(a), int(b, 16)))

# stores from the footprint: (wc, addr, val)
stores = []
for line in open(os.path.join(HERE, "spn_footprint.txt")):
    f = line.split()
    if len(f) < 5 or f[1] != "W":
        continue
    stores.append((int(f[0]), int(f[3].split("=")[1], 16),
                   int(f[4].split("=")[1], 16)))
stores.sort()
print("stores:", len(stores), "wc range", stores[0][0], stores[-1][0])


def states_for_chunk(k):
    """Replay the state buffer 0x900F09C+0x40k through chunk k's op window."""
    base = 0x9000000
    cell0 = 0x900F09C + 0x40 * k
    cells = [cell0 + 4 * i for i in range(16)]
    c0i = 1022 + 1287 * k
    wc_lo = ops[c0i][0]
    wc_hi = ops[min(c0i + 1287, len(ops) - 1)][0]
    hist = [(wc, a, v) for wc, a, v in stores
            if wc_lo <= wc < wc_hi and a in cells]
    cur, si, snap = {}, 0, []
    cw = ops[c0i:c0i + 1287]
    for i in range(len(cw) - 1):
        w1 = cw[i + 1][0]
        while si < len(hist) and hist[si][0] < w1:
            cur[hist[si][1]] = hist[si][2]
            si += 1
        snap.append((cw[i][1], bytes(cur.get(a, 0) for a in cells)))
    R = []
    r = None
    for o, sv in snap:
        if o == 0x1161:
            R.append({"init": sv})
            r = R[-1]
        elif o == 0x1168:
            r = {"sr_in": sv}
            R.append(r)
        elif o == 0x116D:
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
    return R


def keys_for_chunk(k, chunk_in, wire_out):
    R = states_for_chunk(k)
    ks = [bytes(a ^ AES_INV[b] for a, b in zip(chunk_in, R[0]["init"]))]
    rounds = [rd for rd in R[1:] if "quad" in rd]
    for j, rd in enumerate(rounds):
        qout = rd["quad"][-1][1]
        ks.append(bytes(AES_INV[rd["m2"][i]] ^ qout[i] for i in range(16)))
    t = [rd for rd in R if rd.get("tail")]
    if t:
        ks.append(bytes(AES_INV[t[0]["m1"][i]]
                        ^ shift_rows(t[0]["sr_in"])[i] for i in range(16)))
    return ks, R


def spn_chunk(P, keys):
    x = bytes(a ^ b for a, b in zip(P, keys[0]))
    x = bytes(AES_SBOX[v] for v in x)
    for r in range(13):
        x = shift_rows(x)
        x = mix_columns(x)
        x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))
        x = bytes(AES_SBOX[v] for v in x)
    x = shift_rows(x)
    x = bytes(a ^ b for a, b in zip(x, keys[14]))
    return bytes(AES_SBOX[v] for v in x)


all_keys = {}
for k in range(16):
    cin = IV if k == 0 else blob[16 * k:16 * k + 16]     # CBC over wire
    cout = blob[16 + 16 * k:32 + 16 * k]
    ks, R = keys_for_chunk(k, cin, cout)
    all_keys[k] = [k_.hex() for k_ in ks]
    nrounds = len([1 for rd in R if "quad" in rd])
    tail = bool([1 for rd in R if rd.get("tail")])
    ok = len(ks) == 15 and spn_chunk(cin, ks) == cout
    print("chunk %2d: %2d rounds tail=%s keys=%d replay=%s"
          % (k, nrounds, tail, len(ks), ok))

json.dump(all_keys, open(os.path.join(HERE, "ks_all_chunks.json"), "w"),
          indent=1)
print("wrote ks_all_chunks.json")

# ---- schedule probes ----
imm = json.load(open(os.path.join(
    HERE, "..", "..", "adj7_work", "adj7s4_immruns.json")))["d20a0"]
KB_LE = b"".join(struct.pack("<I", w) for w in imm)
KB_BE = b"".join(struct.pack(">I", w) for w in imm)
print("\nKB_LE[:32]:", KB_LE[:32].hex())

def key_sched_aes256(k0, k1):
    """standard AES-256 expansion from two 16-B keys -> 15 round keys"""
    W = [list(k0[i * 4:i * 4 + 4]) for i in range(4)] + \
        [list(k1[i * 4:i * 4 + 4]) for i in range(4)]
    rcon = 1
    for i in range(8, 60):
        t = list(W[i - 1])
        if i % 8 == 0:
            t = [AES_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = ((rcon << 1) ^ 0x1B) & 0xFF if rcon & 0x80 else rcon << 1
        elif i % 8 == 4:
            t = [AES_SBOX[b] for b in t]
        W.append([W[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(b for w in W[4 * r:4 * r + 4] for b in w) for r in range(15)]

for k in (0, 4):
    ks = [bytes.fromhex(h) for h in all_keys[k]]
    pred = key_sched_aes256(ks[0], ks[1])
    match = sum(1 for a, b in zip(ks, pred) if a == b)
    print("chunk %d: AES-256 expansion of (K0,K1) predicts %d/15 keys" % (k, match))
    # xor-structure across rounds
    print("  K1^K0 :", bytes(a ^ b for a, b in zip(ks[1], ks[0])).hex())
    print("  K2^K1 :", bytes(a ^ b for a, b in zip(ks[2], ks[1])).hex())

# cross-chunk: K0 XORs
k0s = [bytes.fromhex(all_keys[k][0]) for k in range(16)]
print("\nK0 per chunk:")
for k, k0 in enumerate(k0s):
    print("  %2d %s" % (k, k0.hex()))
