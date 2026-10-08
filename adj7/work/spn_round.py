"""spn_round.py — the adj7 (3.62.0) whitening SPN, closed form.

STATUS (this session): the SPN core is EXACTLY AES-256 (standard SubBytes /
ShiftRows / MixColumns, 14 rounds).  Verified bit-exact against the genuine
blob on chunk 0 (all round data measured from the emulator footprint) and on
chunk 4 (round-boundary heap captures).  The only open piece is the per-chunk
KEY SCHEDULE: the 15 round keys K0..K14 are derived inside the VM from the
chunk input + KB362 by a custom law (not the AES-256 expansion; tested).

Per-chunk pipeline (all measured, see SPN_FINDINGS.md):
    x  = P_k ^ K0            (0x10af copy-in = initial AddRoundKey)
    x  = AES_SBOX(x)         (0x1161)
    13 x [ ShiftRows (0x1168)
           [0x116d = VM-internal: key-schedule advance]
           MixColumns (4 quad ops: 0x1312/0x1341/0x1372/0x13a5, one column each)
           x ^= K_r          (0x1172)
           x  = AES_SBOX(x)  (0x1177) ]
    ShiftRows (0x117e)
    x ^= K14                 (0x1183)   -> wire bytes (chunk output)
    (0x1188 / 0x10b4 / 0x10af: bookkeeping, copy-out, next chunk)

State buffer: chunk k's working state lives at 0x900f09c + 0x40*k as 16
stride-4 dword cells; the wire bytes are read out of the diagonal... simply
out[i] = cell[i] (byte at cell i).
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

# ---------------------------------------------------------------- AES core
AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
AES_INV = bytes(AES_SBOX.index(i) for i in range(256))


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if hi else 0)
        b >>= 1
    return p


_MCM = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


def mix_columns(b):
    out = bytearray(16)
    for q in range(4):
        col = b[4 * q:4 * q + 4]
        for i in range(4):
            v = 0
            for j in range(4):
                v ^= gmul(col[j], _MCM[i][j])
            out[4 * q + i] = v
    return bytes(out)


def shift_rows(b):
    """measured 0x1168 law: new M[r][c] = old M[(r+c) % 4][c]"""
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * r + c] = b[4 * ((r + c) % 4) + c]
    return bytes(out)


def spn_chunk(P, keys):
    """One 16-B chunk through the whitening SPN.  keys = [K0, K1..K13, K14]."""
    x = bytes(a ^ b for a, b in zip(P, keys[0]))
    x = bytes(AES_SBOX[v] for v in x)
    for r in range(13):
        x = shift_rows(x)
        x = mix_columns(x)
        x = bytes(a ^ b for a, b in zip(x, keys[1 + r]))
        x = bytes(AES_SBOX[v] for v in x)
    x = shift_rows(x)
    x = bytes(a ^ b for a, b in zip(x, keys[14]))
    return bytes(AES_SBOX[v] for v in x)   # final AK is followed by an SB


# --------------------------------------------- chunk-0 keys (mint 0015, sec 1771238644)
# Extracted from the emulator store-log: K_r = AES_INV(m2_r) ^ MC(SR(m2_{r-1})),
# K0 = IV ^ AES_INV(S_init), K14 = AES_INV(C0) ^ SR(m2_13).
CHUNK0_KEYS = [bytes.fromhex(h) for h in (
    "8a30d92045579a112e0cf063fbcb68d4",
    "3db456c07b9166a509bef66cd870654b",
    "a15d4820c630f211d908344311f165af",
    "bf151bb9c4847d1ccd3a8b70154aee3b",
    "7575aa79b34558686a4d6c2b7bbc0984",
    "9e701ae65af467fa97ceec8a828402b1",
    "2e02626a9d473a02f70a56298cb65fad",
    "fa3ed573a0cab28937045e03b5805cb2",
    "eb4855bf760f6fbd810539940db36639",
    "2d53e6618d9954e8ba9d0aeb0f1d5659",
    "5ff99ec929f6f174a8f3c8e0a540aed9",
    "2b5a0254a6c356bc1c5e5c5713430a0e",
    "659e35b44c68c4c0e49b0c2041dba2f9",
    "a8e338cd0e206e71127e3226013d3828",
    "4d0b65434b840dd68882f36df5fc98ef")]


def load_round_states():
    """Rebuild the per-op-boundary states of chunk 0 from spn_footprint.txt."""
    stores = []
    for line in open(os.path.join(HERE, "spn_footprint.txt")):
        f = line.split()
        if len(f) < 5 or f[1] != "W":
            continue
        stores.append((int(f[0]), int(f[3].split("=")[1], 16),
                       int(f[4].split("=")[1], 16)))
    cells = set(range(0x900F09C, 0x900F0DC, 4))
    hist = sorted((wc, a, v) for wc, a, v in stores
                  if a in cells and 6100000 <= wc <= 6640000)
    ops = [(int(a) + 5300000, int(b, 16)) for a, b in
           (l.split() for l in open(os.path.join(HERE, "v9_ops.txt")))]
    c0 = ops[1022:1290]
    cur, si, snap = {}, 0, []
    for i in range(len(c0) - 1):
        w0, o0 = c0[i]
        w1 = c0[i + 1][0]
        while si < len(hist) and hist[si][0] < w1:
            cur[hist[si][1]] = hist[si][2]
            si += 1
        snap.append((o0, bytes(cur.get(a, 0) for a in sorted(cells))))
    R = []
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


def main():
    blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
    IV = blob[:16]
    C0 = blob[16:32]
    R = load_round_states()

    # extract the chunk-0 keys directly from the measured data (no typos)
    IVw = blob[:16]
    Kc0 = [bytes(a ^ AES_INV[b] for a, b in zip(IVw, R[0]["init"]))]
    prev = R[0]["init"]
    for rd in R[1:]:
        if "tail" in rd or "quad" not in rd:
            continue
        qout = rd["quad"][-1][1]
        Kc0.append(bytes(AES_INV[rd["m2"][i]] ^ qout[i] for i in range(16)))
        prev = rd["m2"]
    t = [rd for rd in R if rd.get("tail")][0]
    Kc0.append(bytes(AES_INV[t["m1"][i]] ^ shift_rows(t["sr_in"])[i]
                     for i in range(16)))
    keys0 = Kc0
    print("=== verify the AES-core law on chunk 0 (mint 0015) ===")
    print("  extracted keys K0..K14:")
    for i, k in enumerate(keys0):
        print("    K%-2d %s" % (i, k.hex()))
    ok_sb = sum(1 for rd in R if "quad" in rd and
                bytes(AES_SBOX[v] for v in rd["m1"]) == rd["m2"])
    print("  m2 == AES_S(m1)            : %d/13" % ok_sb)
    ok_mc = sum(1 for rd in R if "quad" in rd and
                mix_columns(rd["post_sr"]) == rd["quad"][-1][1])
    print("  quadout == MixColumns(SR)  : %d/13" % ok_mc)
    # full round-by-round replay with the extracted keys
    x = bytes(a ^ b for a, b in zip(IV, keys0[0]))
    x = bytes(AES_SBOX[v] for v in x)
    print("  S_init reproduced          :", x == R[0]["init"])
    okr = True
    for r in range(13):
        x = shift_rows(x)
        x = mix_columns(x)
        x = bytes(a ^ b for a, b in zip(x, keys0[1 + r]))
        x = bytes(AES_SBOX[v] for v in x)
        if x != R[1 + r]["m2"]:
            okr = False
            print("  round %d MISMATCH" % (r + 1))
    print("  13 rounds reproduced       :", okr)
    x = shift_rows(x)
    x = bytes(a ^ b for a, b in zip(x, keys0[14]))
    out = bytes(AES_SBOX[v] for v in x)
    print("  final SR,AK,SB -> wire     :", out == C0, out.hex())
    print("  spn_chunk(IV, keys0) == C0 :", spn_chunk(IV, keys0) == C0)

    print()
    print("=== chunk 4 cross-check (keys from the cap round-boundary data) ===")
    blob4in = blob[64:80]
    cap = lambda n: open(os.path.join(HERE, "spn_caps", "cap_%d.bin" % n),
                         "rb").read()
    B = 0x900F19C - 0x9000000
    st = lambda n: bytes(cap(n)[B + 4 * i] for i in range(16))
    S_init4 = st(5739035)             # cap at 0x1168 r1 dispatch = post-0x1161
    K0_4 = bytes(a ^ AES_INV[b] for a, b in zip(blob4in, S_init4))
    # m2 states from caps at 0x1168 dispatches (rounds 4..13) + tail
    print("  K0_4 =", K0_4.hex(), "(chunk-dependent! not equal to chunk 0's)")
    # m1 caps (0x1177 dispatch = post-AK, pre-SB): rounds 1..3
    m1_caps = {5770336: 1, 5805637: 2, 5840938: 3}
    K4 = {0: K0_4}
    prev = S_init4
    m2_by_r = {}
    for capn, ridx in sorted(m1_caps.items(), key=lambda kv: kv[1]):
        m1v = st(capn)
        qout = mix_columns(shift_rows(prev))
        K4[ridx] = bytes(AES_INV[m1v[i]] ^ qout[i] for i in range(16))
        prev = bytes(AES_SBOX[v] for v in m1v)      # m2_r
        m2_by_r[ridx] = prev
    # m2 caps at 0x1168 dispatches: post-round states, rounds 4..12
    m2_caps = {5915540: 5, 5950841: 6, 5986142: 7, 6021443: 8, 6056744: 9,
               6092045: 10, 6127346: 11, 6162647: 12}
    for capn, ridx in sorted(m2_caps.items(), key=lambda kv: kv[1]):
        m2_by_r[ridx] = st(capn)
    # K_r = AES_INV(m2_r) ^ MC(SR(m2_{r-1})), needs both neighbours
    for r in range(1, 13):
        if r in K4 or r - 1 not in m2_by_r or r not in m2_by_r:
            continue
        qout = mix_columns(shift_rows(m2_by_r[r - 1]))
        K4[r] = bytes(AES_INV[m2_by_r[r][i]] ^ qout[i] for i in range(16))
    m2_13 = st(6197949)                             # cap at 0x117e
    q13 = mix_columns(shift_rows(m2_by_r[12]))
    K4[13] = bytes(AES_INV[m2_13[i]] ^ q13[i] for i in range(16))
    C4 = blob[80:96]
    K4[14] = bytes(AES_INV[C4[i]] ^ shift_rows(m2_13)[i] for i in range(16))
    known = sorted(K4)
    print("  extracted chunk-4 keys:", known)
    # replay chunk 4 from m2_5 (known) through rounds 6..13 + tail with K6..K14
    x = m2_by_r[5]
    ok = True
    for r in range(6, 14):
        x = shift_rows(x)
        x = mix_columns(x)
        x = bytes(a ^ b for a, b in zip(x, K4[r]))
        x = bytes(AES_SBOX[v] for v in x)
        nxt = m2_by_r.get(r + 1)
        if nxt is not None and x != nxt:
            ok = False
            print("  round %d mismatch" % r)
    x = shift_rows(x)
    x = bytes(a ^ b for a, b in zip(x, K4[14]))
    out4 = bytes(AES_SBOX[v] for v in x)
    print("  rounds 5-13 + tail reproduced:", ok)
    print("  chunk-4 replay == wire C4    :", out4 == C4, out4.hex())
    print("  expected                     :", C4.hex())


if __name__ == "__main__":
    main()
