"""crack_grid.py — invert the 3.62.0 whitening SPN by grid + memory search.

For each SPN variant (adj9-ios-family structure with KB362 keys), decrypt the
known wire chunk 0 and check whether the recovered record chunk R0 (and the
CBC-consistent R1) appears in the mint's heap snapshot.  The variant whose
R0/R1 are present in memory is the cipher.

    python crack_grid.py
"""
import itertools
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "adj9_ios"))
import adj9ios_pure as sg9          # read-only: SBOX, _F, _pi1, F tables

# ---- primitives ----
def _gmul(a, b, poly=0x11B):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= poly
    return r

SBOX = list(sg9.SBOX)
INV_SBOX = [0] * 256
for i, s in enumerate(SBOX):
    INV_SBOX[s] = i

PI = list(sg9._PI)                  # out[PI[i]] = in[i]
PI_INV = [0] * 16
for i, p in enumerate(PI):
    PI_INV[p] = i

def shift(chunk, table):
    out = bytearray(16)
    for i, c in enumerate(chunk):
        out[table[i]] = c
    return bytes(out)

# AES MixColumns / inverse on the 16-B state (col-major like AES)
def mix_aes(chunk, inv=False):
    m = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14)) \
        if inv else ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    out = bytearray(16)
    for c in range(4):
        col = [chunk[4 * c + r] for r in range(4)]
        for r in range(4):
            out[4 * c + r] = (_gmul(m[r][0], col[0]) ^ _gmul(m[r][1], col[1])
                              ^ _gmul(m[r][2], col[2]) ^ _gmul(m[r][3], col[3]))
    return bytes(out)

_F_TAB = sg9._F_TAB

def mix_f(chunk):
    return sg9._F(chunk)

def mix_none(chunk):
    return chunk

# invert the adj9 F per 32-B word: GF(2) 32x32 matrix inverse
def _inv32(rows):
    """rows: 32 ints (row j = output bit j mask).  Return inverse matrix."""
    # build augmented [A | I] over GF(2), rows as bit vectors
    m = [(rows[j], 1 << j) for j in range(32)]
    r = 0
    for c in range(32):
        p = next((k for k in range(r, 32) if (m[k][0] >> c) & 1), None)
        if p is None:
            return None
        m[r], m[p] = m[p], m[r]
        for k in range(32):
            if k != r and (m[k][0] >> c) & 1:
                m[k] = (m[k][0] ^ m[r][0], m[k][1] ^ m[r][1])
        r += 1
    inv = [0] * 32
    for j in range(32):
        inv[j] = m[j][1]
    return inv

def _word_inv_tables():
    tabs = []
    for k in range(4):
        rows = [(sg9.F_ROWS[j] >> (8 * k)) & 0xFF for j in range(32)]
        # rebuild the 32-bit row for word k: F_ROWS[j] bits 8k..8k+3? No --
        # F maps each word independently; row masks for word k are the bits
        # of F_ROWS[j] belonging to word k's OUTPUT?  The adj9 F is
        # word-wise: out_w = M_w(in_w) with the SAME 32x32 matrix per word.
        rowsk = [((sg9.F_ROWS[j] >> (8 * 0)) & 0xFF) for j in range(32)]
        # actually rebuild from the generator: rows[j] bit k of each byte
        # use the true matrix: out bit j gets parity(F_ROWS[j] & x) where x
        # is the whole 32-B word; restrict to word k: contribution rows are
        # F_ROWS[j] & (0xFF << 8k).  Invert per word: matrix M_k with
        # M_k[j][b] = bit (8k+b) of F_ROWS[j].
        Mk = []
        for j in range(32):
            row = ((sg9.F_ROWS[j] >> (8 * k)) & 0xFF)
            Mk.append(sum(((row >> b) & 1) << (8 * b) for b in range(8)))
        # Mk as 32 rows of 32 bits (input byte b -> output bits 8b..8b+7)?
        # simpler: build the full 32x32 for word k by imaging unit vectors.
        cols = []
        for b in range(32):
            x = 1 << b
            y = 0
            for j in range(32):
                m = sg9.F_ROWS[j] & x
                if bin(m).count("1") & 1:
                    y |= 1 << j
            cols.append(y)
        # matrix A with A[j][b] = bit j of f(e_b): rows = j, cols = b
        A = [sum(((cols[b] >> j) & 1) << b for b in range(32))
             for j in range(32)]
        inv = _inv32(A)
        if inv is None:
            tabs.append(None)
        else:
            # inverse maps y -> x: x_b = parity(inv[b] & y)
            tab = []
            for bb in range(256):
                bits = bb << (8 * (k % 4))
                tab.append(bits)  # placeholder, real use below
            tabs.append(inv)
    return tabs

def mix_f_inv(chunk, inv_mats):
    out = bytearray(16)
    for w in range(4):
        x = int.from_bytes(chunk[4 * w:4 * w + 4], "little")
        y = 0
        for j in range(32):
            if bin(x & inv_mats[j]).count("1") & 1:
                y |= 1 << j
        out[4 * w:4 * w + 4] = y.to_bytes(4, "little")
    return bytes(out)

def f_word_images():
    """For each word position the 32x32 GF(2) matrix of sg9._F, as row masks
    (row j = the mask of input bits that feed output bit j)."""
    mats = []
    for w in range(4):
        rows = []
        for j in range(32):
            m = (sg9.F_ROWS[j] >> (8 * w)) & 0xFF
            rows.append(sum(((m >> b) & 1) << (8 * b) for b in range(8)))
        mats.append(rows)
    return mats

F_MAT_ROWS = f_word_images()
F_INV_ROWS = [_inv32(r) for r in F_MAT_ROWS]

def mix_f_inv2(chunk):
    out = bytearray(16)
    for w in range(4):
        x = int.from_bytes(chunk[4 * w:4 * w + 4], "little")
        y = 0
        for j in range(32):
            if bin(x & F_INV_ROWS[w][j]).count("1") & 1:
                y |= 1 << j
        out[4 * w:4 * w + 4] = y.to_bytes(4, "little")
    return bytes(out)

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def swap4(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b) - 3, 4))

# ---- KB forms ----
imm = json.load(open(os.path.join(ROOT, "adj7_work", "adj7s4_immruns.json")))["d20a0"]
KB_LE = b"".join(struct.pack("<I", w) for w in imm)     # as found in memory
KB_BE = b"".join(struct.pack(">I", w) for w in imm)

def kb_forms():
    out = {}
    for nm, kb in (("le", KB_LE), ("be", KB_BE)):
        for mask in ("", "cc", "aa"):
            k = bytes(b ^ int(mask, 16) for b in kb) if mask else kb
            out[f"{nm}{mask}"] = k
            out[f"{nm}{mask}_rev"] = k[::-1]
    return out

def decrypt_chunk(var, out_chunk, prev):
    """Inverse of: x = chunk ^ prev; rounds; -> out_chunk."""
    R, sbox, shift_t, mix, mix_inv, keys, final, kdir = var
    y = xor(out_chunk, final)
    for r in range(R - 1, -1, -1):
        if r < R - 1:
            y = mix_inv(y)
        y = shift(y, shift_t["inv"])
        y = bytes(sbox[b] for b in y)
        y = xor(y, keys[r] if kdir == "asc" else keys[R - 1 - r] if False else keys[r])
    return xor(y, prev)

def build_variants():
    shifts = {
        "pi1": {"f": PI, "inv": PI_INV},
        "pi1inv": {"f": PI_INV, "inv": PI},
        "sr": {"f": None, "inv": None},      # filled below (AES row shifts)
        "id": {"f": list(range(16)), "inv": list(range(16))},
    }
    # AES ShiftRows (state col-major i=4c+r: out[4c+r] = in[4((c+r)%4)+r])
    sr = [4 * ((c + r) % 4) + r for c in range(4) for r in range(4)]
    sr_inv = [0] * 16
    for i, p in enumerate(sr):
        sr_inv[p] = i
    shifts["sr"] = {"f": sr, "inv": sr_inv}
    mixes = {
        "f": (mix_f, mix_f_inv2),
        "aes": (lambda c: mix_aes(c), lambda c: mix_aes(c, inv=True)),
        "id": (mix_none, mix_none),
    }
    sboxes = {"aes": SBOX, "aesinv": INV_SBOX}
    vars_ = []
    kbs = kb_forms()
    for R, kbn, kbk, maskv, sbn, shn, mn, kd, dom in itertools.product(
            (14, 15), ("le", "be"), ("", "_rev"), ("", "cc", "aa"),
            ("aes", "aesinv"), ("pi1", "pi1inv", "sr", "id"),
            ("f", "aes", "id"), ("asc",), ("d", "s")):
        kb = kbs[kbn + kbk]
        if maskv:
            kb = bytes(b ^ int(maskv, 16) for b in kb)
        if len(kb) < 16 * R + 16:
            continue
        keys = [kb[16 * r:16 * r + 16] for r in range(R)]
        final = kb[16 * R:16 * R + 16]
        if kd == "desc":
            keys = keys[::-1]
        vars_.append((R, sboxes[sbn], shifts[shn], mixes[mn][0],
                      mixes[mn][1], keys, final, "asc", dom, kbn + kbk + maskv,
                      shn, mn, R))
    return vars_

def main():
    blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read())
    IV = blob[:16]
    out0 = blob[16:32]
    out1 = blob[32:48]
    snap = open(os.path.join(HERE, "snap_A.bin"), "rb").read()
    variants = build_variants()
    print("variants:", len(variants))
    hits = []
    for v in variants:
        R, sbox, shift_t, mix, mix_inv, keys, final, _, dom, label, shn, mn, _R = v
        for dom_out in ("d", "s"):
            oc0 = out0 if dom_out == "d" else swap4(out0)
            oc1 = out1 if dom_out == "d" else swap4(out1)
            prev0 = IV if dom == "d" else swap4(IV)
            prev1 = oc0
            r0 = decrypt_chunk((R, sbox, shift_t, mix, mix_inv, keys, final,
                                "asc"), oc0, prev0)
            r1 = decrypt_chunk((R, sbox, shift_t, mix, mix_inv, keys, final,
                                "asc"), oc1, prev1)
            for cand, tag in ((r0, "R0"), (r1, "R1")):
                cand_d = cand if dom == "d" else swap4(cand)
                i = snap.find(cand_d)
                if i != -1:
                    hits.append((label, dom, dom_out, tag, hex(0x9000000 + i)))
                    print("HIT", label, "dom", dom, dom_out, tag,
                          "at", hex(0x9000000 + i), cand_d.hex())
    if not hits:
        print("no variant produced a record chunk present in memory")

if __name__ == "__main__":
    main()
