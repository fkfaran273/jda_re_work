"""Pass 6: identify the SubWord map M (used at i%8==0 and i%8==4).

Strategy: M is likely a composition of {byte-rotation, AES sbox,
Sbox^0x55, ShiftRows permutation, MixColumns, InvMixColumns} possibly with
a constant XOR.  For each candidate linear-ish core, compute
out ^ core(in) for all 13 samples; if the map + constant is right, the
residues should be rcon-like (small, structured) or constant.
"""
import sys, os, itertools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return p

def rotl8(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF

def build_sbox(aff=0x63):
    out = []
    for v in range(256):
        inv = 0
        if v:
            r, base, e = 1, v, 254
            while e:
                if e & 1: r = gmul(r, base)
                base = gmul(base, base); e >>= 1
            inv = r
        out.append(inv ^ rotl8(inv,1) ^ rotl8(inv,2) ^ rotl8(inv,3)
                   ^ rotl8(inv,4) ^ aff)
    return out

SBOX = build_sbox()
T55 = [v ^ 0x55 for v in SBOX]

PI = [4 * (((i // 4) - (i % 4)) % 4) + (i % 4) for i in range(16)]
PI_INV = [4 * (((j // 4) + (j % 4)) % 4) + (j % 4) for j in range(16)]

def perm32(w, perm, endian):
    b = w.to_bytes(4, endian)          # a block: byte i
    # treat 4x4: state[i] with row i%4 col i//4 -- but for a single word the
    # cipher treats the 4 bytes as one column; ShiftRows on one column is
    # identity-ish per column... For a WORD-level permutation we just apply
    # byte permutation.
    return int.from_bytes(bytes(b[perm[i]] for i in range(4)), endian)

def mix_word(w, endian):
    """MixColumns on the word as one column: y = 2a^3b^c^d circulant."""
    b = list(w.to_bytes(4, endian))
    out = []
    for i in range(4):
        out.append(gmul(2, b[i]) ^ gmul(3, b[(i+1) % 4]) ^ b[(i+2) % 4]
                   ^ b[(i+3) % 4])
    return int.from_bytes(bytes(out), endian)

def inv_mix_word(w, endian):
    b = list(w.to_bytes(4, endian))
    out = []
    for i in range(4):
        out.append(gmul(14, b[i]) ^ gmul(11, b[(i+1) % 4])
                   ^ gmul(13, b[(i+2) % 4]) ^ gmul(9, b[(i+3) % 4]))
    return int.from_bytes(bytes(out), endian)

W_be = [int.from_bytes(KB[4*i:4*i+4], "big") for i in range(60)]
samples4 = [(W_be[i-1], W_be[i] ^ W_be[i-8] ^ W_be[i-1])
            for i in range(8, 60) if i % 8 == 4]
samples0 = [(W_be[i-1], W_be[i] ^ W_be[i-8] ^ W_be[i-1])
            for i in range(8, 60) if i % 8 == 0]

# candidate cores: byte-substitution then optional byte-permutation then
# optional mix
def cores():
    for subname, sub in (("sbox", SBOX), ("T55", T55), ("inv", None)):
        if sub is None:
            inv = [0]*256
            for i, v in enumerate(SBOX): inv[v] = i
            sub = inv; subname = "invsbox"
        for rot in range(4):
            for usemix in (False, True):
                for mixname, mix in (("MC", mix_word), ("iMC", inv_mix_word)):
                    if not usemix and mixname == "iMC": continue
                    perm = [(rot + j) % 4 for j in range(4)]
                    def core(w, sub=sub, perm=perm, mix=mix):
                        b = list(w.to_bytes(4, "big"))
                        s = bytes(sub[x] for x in b)
                        s2 = bytes(s[perm[j]] for j in range(4))
                        w2 = int.from_bytes(s2, "big")
                        return mix(w2, "big")
                    yield f"{subname} rot{rot} {mixname if usemix else 'no-mix'}", core

print("== i%8==4 samples: out ^ core(in) ==")
best = []
for name, core in cores():
    res = [out ^ core(inp) for inp, out in samples4]
    # score: how many residues share a common byte pattern / are small
    tops = [r >> 24 for r in res]
    common = len(set(tops))
    best.append((common, name, res))
best.sort(key=lambda t: (t[0], ))
for common, name, res in best[:8]:
    print(f"  {name:28s} distinct-top-byte={common} res={[f'{r:08x}' for r in res[:3]]}...")

print("\n== i%8==0 samples: out ^ core(in) ==")
best0 = []
for name, core in cores():
    res = [out ^ core(inp) for inp, out in samples0]
    tops = [r >> 24 for r in res]
    best0.append((len(set(tops)), name, res))
best0.sort(key=lambda t: (t[0],))
for common, name, res in best0[:8]:
    print(f"  {name:28s} distinct-top-byte={common} res={[f'{r:08x}' for r in res]}")
