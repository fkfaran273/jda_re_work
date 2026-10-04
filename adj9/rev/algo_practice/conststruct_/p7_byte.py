"""Pass 7: collect partial byte map F from the 13 sub samples; test
bytewise-consistency, affinity, and identify against sbox families."""
import sys, os
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
INVS = [0]*256
for i, v in enumerate(SBOX): INVS[v] = i

W = [int.from_bytes(KB[4*i:4*i+4], "big") for i in range(60)]
s4 = [(W[i-1], W[i] ^ W[i-8] ^ W[i-1]) for i in range(8, 60) if i % 8 == 4]
s0 = [(W[i-1], W[i] ^ W[i-8] ^ W[i-1]) for i in range(8, 60) if i % 8 == 0]

# ---- 1. bytewise consistency for i%8==4 (no rotation assumed) ----
tab = {}   # in_byte -> set of out_bytes
conflicts = []
for inp, out in s4:
    ib = inp.to_bytes(4, "big"); ob = out.to_bytes(4, "big")
    for j in range(4):
        if ib[j] in tab and tab[ib[j]] != ob[j]:
            conflicts.append((j, ib[j], ob[j], tab[ib[j]]))
        tab.setdefault(ib[j], ob[j])
print(f"i%8==4 bytewise (no rot): {len(tab)} distinct in-bytes, "
      f"conflicts={conflicts}")

# ---- 2. i%8==0 with rotation s: out byte j = F(in byte (j+s)%4) ^ rcon_j? ----
# rcon only contaminates ONE byte in AES; test which rotation makes 3 of 4
# byte positions consistent with tab.
for s in range(4):
    hits, miss = 0, []
    for inp, out in s0:
        ib = inp.to_bytes(4, "big"); ob = out.to_bytes(4, "big")
        for j in range(4):
            src = ib[(j + s) % 4]
            if src in tab:
                if tab[src] == ob[j]: hits += 1
                else: miss.append((s, j, src, ob[j], tab[src]))
    print(f"i%8==0 rot{s}: consistent lookups={hits}/28, mismatches={len(miss)}")
    if hits >= 21:
        for m in miss[:8]: print("     miss:", m)

# ---- 3. is the partial F affine over GF(2)? ----
# gather all (x,y) pairs from tab; find x,y,z with x^y^z in table
pairs = dict(tab)
aff_viol = 0; aff_test = 0
xs = list(pairs)
for x in xs:
    for y in xs:
        z = x ^ y
        if z in pairs and z not in (x, y):
            w = x ^ y ^ z  # = 0 case skipped
            # affine: F(x)^F(y)^F(z)^F(0) == F(x^y^z); we don't know F(0)
            # LINEAR test: F(x)^F(y) == F(x^y) requires F(0)=0.
            # test via: F(x)^F(y)^F(x^y) constant across triples == F(0)?
            if x < y < z:
                c = pairs[x] ^ pairs[y] ^ pairs[z] ^ pairs[x ^ y ^ z] if (x^y^z) in pairs else None
            aff_test += 1
# simpler: check if F(x)^F(y) == F(x^y)^const for all pairs
consts = set()
xs = sorted(pairs)
for i in range(len(xs)):
    for j in range(i+1, len(xs)):
        x, y = xs[i], xs[j]
        if (x ^ y) in pairs and x ^ y != x:
            consts.add(pairs[x] ^ pairs[y] ^ pairs[x ^ y])
print(f"\nF(x)^F(y)^F(x^y) distinct values: {sorted(hex(c) for c in consts)}")
print("(single value => F affine with that value = F(0)... actually = F(0)^0?")

# ---- 4. identify F against sbox families: F(x) = s(gmul(m,x^a))^b ----
def test_family(sbox):
    hits = []
    items = list(pairs.items())
    for m in range(1, 256):
        base = bytes(sbox[gmul(m, x)] for x in range(256))
        for a in range(256):
            shifted = bytes(base[x ^ a] for x in range(256))
            # need out = shifted[x] ^ b  => b = out^shifted[x] constant
            b0 = items[0][1] ^ shifted[items[0][0]]
            if all(items[k][1] ^ shifted[items[k][0]] == b0 for k in range(1, len(items))):
                hits.append((m, a, b0))
    return hits

print("\nfamily sbox(gmul(m, x^a))^b:", test_family(SBOX)[:10])
print("family invsbox(gmul(m, x^a))^b:", test_family(INVS)[:10])

# family: gmul(m, sbox(x^a))^b
def test_family2(sbox):
    hits = []
    items = list(pairs.items())
    for m in range(1, 256):
        base = bytes(gmul(m, sbox[x]) for x in range(256))
        for a in range(256):
            shifted = bytes(base[x ^ a] for x in range(256))
            b0 = items[0][1] ^ shifted[items[0][0]]
            if all(items[k][1] ^ shifted[items[k][0]] == b0 for k in range(1, len(items))):
                hits.append((m, a, b0))
    return hits

print("family gmul(m, sbox(x^a))^b:", test_family2(SBOX)[:10])
print("family gmul(m, invsbox(x^a))^b:", test_family2(INVS)[:10])

# also plain gmul(m,x)^b and affine masks
def test_plain():
    items = list(pairs.items())
    hits = []
    for m in range(1, 256):
        base = bytes(gmul(m, x) for x in range(256))
        b0 = items[0][1] ^ base[items[0][0]]
        if all(items[k][1] ^ base[items[k][0]] == b0 for k in range(1, len(items))):
            hits.append(("gmul", m, b0))
    for c in range(256):
        base = bytes(x ^ c for x in range(256))
        b0 = items[0][1] ^ base[items[0][0]]
        if all(items[k][1] ^ base[items[k][0]] == b0 for k in range(1, len(items))):
            hits.append(("xor", c, b0))
    return hits
print("plain gmul/xor families:", test_plain())

print("\npartial F table so far:")
for x in sorted(pairs):
    print(f"  F(0x{x:02x}) = 0x{pairs[x]:02x}", end="   ")
    if x % 4 == 3: print()
