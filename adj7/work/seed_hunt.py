"""seed_hunt.py — where does the AES-256 seed (W[0..7]) come from?
Test: KB362 as an expansion itself; seed inside expansions of KB slices;
byte-lane transforms; XOR structures.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

def rot(t, n):
    n %= 4
    return t[n:] + t[:n]

def g(t, i):
    t = rot(t, 1)
    t = [AES_SBOX[b] for b in t]
    r = 1
    for _ in range(i // 8 - 1):
        r = ((r << 1) ^ 0x1B) & 0xFF if r & 0x80 else r << 1
    t[0] ^= r
    return t

def expand(seed32):
    W = [list(seed32[4*i:4*i+4]) for i in range(8)]
    for i in range(8, 60):
        t = g(W[i-1], i) if i % 8 == 0 else (
            [AES_SBOX[b] for b in W[i-1]] if i % 8 == 4 else W[i-1])
        W.append([W[i-8][j] ^ t[j] for j in range(4)])
    return [bytes(b for w in W[4*r:4*r+4] for b in w) for r in range(15)]

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
K14 = bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1")
Wt = [None] * 60
for r in range(1, 14):
    kb = bytes.fromhex(d["0"][r])
    for w in range(4):
        Wt[4*r + w] = list(kb[4*w:4*w+4])
for w in range(4):
    Wt[56 + w] = list(K14[4*w:4*w+4])
# back-solve seed with the STANDARD law
Wt[1] = [a ^ b for a, b in zip(Wt[9], Wt[8])]
Wt[2] = [a ^ b for a, b in zip(Wt[10], Wt[9])]
Wt[3] = [a ^ b for a, b in zip(Wt[11], Wt[10])]
# i=8: W[8] = W[0] ^ g(W[7])
g7 = g(Wt[7], 8)
Wt[0] = [a ^ b for a, b in zip(Wt[8], g7)]
seed = bytes(b for w in Wt[0:8] for b in w)
print("recovered seed (32 B):", seed.hex())
ks = expand(seed)
ok = sum(1 for r in range(1, 15) if ks[r] == bytes(b for w in Wt[4*r:4*r+4] for b in w))
print("full standard AES-256 expansion of seed reproduces K1..K14: %d/14" % ok)

imm = json.load(open(os.path.join(HERE, "..", "..", "adj7_work",
                                  "adj7s4_immruns.json")))["d20a0"]
KB_LE = b"".join(struct.pack("<I", w) for w in imm)
KB_BE = b"".join(struct.pack(">I", w) for w in imm)

# 1) is KB362 itself a standard AES-256 expansion (LE / BE views)?
for name, KB in (("LE", KB_LE), ("BE", KB_BE)):
    Wk = [list(KB[4*i:4*i+4]) for i in range(60)]
    okk = 0
    for i in range(8, 60):
        t = g(Wk[i-1], i) if i % 8 == 0 else (
            [AES_SBOX[b] for b in Wk[i-1]] if i % 8 == 4 else Wk[i-1])
        if [Wk[i-8][j] ^ t[j] for j in range(4)] == Wk[i]:
            okk += 1
    print("KB362 %s as AES-256 expansion: %d/52 words consistent" % (name, okk))

# 2) seed inside expansion of every KB 32-B slice (LE/BE), and of KB rows xored
targets = [seed]
def find_in(hay, needle):
    return [off for off in range(len(hay) - len(needle) + 1)
            if hay[off:off+len(needle)] == needle]
for name, KB in (("LE", KB_LE), ("BE", KB_BE)):
    for off in range(0, 225, 4):
        exp0 = expand(KB[off:off+32])[0]
        if exp0 == seed[:16]:
            print("  seed half0 == expand(%s[%d:+32])[0]" % (name, off))
    # seed raw in KB
    if KB.find(seed[:16]) >= 0:
        print("  seed half0 raw in KB_%s at %d" % (name, KB.find(seed[:16])))
    if KB.find(seed[16:]) >= 0:
        print("  seed half1 raw in KB_%s at %d" % (name, KB.find(seed[16:])))

# 3) dword-level: seed dwords vs SubWord / rot of KB dwords
sd = list(struct.unpack("<8I", seed))
sd_be = list(struct.unpack(">8I", seed))
print("\nseed dwords LE:", [hex(x) for x in sd])
kbsub = [int.from_bytes(bytes(AES_SBOX[b] for b in
         struct.pack("<I", w)), "little") for w in imm]
for si, sv in enumerate(sd):
    hits = [i for i, v in enumerate(kbsub) if v == sv]
    if hits:
        print("  seedLE[%d] == SubWord(KB_LE dword) at %s" % (si, hits))
    hits = [i for i, v in enumerate(imm) if v == sv]
    if hits:
        print("  seedLE[%d] == KB dword at %s" % (si, hits))
    hits = [i for i, v in enumerate(imm) if v == sd_be[si]]
    if hits:
        print("  seedBE[%d] == KB dword at %s" % (si, hits))

# 4) XOR of consecutive KB dword pairs / rows
for si, sv in enumerate(sd):
    hits = [(a, b) for a in range(64) for b in range(64)
            if (imm[a] ^ imm[b]) == sv]
    if hits:
        print("  seedLE[%d] == KB[a]^KB[b]: %s" % (si, hits[:4]))

# 5) full expansion of KB_LE[0:32] and KB_BE[0:32]: which round keys match ours?
ours = [bytes(b for w in Wt[4*r:4*r+4] for b in w) for r in range(15)]
for name, KB in (("LE", KB_LE), ("BE", KB_BE)):
    ks = expand(KB[0:32])
    m = [r for r in range(15) if ks[r] == ours[r]]
    print("expand(KB_%s[0:32]) matches our round keys at r = %s" % (name, m))
