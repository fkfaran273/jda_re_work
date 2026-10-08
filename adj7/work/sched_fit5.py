"""sched_fit5.py — correct seed recovery + record + KB362 comparison.

Mapping: d["0"][r] = extracted K_r for chunk 0 (r=0..13, where K0 is
effective = plaintext_0 ^ K*_0 = header ^ K*_0); true K14 = 0299...
True words: W[4r..4r+3] = K*_r.  Recover W[0..3] = K*_0 two ways.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
K14 = bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1")
W = [None] * 60
for r in range(1, 14):                       # K1..K13
    kb = bytes.fromhex(d["0"][r])
    for w in range(4):
        W[4*r + w] = list(kb[4*w:4*w+4])
for w in range(4):                           # K14
    W[56 + w] = list(K14[4*w:4*w+4])

sub = lambda t: [AES_SBOX[b] for b in t]

# --- path A: recurrence back-solve
W[1] = [a ^ b for a, b in zip(W[9], W[8])]
W[2] = [a ^ b for a, b in zip(W[10], W[9])]
W[3] = [a ^ b for a, b in zip(W[11], W[10])]
W[0] = [a ^ b for a, b in zip(W[8], sub(W[7]))]
K0_star = bytes(b for w in W[0:4] for b in w)

# --- path B: K*_0 = K0_chunk0 ^ header
blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
header = blob[:16]
K0_star_B = bytes(a ^ b for a, b in zip(bytes.fromhex(d["0"][0]), header))
print("K*_0 pathA:", K0_star.hex())
print("K*_0 pathB:", K0_star_B.hex())
print("paths agree:", K0_star == K0_star_B)

# --- verify full forward expansion from seed (K*_0, K1)
Wp = [list(W[i]) for i in range(8)]
for i in range(8, 60):
    t = sub(Wp[i-1]) if i % 8 in (0, 4) else Wp[i-1]
    Wp.append([Wp[i-8][j] ^ t[j] for j in range(4)])
ok = sum(1 for i in range(8, 60) if Wp[i] == W[i])
print("forward expansion from seed reproduces W[8..59]: %d/52" % ok)

# --- record
rec = b"".join(bytes(a ^ b for a, b in zip(bytes.fromhex(d[str(k)][0]), K0_star))
               for k in range(16))
print("\nrecovered record (256 B):")
for i in range(0, 256, 32):
    c = rec[i:i+32]
    txt = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
    print("  %02x %s |%s|" % (i, c.hex(), txt))

# --- KB362 comparison
imm = json.load(open(os.path.join(HERE, "..", "..", "adj7_work",
                                  "adj7s4_immruns.json")))["d20a0"]
KB_LE = b"".join(struct.pack("<I", w) for w in imm)
KB_BE = b"".join(struct.pack(">I", w) for w in imm)
K1 = bytes(b for w in W[4:8] for b in w)
print("\nK*_0 =", K0_star.hex())
print("K1   =", K1.hex())
for name, KB in (("LE", KB_LE), ("BE", KB_BE)):
    for label, key in (("K*_0", K0_star), ("K1", K1)):
        hits = [off for off in range(241) if KB[off:off+16] == key]
        print("  %s in KB_%s at byte offsets: %s" % (label, name, hits))
# dword-level: seed dwords vs KB dwords (both orders)
seed_le = struct.unpack("<8I", K0_star + K1)
seed_be = struct.unpack(">8I", K0_star + K1)
for lbl, sd in (("LE", seed_le), ("BE", seed_be)):
    for si, sv in enumerate(sd):
        hits = [i for i, v in enumerate(imm) if v == sv]
        if hits:
            print("  seed dword[%d] (%s %08x) == immruns dword %s"
                  % (si, lbl, sv, hits))
# byte-lane: check K*_0 / K1 against KB rows under transpose/dwordrev
def transpose(b):
    return bytes(b[4*(j % 4) + j//4] for j in range(16))
def dwordrev(b):
    return b"".join(b[4*i:4*i+4][::-1] for i in range(4))
for name, KB in (("LE", KB_LE), ("BE", KB_BE)):
    for tname, tf in (("id", lambda x: x), ("T", transpose), ("D", dwordrev),
                      ("TD", lambda x: transpose(dwordrev(x)))):
        k0t, k1t = tf(K0_star), tf(K1)
        for label, key in (("K*_0", k0t), ("K1", k1t)):
            hits = [off for off in range(241) if KB[off:off+16] == key]
            if hits:
                print("  %s (lane %s) in KB_%s: %s" % (label, tname, name, hits))
print("\nKB_LE rows of 16:")
for i in range(0, 256, 16):
    print("  row %2d: %s" % (i//16, KB_LE[i:i+16].hex()))
