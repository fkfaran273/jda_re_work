"""sched_fit4.py — recover the full schedule seed, verify, and recover the record.

Law:  W[i] = W[i-8] ^ (SubWord(W[i-1]) if i%8 in {0,4} else W[i-1])
Known: W[4..59] (extracted K1..K13 + true K14, cell space).
Recover W[0..3] = K*_0 (true round-0 key), then record_k = K0_k ^ K*_0.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
Kex = [bytes.fromhex(d["0"][r]) for r in range(14)]           # K1..K13
K14 = bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1")        # true K14
W = [None] * 60
for j in range(14):
    for w in range(4):
        W[4 + 4*j + w] = list((K14 if j == 13 else Kex[j])[4*w:4*w+4])

def sub(t):
    return [AES_SBOX[b] for b in t]

# recover seed words W[0..3]
W[1] = [a ^ b for a, b in zip(W[9], W[8])]
W[2] = [a ^ b for a, b in zip(W[10], W[9])]
W[3] = [a ^ b for a, b in zip(W[11], W[10])]
W[0] = [a ^ b for a, b in zip(W[8], sub(W[7]))]
print("recovered seed words:")
for i in range(8):
    print("  W[%d] = %s" % (i, bytes(W[i]).hex()))
K0_star = bytes(b for w in W[0:4] for b in w)
K1 = bytes(b for w in W[4:8] for b in w)
print("K*_0 =", K0_star.hex())
print("K1   =", K1.hex())

# verify: full forward expansion from seed reproduces W[8..59]
Wp = [list(W[i]) for i in range(8)]
rcon_bad = 0
for i in range(8, 60):
    t = sub(Wp[i-1]) if i % 8 in (0, 4) else Wp[i-1]
    Wp.append([Wp[i-8][j] ^ t[j] for j in range(4)])
ok = sum(1 for i in range(8, 60) if Wp[i] == W[i])
print("forward expansion from seed reproduces W[8..59]: %d/52" % ok)

# cross-check W[4] (K1 word0) via i=12 recurrence
w4 = [a ^ b for a, b in zip(W[12], sub(W[11]))]
print("W[4] consistency (i=12):", w4 == W[4])

# ---- recover the record: plaintext_k = K0_k ^ K*_0 ----
blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
rec = b"".join(bytes(a ^ b for a, b in zip(bytes.fromhex(d[str(k)][0]), K0_star))
               for k in range(16))
print("\nrecovered record (256 B, cell order):")
for i in range(0, 256, 32):
    chunk = rec[i:i+32]
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
    print("  %02x %s  |%s|" % (i, chunk.hex(), txt))

# ---- KB362 ----
imm = json.load(open(os.path.join(HERE, "..", "..", "adj7_work",
                                  "adj7s4_immruns.json")))["d20a0"]
KB_LE = b"".join(struct.pack("<I", w) for w in imm)
KB_BE = b"".join(struct.pack(">I", w) for w in imm)
print("\nKB_LE[0:64] :", KB_LE[:64].hex())
print("KB_BE[0:64] :", KB_BE[:64].hex())
for name, KB in (("LE", KB_LE), ("BE", KB_BE)):
    for off in range(0, 241, 1):
        if KB[off:off+16] == K1:
            print("  K1 == %s[%d:%d+16]!" % (name, off, off))
        if KB[off:off+16] == K0_star:
            print("  K*_0 == %s[%d:%d+16]!" % (name, off, off))
# dword views of seed vs KB dwords
seed_d = list(struct.unpack("<8I", K0_star + K1))
print("seed dwords (LE):", [hex(x) for x in seed_d])
kb_d = imm
for si, sv in enumerate(seed_d):
    hits = [i for i, v in enumerate(kb_d) if v == sv]
    if hits:
        print("  seed dword %d (%08x) == KB dword idx %s" % (si, sv, hits))
print("\nKB dwords 0..15:", [hex(x) for x in kb_d[:16]])
