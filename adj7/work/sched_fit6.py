"""sched_fit6.py — exact relation table over true words W[4..59], all i=12..59.
Also: where does 311cfed2 come from? Search lib + KB.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import AES_SBOX

d = json.load(open(os.path.join(HERE, "ks_all2.json")))["keys"]
K14 = bytes.fromhex("029901c84ef1c508aa6ac928ebb16bd1")
W = [None] * 60
for r in range(1, 14):
    kb = bytes.fromhex(d["0"][r])
    for w in range(4):
        W[4*r + w] = list(kb[4*w:4*w+4])
for w in range(4):
    W[56 + w] = list(K14[4*w:4*w+4])
sub = lambda t: [AES_SBOX[b] for b in t]

print("=== relation W[i] =?= W[i-8] ^ f(W[i-1]) for i=12..59 ===")
for i in range(12, 60):
    tgt = W[i]
    xw = [a ^ b for a, b in zip(W[i-8], W[i-1])]
    sw = [a ^ b for a, b in zip(W[i-8], sub(W[i-1]))]
    law = "XOR " if tgt == xw else ("SUBW" if tgt == sw else "NONE")
    print("  i=%2d mod8=%d  plain:%s  subw:%s  -> %s"
          % (i, i % 8, tgt == xw, tgt == sw, law))

# where does the schedule law break for the back-solved seed?
W0 = [0xc0, 0x0c, 0x05, 0x93]
W1 = [0x67, 0x6d, 0xba, 0x31]
W2 = [0x1f, 0x38, 0xc6, 0x52]
W3 = [0xc8, 0xf9, 0x51, 0xec]
Ws = [W0, W1, W2, W3] + [list(W[i]) for i in range(4, 60)]
n_ok = 0
fails = []
for i in range(8, 60):
    t = sub(Ws[i-1]) if i % 8 in (0, 4) else Ws[i-1]
    pred = [Ws[i-8][j] ^ t[j] for j in range(4)]
    if pred == Ws[i]:
        n_ok += 1
    else:
        fails.append(i)
print("\nforward from back-solved seed: %d/52 ok, fails at %s" % (n_ok, fails))

# ---- search 311cfed2 in lib image and KB ----
MASKB = bytes.fromhex("311cfed2")
libp = os.path.join(HERE, "..", "..", "adj7_work")
cands = []
for root, _, files in os.walk(libp):
    for fn in files:
        if fn.endswith((".so", ".bin", ".apk")):
            cands.append(os.path.join(root, fn))
print("\ncandidate lib files:", cands[:5])
for p in cands:
    data = open(p, "rb").read()
    for pat, name in ((MASKB, "311cfed2"), (MASKB[::-1], "d2fe1c31")):
        idx = data.find(pat)
        hits = []
        while idx != -1 and len(hits) < 8:
            hits.append(hex(idx))
            idx = data.find(pat, idx + 1)
        if hits:
            print("  %s: %s found at %s" % (os.path.basename(p), name, hits))

imm = json.load(open(os.path.join(libp, "adj7s4_immruns.json")))["d20a0"]
kb_le = b"".join(struct.pack("<I", w) for w in imm)
print("311cfed2 in KB_LE:", kb_le.find(MASKB))
print("d2fe1c31 in KB_LE:", kb_le.find(MASKB[::-1]))
print("0xd2fe1c31 in imm dwords:", [i for i, v in enumerate(imm)
                                     if v in (0x311cfed2, 0xd2fe1c31)])
