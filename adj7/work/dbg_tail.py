"""dbg_tail.py — find the state-cell -> wire-byte permutation at the tail."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import (load_round_states, CHUNK0_KEYS, AES_INV, AES_SBOX,
                       shift_rows, spn_chunk)

blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
IV, C0 = blob[:16], blob[16:32]
R = load_round_states()
t = [rd for rd in R if rd.get("tail")][0]
m1 = t["m1"]                      # state at 0x1183 (pre final-SB cell view)
m2_13 = t["sr_in"]
print("m1   :", m1.hex())
print("C0   :", C0.hex())
print("SBOX(SR(m2_13)):", bytes(AES_SBOX[v] for v in shift_rows(m2_13)).hex())

# if wire[i] = SBOX[m1[sigma(i)]] -> m1[sigma(i)] = AES_INV[wire[i]]
tgt = bytes(AES_INV[c] for c in C0)
sigma = []
ok = True
for i, tv in enumerate(tgt):
    hits = [j for j in range(16) if m1[j] == tv]
    if len(hits) != 1:
        ok = False
        sigma.append(hits)
    else:
        sigma.append(hits[0])
print("sigma (wire i <- cell sigma(i)):", sigma, "unique:", ok)

# natural candidates
cands = {
    "identity": lambda i: i,
    "transpose c*4+r": lambda i: (i % 4) * 4 + i // 4,
    "SR rows rot": lambda i: 4 * (i % 4) + i // 4,          # same as transpose
}
# also: inverse-transpose, row rotations
def rot(r, i):
    row, col = i // 4, i % 4
    return 4 * row + ((col + r) % 4)
for r in range(1, 4):
    cands["rowrot+%d" % r] = (lambda rr: lambda i: rot(rr, i))(r)
for name, f in cands.items():
    if name == "SR rows rot":
        continue
    out = bytes(m1[f(i)] for i in range(16))
    print("  cand %-16s %s  match_wire: %s" % (name, out.hex(),
                                               bytes(AES_SBOX[v] for v in out) == C0))
