"""dbg_tail2.py — raw tail states for chunk 0."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import (load_round_states, CHUNK0_KEYS, AES_INV, AES_SBOX,
                       shift_rows, mix_columns)

blob = bytes.fromhex(open(os.path.join(HERE, "v3_blob.hex")).read().strip())
IV, C0 = blob[:16], blob[16:32]
R = load_round_states()
print("num records:", len(R), [list(r.keys()) for r in R[-3:]])
r13 = R[13]
tail = R[14]
print("r13 keys :", sorted(r13.keys()))
print("r13 m1   :", r13["m1"].hex())
print("r13 m2   :", r13["m2"].hex())
print("tail sr_in:", tail["sr_in"].hex())
print("tail m1  :", tail["m1"].hex())
print("tail end :", tail.get("end", b"?").hex() if tail.get("end") else None)
print("C0       :", C0.hex())
print()
print("r13.m2 == tail.sr_in :", r13["m2"] == tail["sr_in"])
print("SR(r13.m2) == tail.sr_in :", shift_rows(r13["m2"]) == tail["sr_in"])
print("tail.m1 == C0 :", tail["m1"] == C0)
print()
# candidate final laws from r13.m2 (state after round-13 SB) to wire:
m2 = r13["m2"]
K14 = CHUNK0_KEYS[14]
cands = {
    "SBOX(SR(m2)^K14)": bytes(AES_SBOX[a ^ b] for a, b in zip(shift_rows(m2), K14)),
    "SBOX(SR(m2))^K14": bytes(a ^ b for a, b in zip(
        (AES_SBOX[v] for v in shift_rows(m2)), K14)),
    "SR(SBOX(m2))^K14": bytes(a ^ b for a, b in zip(
        (AES_SBOX[v] for v in m2)[::-1] if 0 else bytes(AES_SBOX[v] for v in m2), K14)),
    "SBOX(m2)^K14 (no SR)": bytes(a ^ b for a, b in zip(
        (AES_SBOX[v] for v in m2), K14)),
    "SR(SBOX(m2)^K14)": bytes(AES_SBOX[v] for v in bytes(
        a ^ b for a, b in zip(m2, K14))),
}
for name, out in cands.items():
    print("  %-22s %s  == C0: %s" % (name, out.hex(), out == C0))
print()
# what XORs with SR(m2) to give AES_INV(C0)?
inv = bytes(a ^ b for a, b in zip(shift_rows(m2), (AES_INV[c] for c in C0)))
print("AES_INV(C0) ^ SR(m2) :", inv.hex())
print("CHUNK0_KEYS[14]      :", K14.hex())
print("tail.m1 ^ SR(m2)     :", bytes(a ^ b for a, b in zip(tail["m1"], shift_rows(m2))).hex())
print("tail.m1 ^ tail.sr_in :", bytes(a ^ b for a, b in zip(tail["m1"], tail["sr_in"])).hex())
