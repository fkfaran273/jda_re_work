"""dbg_c0.py — compare spn_round's chunk-0 keys vs my windowed extraction."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from spn_round import (load_round_states, CHUNK0_KEYS, AES_INV,
                       shift_rows, spn_chunk)
import ksx3_core

blob = ksx3_core.blob
IV = ksx3_core.IV

# method A: spn_round's own loader
R_A = load_round_states()
K_A = [bytes(a ^ AES_INV[b] for a, b in zip(IV, R_A[0]["init"]))]
for rd in [rd for rd in R_A[1:] if "quad" in rd]:
    q = rd["quad"][-1][1]
    K_A.append(bytes(AES_INV[rd["m2"][i]] ^ q[i] for i in range(16)))
t = [rd for rd in R_A if rd.get("tail")][0]
K_A.append(bytes(AES_INV[t["m1"][i]] ^ shift_rows(t["sr_in"])[i]
                 for i in range(16)))
print("A replay:", spn_chunk(IV, K_A) == blob[16:32])

# method B: my windowed extraction
K_B, R_B = ksx3_core.keys_for_chunk(0, IV)
print("B replay:", spn_chunk(IV, K_B) == blob[16:32])
print("A == CHUNK0_KEYS:", [k.hex() for k in K_A] ==
      [k.hex() for k in CHUNK0_KEYS])
for i, (a, b) in enumerate(zip(K_A, K_B)):
    mark = " " if a == b else "  <<< DIFF"
    print("K%-2d A %s B %s%s" % (i, a.hex(), b.hex(), mark))
