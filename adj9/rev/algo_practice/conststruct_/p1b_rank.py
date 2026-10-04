"""Fixed GF(2) rank + span checks (p1 used a buggy min-reduction)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_common import *

def gf2_rank(rows):
    """Correct: basis indexed by leading bit position."""
    basis = {}  # lead_bit -> row
    for r in rows:
        cur = r
        while cur:
            lead = cur.bit_length() - 1
            if lead in basis:
                cur ^= basis[lead]
            else:
                basis[lead] = cur
                break
    return len(basis)

def in_span(target, rows):
    basis = {}
    for r in rows:
        cur = r
        while cur:
            lead = cur.bit_length() - 1
            if lead in basis:
                cur ^= basis[lead]
            else:
                basis[lead] = cur
                break
    t = target
    while t:
        lead = t.bit_length() - 1
        if lead in basis:
            t ^= basis[lead]
        else:
            return False
    return True

B = blocks(KB)
Brows = [int.from_bytes(b, "big") for b in B]
Hrows = [int.from_bytes(KB[i:i+8], "big") for i in range(0, 240, 8)]
Qrows = [int.from_bytes(KB[i:i+4], "big") for i in range(0, 240, 4)]

print("rank of 15 blocks (128-bit rows):", gf2_rank(Brows), "/15")
print("rank of 30 8-byte words (64-bit):", gf2_rank(Hrows), "/30")
print("rank of 60 4-byte words (32-bit):", gf2_rank(Qrows), "/60")
print("rank of 240 bytes as 8-bit rows:", gf2_rank(list(KB)), "/8")

for name, v in (("IV2[0:16]", IV2[:16]), ("IV2[16:]", IV2[16:]),
                ("K[0:16]", K[:16]), ("K[16:]", K[16:])):
    print(f"{name} in span of KB 128-bit blocks:",
          in_span(int.from_bytes(v, "big"), Brows))
for name, v in (("IV2", IV2), ("K", K)):
    print(f"{name} (256-bit) in span of KB 8-byte words:",
          in_span(int.from_bytes(v, "big"), Hrows))
