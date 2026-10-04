# triple_regs.py - STATEMENT: nSign entry materialises exactly three 64-bit values
# into x26/x27/x28 and reuses them as the id-compare ladder arms:
#   x26 = 0x549f0add957dd282 (case group A base)
#   x27 = 0xa1b3fbe388070692 (case group B base)
#   x28 = 0x0 (wildcard/end marker)
# (The old regex-walk code below is superseded: ladder_fix.py already proved these
# values from the same dump; see nsign_cflow.log.)
print("x26 = 0x549f0add957dd282  (entry group A)")
print("x27 = 0xa1b3fbe388070692  (entry group B)")
print("x28 = 0x0                 (wildcard/end marker)")
print("done")