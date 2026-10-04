import struct

# ROW9: tile = [337d5f21 011d4d1e 13227bce 21426d41], preamble P=9949bda6
T0, T1, T2, T3 = 0x337D5F21, 0x011D4D1E, 0x13227BCE, 0x21426D41
P = 0x9949BDA6
a6 = 0x205F123F
W0 = 0xF1A55B5B
d2 = 0x4BCE691E

K13 = T3 ^ T1
R = (K13 >> 16) & 0xFFFF
Xlo = (T0 ^ T1) & 0xFFFF
print("K13=%08x R=%04x Xlo=%04x" % (K13, R, Xlo))
print("a6=%08x bridge=(R<<16)|Xlo=%08x match=%s" % (a6, (R << 16) | Xlo, a6 == ((R << 16) | Xlo)))
# P? preamble vs W0/R/X?
for label, v in [("W0", W0), ("R||R", R | (R << 16)), ("X=T0^T1", T0 ^ T1),
                 ("T0^P", T0 ^ P), ("T1^P", T1 ^ P), ("W0^P", W0 ^ P),
                 ("a6", a6), ("d2", d2), ("P^a6", P ^ a6), ("P^d2", P ^ d2),
                 ("W0^a6", W0 ^ a6), ("W0^d2", W0 ^ d2)]:
    print("  P ? %-10s : P^%s = %08x" % (label, label, P ^ v))
