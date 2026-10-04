#!/usr/bin/env python3
import random, struct
from fold_exact import park_miller, shuffle16, M31

bad = 0
for trial in range(2000):
    seed = random.getrandbits(31) or 1
    st = [seed]
    def rng():
        r, s = park_miller(st[0]); st[0] = s
        return r, s
    perm = shuffle16(rng)
    w23, _ = rng()                       # park_miller right after shuffle16
    src = w23
    words = []
    for i in range(16):
        n = 15 - perm[i]
        w = (1 << n) | (src & ((1 << n) - 1))
        words.append(w & 0xFFFF)
    hb = [w.bit_length() - 1 for w in words]
    if sorted(hb) != list(range(16)):
        bad += 1
        if bad < 4:
            print('BAD seed=%08x perm=%s hb=%s' % (seed, list(perm), hb))
print('trials=2000  anchor-violations=%d' % bad)
# show one example
seed = 0x12345678
st = [seed]
def rng():
    r, s = park_miller(st[0]); st[0] = s
    return r, s
perm = shuffle16(rng); w23, _ = rng()
words = [((1 << (15-perm[i])) | (w23 & ((1 << (15-perm[i])) - 1))) & 0xFFFF for i in range(16)]
print('example perm =', list(perm))
print('example words=', ['%04x' % w for w in words])
print('high bits    =', [w.bit_length()-1 for w in words])
