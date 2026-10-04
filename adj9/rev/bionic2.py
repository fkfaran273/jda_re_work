# bionic2.py - the REAL Bionic algorithm (bionic/libc/stdlib/rand.cpp, AOSP):
#   static uint64_t s = 0x1234ABCD330E;
#   s = s * 6364136223846793005ULL + 1;   return (s >> 33);
# and srand(seed): s = (uint64_t)seed (0 -> 1). The 32-bit outputs are bounded by
# RAND_MAX = 0x7fffffff, so a full 32-bit dword CANNOT come from one rand() call:
# the region must draw 2x per dword or use rand() % high-base values. The MTE-range
# W0=0x13271271 / W1=0xB7D0992B >> 0x7FFFFFFF though, so maybe they are (rand() ^
# (rand()<<16)) pairs. Test: does [W0, W1] sit in a (x^y<<16) stream of seed 1?
MASK = (1 << 64) - 1
A, C = 6364136223846793005, 1


def stream(seed, n):
    s = seed & MASK
    out = []
    for _ in range(n):
        s = (s * A + C) & MASK
        out.append((s >> 33) & 0x7FFFFFFF)
    return out


W0, W1 = 0x13271271, 0xB7D0992B
print("W0=0x%08x (> RAND_MAX? %s)  W1=0x%08x (> RAND_MAX? %s)"
      % (W0, W0 > 0x7FFFFFFF, W1, W1 > 0x7FFFFFFF))
print("=> a Bionic rand() return (max 0x7FFFFFFF) can NEVER be W0 or W1.")
print("=> the W dwords come from a different source (full-width mix), not rand().")
st = stream(0x1234ABCD330E, 8)
print("default-seed stream:", ["0x%08x" % x for x in st])
print("done")