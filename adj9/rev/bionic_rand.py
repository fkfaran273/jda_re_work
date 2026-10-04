# bionic_rand.py - Bionic libc rand()/srand() algorithm emulation, then fit the
# golden region: find the rand() stream position where the 14 observed dwords sit.
#
# Bionic (bionic/libc/stdlib/rand.cpp):
#   static uint32_t rand_seed = 1;          (srand(seed) sets XOR-shift state)
#   unsigned rand() { rand_seed = rand_seed*6364136223846793005ULL + 1; ... }
# Actually Bionic uses: seed = seed * 6364136223846793005 + 1442695040888963407?
# No - Bionic rand: static uint64_t s = 1; s = s * 6364136223846793005 + 1;
#   return (s >> 33) & RAND_MAX(0x7fffffff)?  Test variants against golden #0 W's.
import struct


def bionic_rand_stream(seed, n, variant="shift33"):
    s = seed & 0xFFFFFFFFFFFFFFFF
    out = []
    for _ in range(n):
        if variant == "shift33":
            s = (s * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF
            out.append((s >> 33) & 0xFFFFFFFF)
        elif variant == "glibc":
            s = (1103515245 * s + 12345) & 0x7FFFFFFF
            out.append(s)
        elif variant == "msvc":
            s = (214013 * s + 2531011) & 0xFFFFFFFF
            out.append((s >> 16) & 0x7FFF)
    return out


W0 = 0x13271271
W1 = 0xB7D0992B
CAND_SEEDS = [1, 0, 1789240512, 1789240075, 0x13271271, 0xB7D0992B]
print("=== does any (seed, variant, offset) reproduce W0/W1? ===")
for seed in CAND_SEEDS:
    for v in ("shift33", "glibc", "msvc"):
        try:
            st = bionic_rand_stream(seed, 64, v)
        except Exception as e:
            print("  %s seed=%s ERR %s" % (v, seed, e))
            continue
        hit = [i for i, x in enumerate(st) if x in (W0, W1)]
        print("  %-8s seed=%-12s hit_idx=%s" % (v, seed, hit[:4]))
print("done")