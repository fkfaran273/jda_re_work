"""t3_imms.py -- raw decode of movz/movk immediates across all of .text.
Find crypto constants outside the mapped spans."""
import struct, json

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
TEXT_OFF, TEXT_SIZE = 0x8be0, 0x13fdd4

fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
import bisect
fstarts = [f[0] for f in fdes]
def func_of(a):
    i = bisect.bisect_right(fstarts, a) - 1
    if i >= 0:
        s, z = fdes[i]
        if s <= a < s + z: return s
    return None

def region(a):
    if a < 0x99000: return 'R1'
    if a < 0xBCA30: return 'M1'
    if a < 0x100094: return 'R2'
    if a < 0x12AA48: return 'M2'
    if a < 0x146000: return 'R3'
    return 'M3'

# decode all movz/movk
# movz: sf 10 100101 hw(2) imm16(16) Rd(5)   -> sf=1: 0xD2800000, sf=0: 0x52800000
# movk: sf 11 100101 hw imm16 Rd             -> 0x72800000 / 0xF2800000
movz = {}   # addr -> (rd, hw, imm)
movk = {}
addr = TEXT_OFF
end = TEXT_OFF + TEXT_SIZE
n64 = 0
while addr < end:
    w = struct.unpack_from('<I', d, addr)[0]
    op6 = (w >> 23) & 0x3f
    # movz: bits 30-23 = 0b10100101 (0xA5) for sf=1 -> op6 = 0b100101=0x25? let's just mask
    # w & 0x7F800000 pattern check:
    if (w & 0x7F800000) == 0x52800000:      # movz 32/64: sf in bit31
        rd = w & 31
        hw = (w >> 21) & 3
        imm = (w >> 5) & 0xFFFF
        movz[addr] = (rd, hw, imm)
    elif (w & 0x7F800000) == 0x72800000:    # movk
        rd = w & 31
        hw = (w >> 21) & 3
        imm = (w >> 5) & 0xFFFF
        movk[addr] = (rd, hw, imm)
    addr += 4

print("movz:", len(movz), "movk:", len(movk))

# Reconstruct constants: scan linearly, maintain current value per reg per func;
# simpler: for every address a, walk forward while movk of same reg continues.
consts = {}   # addr of movz -> (value, bits, rd)
for a, (rd, hw, imm) in movz.items():
    if hw != 0:  # top-half only loads
        continue
    val = imm
    bits = 16
    na = a + 4
    while True:
        k = movk.get(na)
        if k and k[0] == rd:
            if k[1] == 1:
                val |= k[2] << 16; bits = max(bits, 32)
            elif k[1] == 2:
                val |= k[2] << 32; bits = max(bits, 48)
            elif k[1] == 3:
                val |= k[2] << 48; bits = 64
            na += 4
        else:
            break
    consts[a] = (val, bits, rd)

# interesting constants
INTEREST = {
    # SHA-256 H and K (a few sentinels)
    0x6a09e667: 'SHA256_H0', 0xbb67ae85: 'SHA256_H1', 0x510e527f: 'SHA256_H7.lo',
    0x428a2f98: 'SHA256_K0', 0x71374491: 'SHA256_K1', 0xc67178f2: 'SHA256_K63',
    0x243f6a88: 'SHA256_K?/pi', 0x90befffa: 'SHA256_K60',
    # SHA-1 / SHA-0
    0x67452301: 'SHA1_H0', 0xefcdab89: 'SHA1_H1', 0xc3d2e1f0: 'SHA1_H4',
    # MD5
    0xd76aa478: 'MD5_T1',
    # IV2 words (first qword eba2c435...) -- need actual IV2 bytes; use w0/hi
    0xeba2c435: 'IV2_w0', 0xc435eba2: 'IV2_w0.swap',
    # MAC key K = 690f6094...
    0x690f6094: 'K_w0', 0x6094690f: 'K_w0.swap',
    # AES sbox first bytes ^0x55 = 0x36, standard 0x63
    0x637c777b: 'AES_SBOX_w0', 0x3629222e: 'AESSBOX55_w0',
    # misc
    0x9e3779b9: 'TEA/phi', 0x61c88647: 'TEA_delta',
    0xedb88320: 'CRC32_poly', 0x82f63b78: 'CRC32C_poly',
    0xff51afd7: 'murmur3 shift const', 0xc2b2ae3d: 'XXH', 0x27d4eb2f: 'XXH32_3',
    0x85ebca6b: 'XXH32_1', 0x165667b1: 'XXH32_2', 0x9e3779b1: 'WH_TEA',
    0x45d9f3b: 'splitmix', 0x2545f491: 'mulhi inv32',
    0xcc9e2d51: 'murmur32_c1', 0x1b873593: 'murmur32_c2',
}

hits = []
for a, (val, bits, rd) in consts.items():
    if val in INTEREST:
        hits.append((a, val, INTEREST[val], bits, rd))
    # also 16-bit halves for IV2/K since 32-bit constants may be loaded as two movz
for a, (rd, hw, imm) in movz.items():
    pass

# For 32-bit values built as movz imm + movk lsl16 we already covered.
# Print hits grouped by constant
from collections import defaultdict
g = defaultdict(list)
for a, val, name, bits, rd in hits:
    g[(name, hex(val))].append(a)
print("\n=== constant hits (movz+movk reconstructed) ===")
for (name, vh), addrs in sorted(g.items()):
    regs = {}
    for a in addrs:
        f = func_of(a)
        key = (region(a), hex(f) if f else '??')
        regs.setdefault(key, 0)
        regs[key] += 1
    print("  %-20s %s: %d sites  %s" % (name, vh, len(addrs), dict(sorted(regs.items()))))

# count occurrences of each 32-bit constant value overall (top values by frequency)
from collections import Counter
c32 = Counter()
for a, (val, bits, rd) in consts.items():
    if bits == 32:
        c32[val] += 1
print("\ntop 32-bit immediates:")
for v, n in c32.most_common(25):
    print("  %08x: %d" % (v, n))
