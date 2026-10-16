# Fresh constant hunt in libsigner.so — SHA-256 constants plain & masked, .data eyeball
import sys, struct, binascii

d = open(r"..\apks\lib\hanaf\libsigner.so", "rb").read()

def allforms(hexstr, name):
    b = binascii.unhexlify(hexstr)
    hits = []
    for tag, pat in [
        ("le", b),
        ("be", b[::-1]),
        ("cc-le", bytes(x ^ 0xCC for x in b)),
        ("cc-be", bytes(x ^ 0xCC for x in b[::-1])),
        ("55-le", bytes(x ^ 0x55 for x in b)),
        ("55-be", bytes(x ^ 0x55 for x in b[::-1])),
    ]:
        i = d.find(pat)
        while i >= 0:
            hits.append((tag, i))
            i = d.find(pat, i + 1)
    if hits:
        print(name, "->", ", ".join("%s@%x" % h for h in hits[:8]))

# SHA-256 IV words + first/last round constants
for w, nm in [("6a09e667", "IV0w"), ("bb67ae85", "IV1w"), ("5be0cd19", "IV7w"),
              ("428a2f98", "K0"), ("c67178f2", "K63")]:
    allforms(w, nm)

# HMAC ipad/opad patterns are runtime-only; look for AES Rcon / S-box markers
allforms("637c777bf26b6fc5", "aes-sbox-head")   # plain sbox first 8 bytes
allforms("0102030405060708", "rcon-run")
allforms("9d3f9ee7c1e63c88", "inv-sbox?")

# sections of interest (from elf_recon): .text a090..112cd0, .data 113d80+335a
print("\n.data hexdump head (0x113d80):")
base = 0x113d80
for i in range(0, 0x200, 32):
    chunk = d[base + i: base + i + 32]
    print("%08x  %s  |%s|" % (base + i, chunk.hex(),
                              "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))

# entropy scan: find 16+ byte high-entropy aligned runs in .data
import math
print("\nhigh-entropy 32B windows in .data:")
run = None
for i in range(base, base + 0x335a - 32, 16):
    w = d[i:i + 32]
    ent = -sum((w.count(b) / 32) * math.log2(w.count(b) / 32) for b in set(w))
    if ent > 4.2:
        if run is None:
            run = [i, i]
        run[1] = i + 32
    else:
        if run and run[1] - run[0] >= 32:
            print("  %08x-%08x (%d B)" % (run[0], run[1], run[1] - run[0]))
        run = None
