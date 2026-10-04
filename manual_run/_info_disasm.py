"""_info_disasm.py -- find code references to the claims key strings inside
penti_libsigner.so and disassemble the surrounding functions.
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

D = open(r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea"
         r"\sdk_diff\libs\penti_libsigner.so", "rb").read()
TEXT_OFF, TEXT_ADDR, TEXT_SIZE = 0x8be0, 0x8be0, 0x13fdd4

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False

# pass 1: raw scan for ADRP+ADD pairs building addresses in the .data range
def sign_extend(v, bits):
    m = 1 << (bits - 1)
    return (v & ((1 << bits) - 1)) - (v & m)

targets = {}   # target va -> list of pcs
words = struct.unpack_from("<%dI" % (TEXT_SIZE // 4), D, TEXT_OFF)
adrp = {}
for i, w in enumerate(words):
    if (w & 0x9F000000) == 0x90000000:
        rd = w & 0x1F
        immhi = (w >> 5) & 0x7FFFF
        immlo = (w >> 29) & 0x3
        imm = sign_extend((immhi << 2 | immlo) << 12, 33)
        pc = TEXT_ADDR + i * 4
        adrp[(i, rd)] = (pc & ~0xFFF) + imm

# ADD Xd, Xn, #imm  (32/64-bit): 0b00110001 (sf=1: 0x91000000, sh flag bit22)
adds = {}
for (i, rd), base in adrp.items():
    for j in range(i + 1, min(i + 8, len(words))):
        w = words[j]
        if (w & 0xFF800000) == 0x91000000:
            rn = (w >> 5) & 0x1F
            rd2 = w & 0x1F
            if rn == rd and rd2 == rd:
                imm12 = (w >> 10) & 0xFFF
                sh = (w >> 22) & 1
                off = imm12 << (12 if sh else 0)
                targets.setdefault(base + off, []).append(TEXT_ADDR + i * 4)
                break

print("code refs to pool string %#x:" % 0x154AD0, [hex(x) for x in targets.get(0x154AD0, [])])
for va in (0x151C20, 0x151C31, 0x151C45, 0x151C55):   # client_sdk/headers_id/native_version/adj_signing_id
    print("code refs to %#x:" % va, [hex(x) for x in targets.get(va, [])])

# dump any other .data targets referenced from code, grouped by 4KB page
from collections import Counter
pagecnt = Counter((t & ~0xFFF) for t in targets)
print("\n.data pages referenced:", {hex(p): n for p, n in sorted(pagecnt.items()) if p >= 0x151000})

# disassemble around the pool string reference
POOL = 0x154AD0
for pc in targets.get(POOL, [])[:4]:
    print("\n==== around %#x ====" % pc)
    lo = max(TEXT_ADDR, pc - 0x180)
    code = D[TEXT_OFF + (lo - TEXT_ADDR): TEXT_OFF + (pc - TEXT_ADDR) + 0x120]
    for ins in md.disasm(code, lo):
        mark = "  <== pool" if ins.address == pc else ""
        print("%#x:\t%s\t%s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
    break
