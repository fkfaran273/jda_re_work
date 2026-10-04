# nsign_refs.py - find code that references the JNI name strings (0xeeb, 0xf1d).
# In AArch64, a reference looks like: adrp Xn, #page ; add Xn, Xn, :lo12: / ldr.
# Resolve every adrp in .text and report the ones landing near the strings.
import struct
import sys

SO = (r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a"
      r"\libsigner.so")
d = open(SO, "rb").read()
TOFF, TSZ = 0x0, 0x148E60
code = d[TOFF:TOFF + TSZ]
STRS = (0xEEB, 0xF1D)

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    have_cs = True
except Exception as e:
    print("no capstone:", e)
    have_cs = False

hits = []
if have_cs:
    for ins in md.disasm(code, 0):
        if ins.mnemonic == "adrp":
            op = ins.operands[0]
            tgt = (ins.address & ~0xFFF) + op.imm
            if 0xD00 <= tgt <= 0x1200:
                hits.append((ins.address, op.reg, tgt))
print("adrp refs into 0xd00..0x1200: %d" % len(hits))
for a, r, t in hits:
    win = d[t:t + 40].split(b"\x00", 1)[0]
    print("  0x%x -> 0x%x  %r" % (a, t, win[:36]))
    sys.stdout.flush()
print("done")