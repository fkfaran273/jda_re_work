"""scan_8d6f4.py - sweep a VA range: bl targets histogram, adrp/adr globals,
immediate-offset str/ldr bases, and any instruction mentioning known globals."""
import sys, os, struct
from collections import Counter, defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import *

LIB = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
elf = open(LIB, "rb").read()

# dynsym imports for name lookup of PLT
e_shoff = struct.unpack_from("<Q", elf, 0x28)[0]
e_shentsize = struct.unpack_from("<H", elf, 0x3A)[0]
e_shnum = struct.unpack_from("<H", elf, 0x3C)[0]
e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]
def sh(i):
    o = e_shoff + i * e_shentsize
    return struct.unpack_from("<IIQQQQIIQQ", elf, o)
stro = sh(e_shstrndx)[4]
secs = {}
for i in range(e_shnum):
    s = sh(i)
    nm = elf[stro + s[0]:elf.index(b"\x00", stro + s[0])].decode()
    secs[nm] = s
dynsym, dynstr = secs[".dynsym"], secs[".dynstr"]
def sym_name(idx):
    o = dynsym[4] + idx * 24
    st_name = struct.unpack_from("<I", elf, o)[0]
    e = elf.index(b"\x00", dynstr[4] + st_name)
    return elf[dynstr[4] + st_name:dynstr[4] + st_name + (e - dynstr[4] - st_name)].decode()
plt_syms = {}
ro = secs[".rela.plt"][4]
for i in range(secs[".rela.plt"][5] // 24):
    off, info, add = struct.unpack_from("<QQq", elf, ro + i * 24)
    plt_syms[off] = sym_name(info >> 32)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

LO = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x8d6f4
HI = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x95fc4

bls = Counter()
adrp_regs = {}
globals_ref = Counter()
imm_ops = defaultdict(set)   # (base_reg, disp) -> set of pcs
calls = []
for ins in md.disasm(elf[LO:HI], LO):
    m, ops = ins.mnemonic, ins.operands
    if m == "bl":
        t = ops[0].imm
        bls[t] += 1
        calls.append((ins.address, t))
    elif m == "adrp":
        adrp_regs[ops[0].reg] = ops[1].imm
        globals_ref[ops[1].imm] += 1
    elif m == "adr":
        globals_ref[ops[1].imm] += 1
    elif m in ("ldr", "str", "ldrb", "strb", "ldur", "stur", "ldrsw", "ldrsh", "ldrh", "strh"):
        if len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
            base = ops[1].mem.base
            disp = ops[1].mem.disp
            if base in adrp_regs:
                globals_ref[adrp_regs[base] + disp] += 1
            imm_ops[base].add(disp)

# PLT names for bl targets that land in PLT
plt_start = secs[".plt"][3]; plt_size = secs[".plt"][5]
got_to_plt = {}
adrp_base = None
for ent in range(1, plt_size // 16):
    addr = plt_start + ent * 16
    code = elf[addr:addr + 16]
    for i2 in md.disasm(code, addr):
        if i2.mnemonic == "adrp":
            adrp_base = i2.operands[1].imm
        elif i2.mnemonic == "ldr" and adrp_base is not None:
            got_to_plt[adrp_base + i2.operands[-1].mem.disp] = addr
            break
PLT_NAME = {p: plt_syms.get(g, "got_%x" % g) for g, p in got_to_plt.items()}

print("== bl targets in 0x%x..0x%x (%d sites) ==" % (LO, HI, sum(bls.values())))
for t, n in sorted(bls.items()):
    nm = PLT_NAME.get(t)
    tag = " <- PLT:%s" % nm if nm else ""
    if plt_start <= t < plt_start + plt_size and not nm:
        tag = " <- PLT?0x%x" % t
    print("  0x%-8x x%-3d%s" % (t, n, tag))

print("\n== adrp/adr page targets (globals) ==")
for g in sorted(globals_ref):
    print("  0x%x  x%d" % (g, globals_ref[g]))

print("\n== bl call sites (ordered) ==")
for pc, t in calls:
    nm = PLT_NAME.get(t)
    print("  0x%06x bl 0x%x%s" % (pc, t, " ; %s" % nm if nm else ""))
