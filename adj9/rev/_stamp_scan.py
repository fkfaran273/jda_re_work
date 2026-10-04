"""Extent + complete bl inventory of the stamp fn 0x12cb74 (srand(time) fn)."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

elf = open(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True

e_shoff = struct.unpack_from("<Q", elf, 0x28)[0]; e_shentsize = struct.unpack_from("<H", elf, 0x3A)[0]
e_shnum = struct.unpack_from("<H", elf, 0x3C)[0]; e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", elf, o)
    secs.append(dict(name=name, addr=addr, off=off, size=size, entsize=entsize))
sh = secs[e_shstrndx]
def nm(n):
    s = sh['off'] + n; return elf[s:elf.index(b"\0", s)].decode()
S = {}
for s in secs: s['nm'] = nm(s['name']); S[s['nm']] = s
dynsym = S['.dynsym']; dynstr = S['.dynstr']
def symname(i):
    o = dynsym['off'] + i * dynsym['entsize']; st = struct.unpack_from("<I", elf, o)[0]
    s = dynstr['off'] + st; return elf[s:elf.index(b"\0", s)].decode()
rela = S['.rela.plt']; got2sym = {}
for k in range(rela['size'] // 24):
    o = rela['off'] + k * 24
    r_off, r_info, _ = struct.unpack_from("<QQq", elf, o); got2sym[r_off] = symname(r_info >> 32)
plt = S['.plt']; plt2sym = {}
base = None
for ins in md.disasm(elf[plt['off']:plt['off'] + plt['size']], plt['addr']):
    if ins.mnemonic == 'adrp' and ins.op_str.startswith('x16,'): base = ins.operands[1].imm
    if ins.mnemonic == 'ldr' and ins.op_str.startswith('x17, [x16'):
        off = 0
        for op in ins.operands:
            if op.type == 3: off = op.mem.disp
        plt2sym[ins.address & ~0xF] = got2sym.get(base + off, '?')

# scan 0x12cb74 .. 0x12e600 for bl + ret + prologues to find extent
lo, hi = 0x12cb74, 0x12e600
rets, prologues, calls = [], [], {}
for ins in md.disasm(elf[lo:hi], lo):
    if ins.mnemonic == "ret":
        rets.append(ins.address)
    if ins.mnemonic == "stp" and "x29, x30, [sp" in ins.op_str and "#-0x" in ins.op_str.replace(" ", ""):
        prologues.append((ins.address, ins.op_str))
    if ins.mnemonic == "bl":
        t = int(ins.op_str.lstrip("#"), 16)
        calls.setdefault((t, plt2sym.get(t, "")), []).append(ins.address)

print("prologues in range:", [(hex(a), s) for a, s in prologues])
print("rets in range (first 12):", [hex(a) for a in rets[:12]])
print("\nbl targets 0x12cb74..0x12e600:")
for (t, s), addrs in sorted(calls.items()):
    print("  0x%-7x %-16s x%d @ %s" % (t, s if s else "", len(addrs),
          ",".join(hex(a) for a in addrs[:10])))
