"""Enumerate bl sites + structure of the nSign hub (0xda99c, frame 0x210) and
the JNI entry 0xdb1cc. Goal: candidate live call sites for the body path."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

elf = open(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True

# plt resolver (same as _e2be0.py)
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

def dis(lo, hi, label):
    print("=" * 20, label, hex(lo), "..", hex(hi))
    for ins in md.disasm(elf[lo:hi], lo):
        tag = ""
        if ins.mnemonic == "bl":
            t = int(ins.op_str.lstrip("#"), 16)
            tag = "  -> %s" % plt2sym.get(t, "fn 0x%x" % t)
        if ins.mnemonic in ("bl", "adr", "adrp") or (ins.mnemonic == "ldr" and "[x29" in ins.op_str):
            print("  %06x: %-8s %-30s%s" % (ins.address, ins.mnemonic, ins.op_str, tag))

# JNI entry 0xdb1cc: what is it? disassemble its head
dis(0xdb1cc, 0xdb280, "JNI entry 0xdb1cc")
print()
# hub 0xda99c: scan whole plausible range for bl sites
dis(0xda99c, 0xdb1cc, "hub 0xda99c")
