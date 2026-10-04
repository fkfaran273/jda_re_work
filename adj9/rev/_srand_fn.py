"""Full disassembly of the srand/stamp function 0x12cb74 and its generator
0x147d3c — does the body consume the same rand() stream as the header?"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

elf = open(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
live = open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/device/rwdata2.bin", "rb").read()
LIVE_VA0 = 0x14C000

def live_cstr(va):
    o = va - LIVE_VA0
    if o < 0 or o >= len(live): return None
    end = live.find(b"\0", o)
    if end < 0 or end - o > 200: end = o + 200
    b = live[o:end]
    try:
        t = b.decode()
        if all(32 <= ord(c) < 127 or c in "\n\t" for c in t): return t
    except Exception: pass
    return None

# plt map
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
    print("=" * 22, label, hex(lo), "..", hex(hi))
    adrp = {}
    for ins in md.disasm(elf[lo:hi], lo):
        tag = ""
        if ins.mnemonic == "bl":
            t = int(ins.op_str.lstrip("#"), 16)
            tag = "   -> " + (plt2sym.get(t) or ("fn 0x%x" % t))
        if ins.mnemonic in ("adrp", "adr") and len(ins.operands) == 2:
            try:
                reg = ins.reg_name(ins.operands[0].reg); imm = ins.operands[1].imm
                if ins.mnemonic == "adrp": adrp[reg] = imm
                else:
                    st = live_cstr(imm)
                    tag += "   ; %r" % st if st else ""
            except Exception: pass
        if ins.mnemonic == "add" and len(ins.operands) == 3 and ins.operands[2].type == 2:
            try:
                d = ins.reg_name(ins.operands[0].reg); sr = ins.reg_name(ins.operands[1].reg)
                if sr in adrp:
                    va = adrp[sr] + ins.operands[2].imm
                    st = live_cstr(va)
                    if st: tag += "   ; %r" % st
            except Exception: pass
        print("  %06x: %-8s %-34s%s" % (ins.address, ins.mnemonic, ins.op_str, tag))

# how big is 0x12cb74? find the next stack_chk_fail or known fn boundary; dump 0x400
dis(0x12cb74, 0x12cb74 + 0x420, "stamp fn")
print()
dis(0x147d3c, 0x147d3c + 0x300, "generator 0x147d3c")
