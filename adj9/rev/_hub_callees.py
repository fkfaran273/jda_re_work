"""Identify each callee of the nSign hub / JNI entry:
0xe2be0, 0x95fc4, 0xe4a7c, 0xf9dc, 0xda4b4, 0xda6b8, 0x13de90, 0xe293c,
0x1bb5c, 0x232ec, 0x14868, 0x1bbb4, 0x12cb74.
For each: prologue, bl calls in first 0x300, adrp/adr targets w/ live strings,
and JNI-function usage via imported symbols."""
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
    return b if all(32 <= c < 127 for c in b[:min(len(b),40)]) else b[:40]

# plt/dynsym
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

# full dynsym imports (for JNI-ish names)
imports = {}
for i in range(dynsym['size'] // dynsym['entsize']):
    o = dynsym['off'] + i * dynsym['entsize']
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", elf, o)
    if st_value == 0 and st_name:
        s = dynstr['off'] + st_name
        imports[st_value] = elf[s:elf.index(b"\0", s)].decode()

def probe(fn, span=0x300):
    print("=" * 24, "fn 0x%x" % fn)
    seen_adrp = {}
    calls = []
    end = min(fn + span, len(elf) - 4)
    for ins in md.disasm(elf[fn:end], fn):
        if ins.mnemonic == "bl":
            t = int(ins.op_str.lstrip("#"), 16)
            calls.append((ins.address, t, plt2sym.get(t, "")))
        if ins.mnemonic in ("adrp", "adr") and len(ins.operands) == 2:
            try:
                reg = ins.reg_name(ins.operands[0].reg); imm = ins.operands[1].imm
                if ins.mnemonic == "adrp": seen_adrp[reg] = (imm, ins.address)
                else:
                    s = live_cstr(imm)
                    if s: print("   %06x: adr %s -> 0x%x %r" % (ins.address, reg, imm, s))
            except Exception: pass
        if ins.mnemonic == "add" and len(ins.operands) == 3 and ins.operands[2].type == 2:
            try:
                d = ins.reg_name(ins.operands[0].reg); sr = ins.reg_name(ins.operands[1].reg)
                if sr in seen_adrp:
                    va = seen_adrp[sr][0] + ins.operands[2].imm
                    s = live_cstr(va)
                    if s: print("   %06x: %s -> 0x%x %r" % (ins.address, d, va, s))
            except Exception: pass
    for a, t, s in calls[:24]:
        print("   %06x: bl 0x%-7x %s" % (a, t, s if s else ""))

for fn in (0xe2be0, 0x95fc4, 0xe4a7c, 0xf9dc, 0xda4b4, 0xda6b8,
           0x13de90, 0xe293c, 0x1bb5c, 0x232ec, 0x14868, 0x1bbb4, 0x12cb74):
    probe(fn)
    print()
