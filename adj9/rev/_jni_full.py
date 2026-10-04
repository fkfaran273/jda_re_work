"""Full call-site enumeration for the JNI entry starting 0xdb1cc, and deep
probe of fn 0xe2be0 and pthread worker 0x9afa4."""
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

def calls_in(lo, hi, label):
    print("=" * 20, label, hex(lo), "..", hex(hi))
    seen = {}
    for ins in md.disasm(elf[lo:hi], lo):
        if ins.mnemonic == "bl":
            t = int(ins.op_str.lstrip("#"), 16)
            s = plt2sym.get(t, "")
            seen.setdefault((t, s), []).append(ins.address)
    for (t, s), addrs in sorted(seen.items()):
        print("  0x%-7x %-18s x%d  @ %s" % (t, s if s else "", len(addrs),
              ",".join(hex(a) for a in addrs[:8])))

calls_in(0xdb1cc, 0xdc400, "JNI entry region 0xdb1cc")
print()
calls_in(0x9afa4, 0x9b600, "worker 0x9afa4")
print()
calls_in(0xe2be0, 0xe3144, "fn 0xe2be0 (full, to 0xe3144)")
