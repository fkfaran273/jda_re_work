"""Probe the JNI-entry callees that could build the body:
0xda97c, 0x13d874, 0x1483e0, 0xbb548 (+ worker 0x9afa4 wider).
Print calls, string refs, and any SHA-1/H constants materialised."""
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

SHA1_ANCHORS = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
                0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6}

def probe(fn, span, label):
    print("=" * 22, label, hex(fn), "span", hex(span))
    seen = {}
    adrp = {}
    for ins in md.disasm(elf[fn:fn + span], fn):
        if ins.mnemonic == "bl":
            t = int(ins.op_str.lstrip("#"), 16)
            s = plt2sym.get(t, "")
            seen.setdefault((t, s), []).append(ins.address)
        if ins.mnemonic in ("adrp", "adr") and len(ins.operands) == 2:
            try:
                reg = ins.reg_name(ins.operands[0].reg); imm = ins.operands[1].imm
                if ins.mnemonic == "adrp": adrp[reg] = imm
                else:
                    st = live_cstr(imm)
                    if st: print("   %06x: adr %s 0x%x %r" % (ins.address, reg, imm, st))
            except Exception: pass
        if ins.mnemonic == "add" and len(ins.operands) == 3 and ins.operands[2].type == 2:
            try:
                d = ins.reg_name(ins.operands[0].reg); sr = ins.reg_name(ins.operands[1].reg)
                if sr in adrp:
                    va = adrp[sr] + ins.operands[2].imm
                    st = live_cstr(va)
                    if st: print("   %06x: %s 0x%x %r" % (ins.address, d, va, st))
            except Exception: pass
        # mov/movk wide immediates that match SHA-1 constants
        if ins.mnemonic in ("mov", "movk", "movz"):
            for op in ins.operands:
                if op.type == 2 and op.imm in SHA1_ANCHORS:
                    print("   %06x: %s %s   *** SHA-1 constant 0x%x" % (ins.address, ins.mnemonic, ins.op_str, op.imm))
    for (t, s), addrs in sorted(seen.items()):
        print("  bl 0x%-7x %-16s x%d @ %s" % (t, s if s else "", len(addrs),
              ",".join(hex(a) for a in addrs[:10])))
    print()

probe(0xda97c, 0x800, "0xda97c (JNI callee)")
probe(0x13d874, 0x800, "0x13d874 (JNI callee x2)")
probe(0x1483e0, 0x1000, "0x1483e0 (JNI callee x4)")
probe(0xbb548, 0x800, "0xbb548 (output materializer)")
probe(0x9afa4, 0x1400, "worker 0x9afa4 (wider)")
