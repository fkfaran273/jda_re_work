import sys, struct, capstone

PATH = r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so"
data = open(PATH, 'rb').read()
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from('<IIQQQQIIQQ', data, o)
    secs.append(dict(name=name, addr=addr, off=off, size=size))
sh = secs[e_shstrndx]
def nm(n):
    s = sh['off'] + n
    return data[s:data.index(b'\0', s)].decode()
text = None
for s in secs:
    s['nm'] = nm(s['name'])
    if s['nm'] == '.text':
        text = s
base, off, size = text['addr'], text['off'], text['size']
code = data[off:off + size]

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True

start = int(sys.argv[1], 16) if not sys.argv[1].startswith('0x') else int(sys.argv[1], 16)
count = int(sys.argv[2]) if len(sys.argv) > 2 else 400
s = start - base
for ins in md.disasm(code[s:s + count * 4], start):
    ops = ins.op_str
    if ins.mnemonic in ('bl', 'b', 'b.eq', 'b.ne', 'cbz', 'cbnz', 'tbz', 'tbnz', 'blt', 'bgt', 'b.le', 'b.gt', 'b.ls', 'b.hi', 'b.lt', 'b.ge', 'br'):
        try:
            t = int(ins.operands[-1].imm)
            ops = ops.replace(hex(t), hex(t))
        except Exception:
            pass
    print("0x%x  %-10s %s" % (ins.address, ins.mnemonic, ops))
    if ins.mnemonic == 'ret' and ins.address > start + 32:
        pass
