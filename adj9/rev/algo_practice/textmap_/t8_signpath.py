"""t8 -- disassemble nSign path + DRR users + nOnResume."""
import struct, json, sys
import capstone
from collections import defaultdict

P = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/libsigner.so"
d = open(P, 'rb').read()
fdes = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/fdes.json"))["fdes"]
fsize = {f[0]: f[1] for f in fdes}
gotplt_by_addr = {int(k, 16): v for k, v in json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/gotplt.json"))["gotplt"].items()}
plt_start, plt_end = 0x1489c0, 0x1489c0 + 0x4a0
plt_map = {}
md0 = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
ad = plt_start; adrpv = {}
while ad < plt_end:
    for ins in md0.disasm(d[ad:ad+16], ad):
        if ins.mnemonic == 'adrp':
            r, pg = ins.op_str.split(', ')
            adrpv[r] = int(pg.lstrip('#'), 0)
        elif ins.mnemonic == 'ldr' and adrpv:
            ops = ins.op_str; b = ops.find('[')
            if b != -1:
                inner = ops[b+1:ops.find(']')].split(',')
                base = inner[0].strip()
                off = int(inner[1].strip().lstrip('#'), 0) if len(inner) > 1 else 0
                if base in adrpv: plt_map[ad] = adrpv[base] + off
    ad += 16
name_of_plt = {stub: nm for stub, nm in ((s, gotplt_by_addr.get(g)) for s, g in plt_map.items()) if nm}

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

def dis(s, out=sys.stdout, maxn=None):
    z = fsize[s]
    print("\n=== %s (%d bytes) ===" % (hex(s), z), file=out)
    adrpv = {}
    n = 0
    for ins in md.disasm(d[s:s+z], s):
        m, ops = ins.mnemonic, ins.op_str
        note = ""
        if m == 'adrp':
            r, pg = ops.split(', ')
            adrpv[r] = int(pg.lstrip('#'), 0)
        elif m == 'bl':
            t = int(ops.lstrip('#'), 0)
            if plt_start <= t < plt_end:
                note = "  ; PLT -> " + name_of_plt.get(t, hex(t))
            else:
                note = "  ; -> " + hex(t)
        elif m in ('blr', 'br', 'ret'):
            note = "  ; INDIRECT" if m != 'ret' else ""
        elif m.startswith('ldr') or m.startswith('str'):
            b = ops.find('[')
            if b != -1 and adrpv:
                inner = ops[b+1:ops.find(']')].split(',')
                base = inner[0].strip()
                if base in adrpv:
                    off = int(inner[1].strip().lstrip('#'), 0) if len(inner) > 1 else 0
                    note = "  ; ABS 0x%x" % (adrpv[base] + off)
        print("  %08x: %-8s %-42s%s" % (ins.address, m, ops, note), file=out)
        n += 1
        if maxn and n >= maxn:
            print("  ... (truncated)", file=out)
            break

import io
buf = io.StringIO()
for s in (0xdb1cc, 0x13de90, 0x1483e0, 0x8be0, 0x8c14, 0x15384, 0xda4b0):
    dis(s, buf)
open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/textmap_/signpath_dis.txt", "w").write(buf.getvalue())
print("written signpath_dis.txt, %d bytes" % len(buf.getvalue()))
