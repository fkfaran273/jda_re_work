#!/usr/bin/env python
"""Dump + fingerprint the three functions that load the SHA-1/MD5 constant block.

0x12e5f4  loads BOTH q0 (H0..H3) and q1 (H4,K0,K1,K2)   <- prime suspect
0x8d400   loads q0 only
0x31924   loads q1 only

A real SHA-1 shows:  ror #27 (rotl 5), ror #2 (rotl 30), ror #31 (rotl 1)
and the 4th round constant ca62c1d6 materialised as an immediate.
"""
import io, os, sys
from elftools.elf.elffile import ELFFile
import capstone

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
HERE = os.path.dirname(os.path.abspath(__file__))
data = open(SO, "rb").read()
elf = ELFFile(io.BytesIO(data))
secs = {s.name: s for s in elf.iter_sections()}
text = secs[".text"]
TX_OFF, TX_VA, TX_SZ = text["sh_offset"], text["sh_addr"], text["sh_size"]

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
code = data[TX_OFF:TX_OFF + TX_SZ]

out = io.open(os.path.join(HERE, "dump_sha1_fn.txt"), "w", encoding="utf8")

FNS = [0x12E5F4, 0x8D400, 0x31924]
NSIGN_LO, NSIGN_SZ = 0xDB1CC, 3188

for fn in FNS:
    sub = code[fn - TX_VA: fn - TX_VA + 0x4000]
    insns = []
    for ins in md.disasm(sub, fn):
        insns.append(ins)
        if ins.mnemonic == "ret" and len(insns) > 8:
            break
    out.write("\n" + "=" * 70 + "\n")
    out.write("FUNCTION 0x%x   %d instructions to first ret\n" % (fn, len(insns)))
    out.write("=" * 70 + "\n")

    rors, adds, eors, movs, k4 = {}, 0, 0, {}, False
    for ins in insns:
        if ins.mnemonic.startswith("ror"):
            m = ins.op_str.split("#")
            if len(m) > 1:
                rors[m[1].strip()] = rors.get(m[1].strip(), 0) + 1
        if ins.mnemonic == "add" and "#" in ins.op_str:
            adds += 1
        if ins.mnemonic in ("eor", "eor3"):
            eors += 1
        if ins.mnemonic in ("mov", "movk", "movz", "movn"):
            if "#" in ins.op_str:
                try:
                    v = int(ins.op_str.split("#")[1].split(",")[0].strip(), 0)
                    movs[v] = movs.get(v, 0) + 1
                except Exception:
                    pass
        if "0xca62c1d6" in ins.op_str.lower() or "0xca62c1d5" in ins.op_str.lower():
            k4 = True
        out.write("  0x%x  %-10s %s\n" % (ins.address, ins.mnemonic, ins.op_str))
        if len(insns) > 400 and ins.address > fn + 0x2000:
            out.write("  ... (truncated)\n")
            break

    out.write("\n  fingerprint: ror amounts %s\n" % sorted(rors.items(), key=lambda x: -x[1])[:8])
    out.write("               add#=%d eor=%d  4th SHA1 K (ca62c1d6) as immediate: %s\n" % (adds, eors, k4))
    notable = [(hex(k), v) for k, v in movs.items() if k > 0xffff]
    out.write("               large immediates: %s\n" % notable[:12])

# ---- callers
out.write("\n\n=== callers (bl / b) of each function ===\n")
insns_all = list(md.disasm(code, TX_VA))
callers = {fn: [] for fn in FNS}
for ins in insns_all:
    if ins.mnemonic in ("bl", "b") and ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_IMM:
        t = ins.operands[0].imm
        if t in callers:
            callers[t].append(ins.address)
for fn in FNS:
    cs = callers[fn]
    out.write("\n  0x%x : %d caller(s)\n" % (fn, len(cs)))
    for c in cs[:40]:
        inside = NSIGN_LO <= c < NSIGN_LO + NSIGN_SZ
        out.write("      from 0x%x%s\n" % (c, "   <== INSIDE nSign body" if inside else ""))

out.close()
print("wrote dump_sha1_fn.txt")
