#!/usr/bin/env python
"""Find the code that references the SHA-1 / MD5 constant block in .rodata.

.rodata+0xc0 -> 67452301 efcdab89 98badcfe 10325476   (MD5 IV == SHA1 H0..H3)
.rodata+0xe0 -> c3d2e1f0 5a827999 6ed9eba1 8f1bbcdc   (SHA1 H4 + K0..K2)

Goal: identify the hash function(s), and whether they are reachable from nSign.
"""
import io, os, struct, pickle
from elftools.elf.elffile import ELFFile
import capstone

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
HERE = os.path.dirname(os.path.abspath(__file__))

data = open(SO, "rb").read()
elf = ELFFile(io.BytesIO(data))

secs = {}
for s in elf.iter_sections():
    secs[s.name] = s

text = secs[".text"]
rodata = secs[".rodata"]
TX_OFF, TX_VA, TX_SZ = text["sh_offset"], text["sh_addr"], text["sh_size"]
RO_OFF, RO_VA, RO_SZ = rodata["sh_offset"], rodata["sh_addr"], rodata["sh_size"]


def va2off(va):
    return va - TX_VA + TX_OFF


def off2va_rod(off):
    return off - RO_OFF + RO_VA


out = io.open(os.path.join(HERE, "find_hash_users.txt"), "w", encoding="utf8")
out.write(".text   va=0x%x off=0x%x size=0x%x\n" % (TX_VA, TX_OFF, TX_SZ))
out.write(".rodata va=0x%x off=0x%x size=0x%x\n\n" % (RO_VA, RO_OFF, RO_SZ))

# ---- the constant block
out.write("=== constant block, read as LE dwords ===\n")
for off in range(0x3610, 0x3660, 4):
    w = struct.unpack_from("<I", data, off)[0]
    note = ""
    for nm, v in (("MD5/SHA1 H0", 0x67452301), ("H1", 0xefcdab89), ("H2", 0x98badcfe),
                  ("H3", 0x10325476), ("SHA1 H4", 0xc3d2e1f0), ("SHA1 K0", 0x5a827999),
                  ("SHA1 K1", 0x6ed9eba1), ("SHA1 K2", 0x8f1bbcdc), ("SHA1 K3", 0xca62c1d6)):
        if w == v:
            note = "  <== " + nm
    out.write("  .rodata+0x%03x  va=0x%x  %08x%s\n" % (off - RO_OFF, off2va_rod(off), w, note))

# ---- targets: every dword in the block
targets = {}
for off in range(0x3618, 0x3654, 4):
    targets[off2va_rod(off)] = ".rodata+0x%x" % (off - RO_OFF)

# ---- disassemble .text, track adrp/add
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True
code = data[TX_OFF:TX_OFF + TX_SZ]
insns = list(md.disasm(code, TX_VA))

pages = {}
adrp_state = {}   # reg -> page va
hits = []
for ins in insns:
    if ins.mnemonic == "adrp" and ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_REG \
            and ins.operands[1].type == capstone.arm64.ARM64_OP_IMM:
        adrp_state[ins.reg_name(ins.operands[0].reg)] = ins.operands[1].imm
        continue
    if ins.mnemonic in ("add", "ldr", "str", "ldrb", "ldrh", "ldrsw") and ins.operands:
        ops = ins.operands
        # add xN, xM, #imm   (form the full address)
        if ins.mnemonic == "add" and len(ops) == 3 and ops[1].type == capstone.arm64.ARM64_OP_REG \
                and ops[2].type == capstone.arm64.ARM64_OP_IMM:
            reg = ins.reg_name(ops[1].reg)
            if reg in adrp_state:
                full = adrp_state[reg] + ops[2].imm
                pages[ins.reg_name(ops[0].reg)] = full
                if full in targets:
                    hits.append((ins.address, "adrp+add", targets[full], ins.mnemonic + " " + ins.op_str))
                continue
        # base+offset memory operand
        for op in ops:
            if op.type == capstone.arm64.ARM64_OP_MEM:
                base = ins.reg_name(op.mem.base)
                if base in adrp_state:
                    full = adrp_state[base] + op.mem.disp
                    if full in targets:
                        hits.append((ins.address, "adrp+mem", targets[full],
                                     ins.mnemonic + " " + ins.op_str))
                    break
                if base in pages:
                    full = pages[base] + op.mem.disp
                    if full in targets:
                        hits.append((ins.address, "addreg+mem", targets[full],
                                     ins.mnemonic + " " + ins.op_str))
                    break

out.write("\n=== code references to the SHA-1/MD5 constant block: %d ===\n" % len(hits))
by_addr = {}
for va, kind, tgt, txt in hits:
    by_addr.setdefault(va, []).append((kind, tgt, txt))
for va in sorted(by_addr):
    for kind, tgt, txt in by_addr[va]:
        out.write("  0x%x  %-12s %-14s %s\n" % (va, kind, tgt, txt))

# ---- which functions contain those addresses?
# build a crude function start list from the CFG pickle if present, else use bl targets
out.write("\n=== function containment: nearest preceding symbol/bl-target ===\n")
starts = set()
for ins in insns:
    if ins.mnemonic in ("bl", "b") and ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_IMM:
        starts.add(ins.operands[0].imm)
starts.add(TX_VA)
sl = sorted(starts)
import bisect
funcs = {}
for va in sorted(by_addr):
    i = bisect.bisect_right(sl, va) - 1
    f = sl[i] if i >= 0 else TX_VA
    funcs.setdefault(f, []).append(va)
for f in sorted(funcs):
    out.write("  func 0x%x  refs at %s\n" % (f, ", ".join("0x%x" % x for x in funcs[f])))

# ---- is any of them in the nSign CFG?
cfgp = os.path.join(HERE, "nsign_cfg.pkl")
if os.path.exists(cfgp):
    try:
        cfg = pickle.load(open(cfgp, "rb"))
        addrs = set()
        if isinstance(cfg, dict):
            for v in cfg.values():
                if isinstance(v, (set, list, tuple)):
                    addrs |= set(v)
                elif isinstance(v, int):
                    addrs.add(v)
        elif isinstance(cfg, (set, list, tuple)):
            addrs = set(cfg)
        out.write("\n=== nSign CFG contains %d addresses ===\n" % len(addrs))
        for f, vas in sorted(funcs.items()):
            for va in vas:
                out.write("  0x%x in nSign CFG: %s\n" % (va, va in addrs))
    except Exception as e:
        out.write("\n(nsign_cfg.pkl not usable: %r)\n" % (e,))

out.close()
print("wrote find_hash_users.txt")
