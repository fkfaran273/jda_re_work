"""Resolve the openat path register (x22) at 0xe1f88 — the fd that feeds the
2048-byte read at 0xe3c44 (CTX_MODEL_DISPROVEN.md revised step 1).
Also trace how fn 0xe3144 consumes the 2048-byte buffer at sp+0xe0."""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_IMM, ARM64_OP_REG

elf = open(r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a/libsigner.so", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True

# --- live decrypted string dump (device/rwdata2.bin, va 0x14C000..0x156000) ---
live = open(r"C:/Users/Apps/Downloads/com.penti.app/adj9/device/rwdata2.bin", "rb").read()
LIVE_VA0 = 0x14C000

def live_bytes(va, n):
    o = va - LIVE_VA0
    if 0 <= o and o + n <= len(live):
        return live[o:o + n]
    return None

def live_cstr(va):
    o = va - LIVE_VA0
    if o < 0 or o >= len(live):
        return None
    end = live.find(b"\0", o)
    if end < 0 or end - o > 200:
        end = o + 200
    return live[o:end]

def live_cstr_back(va):
    """string that ENDS at va (pointer may point at the tail of an entry)"""
    o = va - LIVE_VA0
    if o < 0 or o >= len(live):
        return None
    start = max(0, o - 200)
    seg = live[start:o + 120]
    # find last NUL before o
    p = seg.rfind(b"\0", 0, o - start + 1)
    if p < 0:
        return None
    s = seg[p + 1:]
    end = s.find(b"\0")
    return s[:end] if end >= 0 else s

# ---------- find enclosing function of an address ----------
def find_prologue(va, back=0x4000):
    code = elf[va - back:va]
    starts = []
    for ins in md.disasm(code, va - back):
        if ins.mnemonic == "sub" and ins.op_str.startswith("sp, sp, #"):
            starts.append((ins.address, ins.op_str))
        if ins.mnemonic in ("stp",) and "x29, x30" in ins.op_str:
            starts.append((ins.address, "stp x29,x30 " + ins.op_str))
    return starts[-6:]

print("=== prologue candidates before 0xe1f88 ===")
for a, t in find_prologue(0xe1f88):
    print("  %06x  %s" % (a, t))

# ---------- disassemble window before openat site, track x22 ----------
def dis_window(lo, hi):
    out = []
    for ins in md.disasm(elf[lo:hi], lo):
        out.append(ins)
    return out

print("\n=== 0xe1e00..0xe2000 (openat site 0xe1f88) ===")
for ins in dis_window(0xe1e00, 0xe2000):
    tag = ""
    if ins.mnemonic == "bl":
        t = int(ins.op_str.lstrip("#"), 16); tag = " -> " + hex(t)
    print("  %06x: %-8s %-30s%s" % (ins.address, ins.mnemonic, ins.op_str, tag))

# ---------- find where x22 is set anywhere in 0xe1c00..0xe1f88 ----------
print("\n=== all x22 writes in 0xe1800..0xe1f88 ===")
for ins in dis_window(0xe1800, 0xe1f88):
    ops = ins.op_str.split(", ")
    if ops and ops[0] in ("x22", "w22"):
        print("  %06x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))

# ---------- adrp/adr literals in the window: any .data address? ----------
print("\n=== adrp/adr targets in 0xe1800..0xe2000 ===")
for ins in dis_window(0xe1800, 0xe2000):
    if ins.mnemonic in ("adrp", "adr"):
        # compute target
        try:
            if ins.mnemonic == "adrp":
                reg = ins.operands[0].reg
                imm = ins.operands[1].imm
                print("  %06x: adrp %s, 0x%x" % (ins.address, ins.reg_name(reg), imm))
            else:
                reg = ins.operands[0].reg
                imm = ins.operands[1].imm
                s = live_cstr(imm) or live_cstr_back(imm)
                print("  %06x: adr  %s, 0x%x  live=%r" % (ins.address, ins.reg_name(reg), imm, s))
        except Exception as e:
            print("  %06x: %s %s  (%s)" % (ins.address, ins.mnemonic, ins.op_str, e))

# adrp+add pairs -> full addresses
print("\n=== adrp+add pairs (0xe1800..0xe2000) with live strings ===")
adrp = {}
for ins in dis_window(0xe1800, 0xe2000):
    if ins.mnemonic == "adrp" and len(ins.operands) == 2:
        adrp[ins.reg_name(ins.operands[0].reg)] = (ins.operands[1].imm, ins.address)
    elif ins.mnemonic == "add" and len(ins.operands) == 3 and ins.operands[2].type == ARM64_OP_IMM:
        d = ins.reg_name(ins.operands[0].reg); s = ins.reg_name(ins.operands[1].reg)
        if s in adrp:
            va = adrp[s][0] + ins.operands[2].imm
            s1 = live_cstr(va); s2 = live_cstr_back(va)
            print("  %06x: %s = 0x%x   live@va=%r  back=%r" % (ins.address, d, va, s1, s2))
