"""fn.py - exact-entry function dumper for libsigner.so.

dump_fn.py guesses the function start by scanning back for a prologue, which lands
on the WRONG function whenever an entry has a non-standard prologue (e.g. 0x95fc4
starts with 'sub sp, sp, #0x80', no stp). This dumper starts at the exact entry VA
and walks forward to the first 'ret' (or __stack_chk_fail epilogue), reporting:

  * every bl -> sub_xxx / PLT import (callgraph one level)
  * every adrp/adr target with the data bytes / string there
  * immediates that look like descriptor lengths (90=#10 session, 144=#0, 32=#4,
    0x21f/0x1f6 desc lengths, 0x54/0x5a/0x60)
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF

SO = r"C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so"
E = ELF(SO)
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

LENS = {0x5A: "#10 session(90dw)", 0x90: "#0 144B", 0x20: "#4 32B",
        0x1F6: "#7 502", 0x211: "#7 529", 0x54: "84", 0x60: "96",
        0x168: "#7 360", 0x183: "#7 387", 0x4C: "76"}


def body(entry, cap=0x1400):
    raw = E.read(entry, cap)
    if not raw:
        return []
    out, nret = [], 0
    for ins in MD.disasm(raw, entry):
        out.append(ins)
        if ins.mnemonic == "ret":
            nret += 1
            if nret >= 1:
                break
        if len(out) >= cap // 4:
            break
    return out


def describe(addr, n=24):
    b = E.read(addr, n)
    if not b:
        return "?"
    s = b.split(b"\x00")[0]
    if len(s) >= 4 and all(32 <= c < 127 for c in s):
        return "%r" % s[:20]
    if len(b) >= 8:
        q = struct.unpack_from("<Q", b, 0)[0]
        return "q0=0x%x" % q
    return b[:12].hex()


def dump(entry, out_path):
    ins = body(entry)
    calls, adrs, lens = [], [], []
    for i in ins:
        if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
            t = i.operands[0].imm
            calls.append((i.address, t, E.plt_map.get(t, "")))
        if i.mnemonic in ("adrp", "adr"):
            adrs.append((i.address, i.mnemonic, i.operands[1].imm))
        if i.mnemonic == "mov" and i.operands:
            for op in i.operands:
                if op.type == 2 and op.imm in LENS:
                    lens.append((i.address, op.imm, LENS[op.imm]))
    with open(out_path, "w") as f:
        f.write("entry 0x%x : %d insns\n" % (entry, len(ins)))
        f.write("== calls ==\n")
        for a, t, nm in calls:
            f.write("  0x%-6x -> 0x%-6x %s\n" % (a, t, nm or "sub_%x" % t))
        f.write("== adrp/adr ==\n")
        for a, m, t in adrs:
            f.write("  0x%-6x %-4s 0x%-7x %s\n" % (a, m, t, describe(t)))
        f.write("== interesting immediates ==\n")
        for a, v, nm in lens:
            f.write("  0x%-6x #0x%x %s\n" % (a, v, nm))
        f.write("== body ==\n")
        for i in ins:
            ex = ""
            if i.mnemonic == "bl" and i.operands and i.operands[0].type == 2:
                t = i.operands[0].imm
                ex = "  ; -> %s" % (E.plt_map.get(t) or ("sub_%x" % t))
            f.write("0x%x  %-8s %s%s\n" % (i.address, i.mnemonic, i.op_str, ex))
    print("entry 0x%x: %d insns, %d calls, %d adrp/adr -> %s"
          % (entry, len(ins), len(calls), len(adrs), out_path))
    for a, t, nm in calls:
        print("   0x%-6x -> %s" % (a, nm or ("sub_%x" % t)))


if __name__ == "__main__":
    for a in (int(x, 16) for x in sys.argv[1:]):
        dump(a, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "fn_%x.log" % a))