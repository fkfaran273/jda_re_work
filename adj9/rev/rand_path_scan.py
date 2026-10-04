"""rand_path_scan.py - call graph + prologue finder + rand/srand census for libsigner.so.

Usage:
  python rand_path_scan.py census            # all bl to rand/srand/time in whole .text
  python rand_path_scan.py callers <va>      # all bl sites targeting va
  python rand_path_scan.py prologues <lo> <hi>  # prologue candidates in range
  python rand_path_scan.py xrefs             # any data/branch refs to va from .text
"""
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elf import ELF
from decryptors import LIB

e = ELF(LIB)
t = e.byname[".text"]
off, va0, size = t["offset"], t["addr"], t["size"]
words = struct.unpack_from("<%dI" % (size // 4), e.data, off)

def dec(lo, hi):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    o = e.vaddr_to_off(lo)
    for ins in md.disasm(e.data[o:o + (hi - lo)], lo):
        yield ins

def bl_sites(target):
    """all bl sites in .text whose target == target (direct bl only)."""
    hits = []
    for i, w in enumerate(words):
        if (w >> 26) == 0x25:  # BL
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            tgt = va0 + i * 4 + imm * 4
            if tgt == target:
                hits.append(va0 + i * 4)
    return hits

def census():
    rand = e.imports.get("rand"); srand = e.imports.get("srand")
    time_ = e.imports.get("time"); lrand = e.imports.get("lrand48")
    srand48 = e.imports.get("srand48"); random_ = e.imports.get("random")
    srandom_ = e.imports.get("srandom")
    print("PLT: rand=%x srand=%x time=%x lrand48=%s srand48=%s random=%s srandom=%s" % (
        rand or 0, srand or 0, time_ or 0,
        hex(lrand) if lrand else None, hex(srand48) if srand48 else None,
        hex(random_) if random_ else None, hex(srandom_) if srandom_ else None))
    for name, tgt in [("rand", rand), ("srand", srand), ("time", time_),
                      ("lrand48", lrand), ("srand48", srand48),
                      ("random", random_), ("srandom", srandom_)]:
        if tgt is None:
            continue
        sites = bl_sites(tgt)
        print("%-8s plt=0x%x  %d direct bl sites: %s" % (
            name, tgt, len(sites), " ".join(hex(s) for s in sites)))

def prologues(lo, hi):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    o = e.vaddr_to_off(lo)
    ins_list = list(md.disasm(e.data[o:o + (hi - lo)], lo))
    for i, ins in enumerate(ins_list):
        if ins.mnemonic == "stp" and "x29" in ins.op_str and "x30" in ins.op_str:
            # look ahead for mov x29, sp within 3 insns
            nxt = [x.mnemonic + " " + x.op_str for x in ins_list[i:i + 4]]
            if any(n.startswith("mov x29, sp") for n in nxt):
                print("0x%x  PROLOGUE: %s | %s" % (ins.address, nxt[0], nxt[1] if len(nxt) > 1 else ""))

def refs(target):
    """branches (b/bl/cbz/adr) to target anywhere in .text"""
    hits = []
    for i, w in enumerate(words):
        op = w >> 26
        va = va0 + i * 4
        tgt = None
        if op == 0x25 or op == 0x05:  # BL / B
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            tgt = va + imm * 4
        elif (w >> 24) == 0x34 or (w >> 24) == 0x35 or (w >> 24) == 0x36 or (w >> 24) == 0x37:
            # cbz/cbnz/tbz/tbnz family (19-bit imm for cbz)
            imm = (w >> 5) & 0x7FFFF
            if imm & 0x40000:
                imm -= 0x80000
            tgt = va + imm * 4
        if tgt == target:
            hits.append(va)
    print("refs to 0x%x: %s" % (target, " ".join(hex(h) for h in hits)))

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "census"
    if cmd == "census":
        census()
    elif cmd == "callers":
        for va in bl_sites(int(sys.argv[2], 16)):
            print(hex(va))
    elif cmd == "prologues":
        prologues(int(sys.argv[2], 16), int(sys.argv[3], 16))
    elif cmd == "refs":
        refs(int(sys.argv[2], 16))
