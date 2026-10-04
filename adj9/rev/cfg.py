"""Control-flow crawl from nSign: follow every direct branch, step over BL/BLR.
Result = the exact set of instruction addresses nSign can execute."""
import sys, os, struct, pickle
import capstone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
from decryptors import LIB

NSIGN = 0xdb1cc

TERM = {"ret", "br", "braa", "brab", "retab", "retaa", "eret", "drps"}
COND_B = {"b"}


def crawl(e, entry, max_blocks=400000, max_steps=3000000):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    lo = e.byname[".text"]["addr"]
    hi = lo + e.byname[".text"]["size"]
    plt_lo = e.byname[".plt"]["addr"]
    plt_hi = plt_lo + e.byname[".plt"]["size"]

    visited = set()      # block starts
    insns = set()        # every executed instruction address
    callees = set()      # BL targets (internal)
    imports = set()
    work = [entry]
    steps = 0
    cache_off = None
    cache = b""
    while work:
        blk = work.pop()
        if blk in visited or len(visited) > max_blocks:
            continue
        visited.add(blk)
        if not (lo <= blk < hi):
            continue
        # read a chunk; stop the block at a terminator
        o = e.vaddr_to_off(blk)
        chunk = e.data[o:o + 0x4000]
        for ins in md.disasm(chunk, blk):
            steps += 1
            if steps > max_steps:
                return visited, insns, callees, imports
            insns.add(ins.address)
            if not (lo <= ins.address < hi):
                break
            m = ins.mnemonic
            if m in TERM:
                break
            if m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
                t = ins.operands[-1].imm
                work.append(t)
                continue
            if m == "b":
                t = ins.operands[-1].imm
                work.append(t)
                break
            if m == "bl":
                t = ins.operands[-1].imm
                if plt_lo <= t < plt_hi:
                    imports.add(t)
                else:
                    callees.add(t)
                    work.append(t)      # descend into the callee too
                continue
            if m == "blr":
                break
    return visited, insns, callees, imports


def main():
    e = ELF(LIB)
    visited, insns, callees, imports = crawl(e, NSIGN)
    print("nSign CFG crawl")
    print("  blocks reached      : %d" % len(visited))
    print("  instructions reached: %d" % len(insns))
    print("  internal BL targets : %d" % len(callees))
    print("  PLT imports called  : %d" % len(imports))
    for t in imports:
        print("      %s" % e.plt_map.get(t, "?"))
    lo, hi = min(insns), max(insns)
    print("  address span        : 0x%x .. 0x%x" % (lo, hi))

    sites, P = pickle.load(open("decrypt.pkl", "rb"))
    print()
    print("  obfuscated strings decrypted on this path:")
    import decode_exact
    res = decode_exact.run()
    for va in sorted(P):
        l, s = P[va]
        if s in insns or l in insns:
            d = res.get(va)
            print("    0x%08x  key=0x%02x  %-40r  block 0x%x" %
                  (va, d["key"] if d else 0, d["text"] if d else "?", l))
    pickle.dump((sorted(insns), sorted(callees), sorted(imports)),
                open("nsign_cfg.pkl", "wb"))
    return e, insns


if __name__ == "__main__":
    main()
