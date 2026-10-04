"""nSign call graph + 'which obfuscated strings does this subtree decrypt'."""
import sys, os, struct, pickle, bisect
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
from decryptors import LIB

NSIGN = 0xdb1cc
NSIGN_SIZE = 3188


def bl_targets(e, start, size):
    va0 = start
    n = size // 4
    words = struct.unpack_from("<%dI" % n, e.data, e.vaddr_to_off(start))
    plt_lo = e.byname[".plt"]["addr"]
    plt_hi = plt_lo + e.byname[".plt"]["size"]
    out = []
    for i, w in enumerate(words):
        if (w & 0xFC000000) != 0x94000000:
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        t = (va0 + i * 4) + imm * 4
        out.append((va0 + i * 4, t, plt_lo <= t < plt_hi))
    return out


def main(depth=4):
    e = ELF(LIB)
    sites, P = pickle.load(open("decrypt.pkl", "rb"))
    dec_va = sorted(P)
    dec_at = sorted((P[v][1], v) for v in P)   # store addr -> va

    # function starts = union of all BL targets in .text
    t = e.byname[".text"]
    all_words = struct.unpack_from("<%dI" % (t["size"] // 4), e.data, t["offset"])
    plt_lo = e.byname[".plt"]["addr"]; plt_hi = plt_lo + e.byname[".plt"]["size"]
    starts = set()
    for i, w in enumerate(all_words):
        if (w & 0xFC000000) == 0x94000000:
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            tt = (t["addr"] + i * 4) + imm * 4
            if not (plt_lo <= tt < plt_hi):
                starts.add(tt)
    starts = sorted(starts)

    def extent(fn):
        i = bisect.bisect_right(starts, fn)
        return (starts[i] if i < len(starts) else t["addr"] + t["size"]) - fn

    # BFS
    from collections import deque
    seen = {}
    q = deque([(NSIGN, 0, NSIGN_SIZE)])
    while q:
        fn, d, sz = q.popleft()
        if fn in seen:
            continue
        seen[fn] = (d, sz or extent(fn))
        if d >= depth or not sz:
            continue
        for at, tgt, is_plt in bl_targets(e, fn, min(sz or extent(fn), 0x40000)):
            if is_plt or tgt in seen:
                continue
            if t["addr"] <= tgt < t["addr"] + t["size"]:
                q.append((tgt, d + 1, None))
    # second pass: give extent to everything
    for fn in list(seen):
        if seen[fn][1] is None:
            seen[fn] = (seen[fn][0], extent(fn))
    return e, seen, dec_at, starts, extent


if __name__ == "__main__":
    e, seen, dec_at, starts, extent = main()
    print("nSign 0x%x size 0x%x" % (NSIGN, NSIGN_SIZE))
    print("reachable functions (depth<=4): %d" % len(seen))
    print()
    for fn, (d, sz) in sorted(seen.items(), key=lambda kv: (kv[1][0], kv[0])):
        lo, hi = fn, fn + sz
        inside = [(a, v) for a, v in dec_at if lo <= a < hi]
        print("d%d 0x%08x size=0x%-6x  decrypts: %s" %
              (d, fn, sz, ", ".join("0x%x" % v for a, v in inside) if inside else "-"))
