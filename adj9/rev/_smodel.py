"""_smodel.py - the region is f(S): d2=bswap32(S), d4=F._d4_words(S), d0=F._d0_words(d4,head).

Two questions:
  Q1  Does body depend on d4 at all?  (_perturb said NO: d4[0], d4[7] flips moved
      0/44 body words, and d0[35] moved 0/44.)  If true, the decoder only has to
      recover S (32 bits) -- d0 and d4 follow from S by F.py.
  Q2  Is the map S -> body injective and structured?  Sample random S, build the
      region, run FinEx, and record the body.
"""
import json, struct, sys, time
sys.path.insert(0, ".")
from fin_vm2 import FinEx
import F

VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
asg = json.load(open("all_signings.json"))
ph3 = json.load(open("pair_h3.json"))


def descs_of(r):
    out = []
    for bi in VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        out.append((len(data) // 4, 0, data))
    return out


def body(d, seed):
    ex = FinEx(seed, d)
    st = ex.run(max_steps=60_000_000)
    by = {}
    for (sva, n, v) in ex.emit_trace:
        if (sva & 0xFFFFFFFFFFFF) == 0x5500000000:
            by[n & 0xFFFFFFFF] = v & 0xFFFFFFFF
    return [by.get(i) for i in range(48)], st


def region_for_S(S, head):
    """Rebuild the #0/#2/#4 descriptors from S alone, in the F.py model."""
    d2 = struct.pack(">I", struct.unpack(">I", struct.pack("<I", S))[0])  # bswap32
    d4 = b"".join(struct.pack(">I", w) for w in F._d4_words(S))
    d0w = F._d0_words(F._d4_words(S), head)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    return d0, d2, d4


if __name__ == "__main__":
    i = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    r = asg[i]
    seed = ph3[i]["second"]
    S_cap = struct.unpack(">I", bytes.fromhex(r["d2"]))[0]
    S_cap = struct.unpack("<I", struct.pack(">I", S_cap))[0]   # undo bswap
    print("row %d second=%d S(captured)=%08x" % (i, seed, S_cap))
    d4c = F._d4_words(S_cap)
    d4cap = [struct.unpack_from(">I", bytes.fromhex(r["d4"]), 4 * j)[0]
             for j in range(8)]
    print("d4 model == capture:", ["%08x" % x for x in d4c] == ["%08x" % x for x in d4cap])
    d0cap = [struct.unpack_from(">I", bytes.fromhex(r["d0"]), 4 * j)[0]
             for j in range(36)]
    for hn, h in (("HEAD_FIRST", F.HEAD_FIRST), ("HEAD_RESIGN", F.HEAD_RESIGN),
                  ("HEAD_RESIGN_ALT", F.HEAD_RESIGN_ALT)):
        m = F._d0_words(d4c, h)
        eq = sum(1 for a, b in zip(m, d0cap) if a == b)
        print("  d0 vs %-15s %2d/36 match" % (hn, eq))
    print("captured d0:", " ".join("%08x" % x for x in d0cap[:8]))
    print("model   d0 :", " ".join("%08x" % x for x in F._d0_words(d4c, F.HEAD_FIRST)[:8]))
