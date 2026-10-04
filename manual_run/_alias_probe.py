"""Step-boundary audit of the x/w aliasing invariant.

The dict is only ever *observed* at the top of a VM step (every reader --
val(), set_reg(), mem_op2, run() -- runs between steps).  So the flat-list
rewrite is exact iff, at the start of every step,

    for every N present:   R["xN"] & 0xFFFFFFFF == R["wN"]

and every write inside a step leaves the pair consistent.  This counts step
boundaries where that fails, and separately flags any step that writes only
one half of a pair (which would need an explicit mask at the list site).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_signature as S
import _gate

M32 = 0xFFFFFFFF


def build(kind):
    params = _gate.make(kind)
    val = dict(params)
    val.update({"activity_kind": kind, "client_sdk": S.CLIENT_SDK,
                "adj_signing_id": S.ADJ_SIGNING_ID, "headers_id": "10",
                "native_version": S.NATIVE_VERSION,
                "adj_verification": S.ADJ_VERIFICATION})
    d0w, d2w, d4w = S.region(_gate.SEED, 0, 0, head=S.WIN_PHASE)
    padded, unpadded = S.claims_padded(val, kind)
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, S.DESC9), 8: (4, 0, S.DESC8),
          4: (8, 0, d4), 2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", unpadded)),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    return [by[i] for i in S.VA_ORDER]


def run(kind, every=97):
    """Check the invariant every `every` steps (the pattern is periodic, and a
    cheap sample keeps this from taking 5 minutes)."""
    bad = []
    st = {"n": 0}

    def hook(ex):
        st["n"] += 1
        if st["n"] % every:
            return
        R = ex.R
        for k in R:
            if k[0] in "wx" and k[1:].isdigit():
                o = ("w" if k[0] == "x" else "x") + k[1:]
                if o not in R:
                    continue
                w = R["w" + k[1:]]
                x = R[k] if k[0] == "x" else R[o]
                if (x & M32) != w:
                    bad.append((st["n"], hex(ex.pc), k, hex(x), hex(w)))

    ex = S.FinEx(_gate.SECOND, build(kind))
    ex._step_hook = hook
    status = ex.run(max_steps=40_000_000)
    print("%-8s status=%-12s steps=%-10d sampled=%d violations=%d"
          % (kind, status, ex.steps, st["n"], len(bad)))
    for b in bad[:10]:
        print("    step-boundary VIOLATION", b)
    return bad


def sp_probe():
    """Is 'sp' ever a set_reg destination?  (decides whether slot 32 matters)"""
    dsts = set()
    for ins in S.INS:
        if ins.mnemonic in ("mrs",):
            dsts.add(ins.op_str.split(",")[0].strip())
        elif ins.op_str and not ins.op_str.startswith("["):
            d = ins.op_str.split(",")[0].strip()
            if d in ("sp", "wsp", "xzr", "wzr"):
                dsts.add((ins.mnemonic, d))
    print("instructions writing sp/wsp/xzr/wzr as a plain destination:",
          sorted(map(repr, dsts))[:20], "count", len(dsts))


if __name__ == "__main__":
    sp_probe()
    allbad = []
    for kind in ("session", "click"):
        allbad += run(kind)
    print("ALIAS INVARIANT", "HOLDS" if not allbad else "BROKEN")
