"""block_pass1.py — pass-1 spy: dump MAIN 685..692 (SHA state) + 821..892
(message window) writes with step numbers, for an arbitrary signing config.

Usage:
  python block_pass1.py                 # r0 base config
  python block_pass1.py r3_claim        # any probe_runs RUNS tag
"""
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ALG = os.path.dirname(HERE)
REV = os.path.dirname(ALG)
sys.path.insert(0, REV)
sys.path.insert(0, ALG)

from fin_vm2 import FinEx, FinStream          # noqa: E402
from probe_runs import BASE_CLAIMS, build_descs as _bd  # noqa: E402
import probe_runs as PR                        # noqa: E402
from dump_streams import build_descs, SEC, SEED  # noqa: E402

MAIN = 0x5450001000
EMITS = []
_OWNER = {}
_orig_emit = FinStream.emit


def emit_spy(self, n, v):
    n &= 0xFFFFFFFF
    v &= 0xFFFFFFFF
    top = self.top[-1]
    _orig_emit(self, n, v)
    ex = _OWNER.get(self.va)
    EMITS.append(((ex.steps if ex else -1), self.va, top, n, v, top + n))


def run(tag=None, descs=None, sec=SEC):
    EMITS[:] = []
    FinStream.emit = emit_spy
    if descs is None:
        if tag in (None, "r0_base"):
            descs = build_descs()
        else:
            claims = dict(BASE_CLAIMS)
            for t, s, sd, tw in PR.RUNS:
                if t == tag:
                    sec, sd = s, sd
                    claims.update(tw)
                    break
            from desc10_law import build_desc10
            import F as FP
            raw = build_desc10(claims, "session").encode("latin1")
            padded = raw + b"\x00" * (-len(raw) % 4)
            d0w, d2w, d4w = FP.region(sd, 0, 0, head=(0x2B, 0x48))
            d0 = b"".join(struct.pack(">I", w) for w in d0w)
            d4 = b"".join(struct.pack(">I", w) for w in d4w)
            D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
            D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
            by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
                  2: (1, 0, struct.pack(">I", d2w)),
                  7: (1, 0, struct.pack(">I", len(raw))),
                  10: (len(padded) // 4, 0, padded),
                  5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
                  1: (0, 0, b""), 3: (0, 0, b"")}
            descs = [by[i] for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]]
    ex = FinEx(sec, descs)
    _OWNER.update({sva: ex for sva in ex.streams})
    t0 = time.time()
    status = ex.run(max_steps=40_000_000)
    print("status=%s steps=%d (%.1fs)" % (status, ex.steps, time.time() - t0))
    out = [[st, sva & 0xFFFFFFFFFFFF, top, n, v, idx]
           for (st, sva, top, n, v, idx) in EMITS]
    name = tag or "r0_base"
    json.dump(out, open(os.path.join(HERE, "emits_%s.json" % name), "w"))
    return out


def report(out):
    """Print the SHA-state chain (idx 685..692) and the message window."""
    seq = [(st, n, v) for (st, sva, top, n, v, idx) in out
           if sva == MAIN and top == 620 and 65 <= n <= 72 and st < 3100000]
    rounds = []
    i = 0
    while i + 7 < len(seq) and seq[i + 1][0] - seq[i][0] < 400:
        rounds.append((seq[i][0], [seq[i + j][2] for j in range(8)]))
        i += 8
    print("\n== state rounds (idx 685..692) ==")
    for st, s in rounds:
        print("%8d %s" % (st, " ".join("%08x" % w for w in s)))
    return rounds


if __name__ == "__main__":
    tag = sys.argv[1] if len(sys.argv) > 1 else None
    o = run(tag)
    report(o)