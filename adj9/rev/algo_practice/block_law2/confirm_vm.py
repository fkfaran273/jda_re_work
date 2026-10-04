"""confirm_vm.py — VM confirmation of the block law on an ARBITRARY claims
length (not a multiple of 4, and not one of the validated vectors).

Builds a synthetic signing with a claims payload of length L, runs the VM once,
and compares record[46:78) against predict_block().  Proves the SHA padding /
bit-length rule on a fresh (S, claims) pair that no other check covers.

Run: python confirm_vm.py [L]
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALG = os.path.dirname(HERE)
REV = os.path.dirname(ALG)
sys.path[:0] = [HERE, ALG, REV]

import predict_block as PB
from fin_vm2 import FinEx, FinStream
from whiten_decoder import whiten_body_inverse, head_words
from desc10_law import build_desc10
from probe_runs import BASE_CLAIMS
import F as FP

SEC = 1790625704
SEED = 0xA6DA5D2B
D8 = bytes.fromhex("bffffffffffffd1f0007000000000000")
D9 = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")
EMITS = []
_OWNER = {}
_orig = FinStream.emit


def spy(self, n, v):
    n &= 0xFFFFFFFF
    v &= 0xFFFFFFFF
    top = self.top[-1]
    _orig(self, n, v)
    ex = _OWNER.get(self.va)
    EMITS.append(((ex.steps if ex else -1), self.va, top, n, v, top + n))


def run(claims: bytes):
    padded = claims + b"\x00" * (-len(claims) % 4)
    d0w, d2w, d4w = FP.region(SEED, 0, 0, head=(0x2B, 0x48))
    d0 = b"".join(struct.pack(">I", w) for w in d0w)
    d4 = b"".join(struct.pack(">I", w) for w in d4w)
    by = {0: (36, 0, d0), 9: (5, 0, D9), 8: (4, 0, D8), 4: (8, 0, d4),
          2: (1, 0, struct.pack(">I", d2w)),
          7: (1, 0, struct.pack(">I", len(claims))),
          10: (len(padded) // 4, 0, padded),
          5: (1, 0, b"\x00\x00\x00\x00"), 6: (1, 0, b"\x00\x00\x00\x00"),
          1: (0, 0, b""), 3: (0, 0, b"")}
    descs = [by[i] for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]]
    EMITS[:] = []
    FinStream.emit = spy
    ex = FinEx(SEC, descs)
    _OWNER.update({s: ex for s in ex.streams})
    st = ex.run(max_steps=40_000_000)
    last = {}
    for (s, sva, top, n, v, idx) in EMITS:
        last[(sva & 0xFFFFFFFFFFFF, n & 0xFFFFFFFF)] = v & 0xFFFFFFFF
    blob = b"".join(struct.pack(">I", last[(0x5500000000, n)]) for n in range(48))
    return st, whiten_body_inverse(blob[16:160], blob[:16])


def main():
    base = build_desc10(BASE_CLAIMS, "session").encode("latin1")
    lens = [int(sys.argv[1])] if len(sys.argv) > 1 else [359, 361, 453]
    ok = n = 0
    for L in lens:
        claims = (base + b"XXXXX")[:L]
        st, rec = run(claims)
        got = PB.predict_block(claims, SEED, rec[3:19], D9)
        good = got == rec[46:78]
        n += 1
        ok += good
        print("L=%-4d vm=%-10s claims=%d  %s  %s"
              % (L, st, len(claims), "OK  " if good else "FAIL", got.hex()))
    print("-> %d/%d byte-exact vs the VM" % (ok, n))
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
