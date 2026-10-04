"""cmp_native_vs_F.py — does the pure-Python F.region model reproduce the TRUE
native (Unicorn post-head) d0 for the same seed?

The live mint path uses adj9_signer.region -> native_d0.posthead_region_native
(the real libsigner nSign under Unicorn, ~115 s/call).  F.region is the cheap
pure-Python alternative.  If NO head makes F.region agree with the native d0,
then every mint that falls back to the Python model ships a byte-wrong #0
(144 B) — which is exactly the class of defect that costs the click->install
join while leaving params, CTIT, TLS and HMAC all looking perfect.

Run:  python cmp_native_vs_F.py [seed]
"""
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "signer"))
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

import F as Fmod                                            # noqa: E402
import adj9_signer as S                                     # noqa: E402
import mint_pipeline as MP                                  # noqa: E402
import native_d0                                            # noqa: E402

SEED = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xD124F72B


def be(ws):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)


def main():
    print("seed = %#010x" % SEED)
    t0 = time.time()
    nd0, nd2, nd4 = native_d0.posthead_region_native(SEED)
    print("native post-head d0 from the REAL signer (%.1fs):" % (time.time() - t0))
    print("  d2 = %#010x" % nd2)
    print("  d0 = %s" % " ".join("%08x" % x for x in nd0[:8]))
    nb = be(nd0)
    print()

    heads = [("F.HEAD_FIRST", Fmod.HEAD_FIRST),
             ("F.HEAD_RESIGN", Fmod.HEAD_RESIGN),
             ("SYNTH_FIRST", Fmod.SYNTH_HEAD_FIRST),
             ("SYNTH_RESIGN", Fmod.SYNTH_HEAD_RESIGN),
             ("SYNTH_RESIGN_ALT", Fmod.SYNTH_HEAD_RESIGN_ALT),
             ("DEVICE_SELECTORS", MP.DEVICE_SELECTORS),
             ("None", None)]
    exact = []
    for hname, h in heads:
        d0w, d2v, d4w = Fmod.region(SEED, 0, 0, h)
        m0 = be(d0w) == nb
        if m0:
            exact.append(hname)
        ndiff = sum(1 for a, b in zip(be(d0w), nb) if a != b)
        print("F.region head=%-18s d0=%-5s  bytes differing = %3d/144"
              % (hname, "EXACT" if m0 else "diff", ndiff))
    print()
    print("VERDICT: F.region reproduces the native d0 with: %s"
          % (", ".join(exact) if exact else "NO HEAD AT ALL"))
    if not exact:
        fw, _, _ = Fmod.region(SEED, 0, 0, Fmod.HEAD_FIRST)
        print("  native d0[0:6] = %s" % " ".join("%08x" % x for x in nd0[:6]))
        print("  F.py   d0[0:6] = %s" % " ".join("%08x" % x for x in fw[:6]))
        print("  -> the Python d0 model is structurally wrong, not just mis-headed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
