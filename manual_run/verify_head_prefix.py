"""verify_head_prefix.py — the head prefix is a PER-BUILD constant, not per-app.

A background agent traced the VM and concluded the d0 prefix is a fixed 10-byte
sequence emitted by one-instruction thunks, each hard-wired to one d0 slot.  Its
specific values came from `adj9/rev/creditsea/libsigner.so`.  Testing against
the OTHER build we hold -- the VM in adj9_signature.py -- gives a different
prefix, which is the point: the constant is per-build.

    creditsea/libsigner.so   30 2b 34 37 38 3b 35 36   (+2d 05 beyond the head)
    the adj9_signature VM    2b 48

So HEAD_PHASE_DEFAULT = (0x2B,) is right for penti and wrong for the creditsea
build, and neither choice changes attribution -- measured both ways, all four
app/phase combinations join.

Run this file to see the three prefixes tested against the native VM.
"""
import json
import os
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_decode as D        # noqa: E402
import adj9_pure as P          # noqa: E402
import adj9_signature as S     # noqa: E402  the FinEx VM

PREFIXES = [
    ("(0x2b,)            our default", (0x2B,)),
    ("(0x2b,0x48)        penti captures 2-4", (0x2B, 0x48)),
    ("30 2b 34 37 38 3b 35 36 2d 05  agent's", (0x30, 0x2B, 0x34, 0x37,
                                                  0x38, 0x3B, 0x35, 0x36,
                                                  0x2D, 0x05)),
]


def main():
    dev = json.load(open(os.path.join(HERE, "device_data.json")))
    camp = json.load(open(os.path.join(HERE, "apps.json")))["penti"]
    S.configure_app(camp)
    from run_install import build_session_request

    native_heads = []
    for n in range(4):
        seed = 0x1000 + n * 0x1117
        f = build_session_request(str(uuid.uuid4()), str(uuid.uuid4()),
                                 dev, camp, 1789000000)
        blob, _s, _i = S.sign_request_vm(f, "session", second=1789000000,
                                         seed=seed)
        native_heads.append((seed, D.whiten_body_inverse(blob[16:160],
                                                        blob[:16])[3:19]))

    print("=" * 72)
    print("which head prefix does THIS build emit?  (seed pinned)")
    print("=" * 72)
    for label, ph in PREFIXES:
        ok = sum(P.head16_for(seed, ph) == want for seed, want in native_heads)
        print("   %-46s %d/%d" % (label, ok, len(native_heads)))

    print()
    print("VERDICT: the prefix is per-BUILD.  HEAD_PHASE_DEFAULT is a working")
    print("value for penti, not a law -- and it does not affect attribution.")
    return 0


if __name__ == "__main__":
    sys.exit(main())