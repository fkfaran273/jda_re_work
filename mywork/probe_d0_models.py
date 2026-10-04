"""probe_d0_models.py — decide, OFFLINE, which d0 model matches the DEVICE.

rows_full.json holds REAL device captures (foldhook_native on com.penti.app):
for each signing we have the device's own #0 (144 B), #2 (4 B) and #4 (32 B)
plus the seed S the native reported.

Two competing d0 models ship in mywork/signer:
  F.region(V, pid, tid, head)   pure Python; seed = V ^ ((pid & 0xffff) << 16)
  adj9_signer.region(seed)       drives the REAL nSign under Unicorn, head ignored

Questions answered here, with no device needed:
  Q1  does the captured #2 == bswap32(S)?            (the seed law)
  Q2  does F.region(S, 0, 0, head) reproduce #0 for ANY plausible head?
  Q3  does F.region's d4/d2 agree with the capture?  (seed -> region lift)
  Q4  do the captured d0 words satisfy the region laws L1/L2/L3?
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "signer"))
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

import F as Fmod                                            # noqa: E402
import mint_pipeline as MP                                  # noqa: E402
from header_gen import make_header                         # noqa: E402

ROWS = os.path.join(HERE, "artifacts", "rows_full.json")


def bswap32(x):
    x &= 0xFFFFFFFF
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | ((x >> 24) & 0xFF)


def be(ws):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)


def main():
    d = json.load(open(ROWS, encoding="utf-8"))
    rows = d["rows"] if isinstance(d, dict) else d
    print("=" * 74)
    print("DEVICE d0-MODEL PROBE  (%d genuine signings)" % len(rows))
    print("=" * 74)

    heads = [("F.HEAD_FIRST", Fmod.HEAD_FIRST),
             ("F.HEAD_RESIGN", Fmod.HEAD_RESIGN),
             ("SYNTH_FIRST", Fmod.SYNTH_HEAD_FIRST),
             ("SYNTH_RESIGN", Fmod.SYNTH_HEAD_RESIGN),
             ("DEVICE_SEL(12)", MP.DEVICE_SELECTORS),
             ("None", None)]

    for r in rows:
        S = int(r["S"])
        cap0 = bytes.fromhex(r["desc"]["0"]["hex"])
        cap2 = bytes.fromhex(r["desc"]["2"]["hex"])
        cap4 = bytes.fromhex(r["desc"]["4"]["hex"])
        w0 = list(struct.unpack(">36I", cap0))
        print("-" * 74)
        print("sign_id=%s second=%s S=0x%08x" % (r.get("sign_id"), r.get("second"), S))

        # Q1 seed law
        q1 = (cap2 == struct.pack(">I", bswap32(S)))
        print("  Q1 #2 == bswap32(S)      : %s  cap2=%s"
              % ("PASS" if q1 else "FAIL", cap2.hex()))

        # Q2/Q3 which head (if any) lifts the seed to the captured d0
        hit = None
        for hname, h in heads:
            d0w, d2v, d4w = Fmod.region(S, 0, 0, h)
            m0 = be(d0w) == cap0
            m2 = be([d2v]) == cap2
            m4 = be(d4w) == cap4
            print("     F.region head=%-14s d0=%-5s d2=%-5s d4=%-5s"
                  % (hname, "EXACT" if m0 else "diff",
                     "EXACT" if m2 else "diff", "EXACT" if m4 else "diff"))
            if m0 and hit is None:
                hit = hname
        print("  Q2 any head reproduces #0: %s" % (hit or "NO — F.region cannot lift this seed"))

        # Q4 region laws on the DEVICE's own d0 (is L3 even a device law?)
        try:
            laws = MP.region_laws(be(list(w0)), cap4)
        except Exception as e:
            laws = None
            print("  Q4 region_laws unavailable: %s" % str(e)[:80])
        if laws:
            print("  Q4 device d0 laws        : L1=%s L2=%s L3=%s"
                  % (laws.get("L1_tile_Rrep"), laws.get("L2_d4_6_hi_eq_R"),
                     laws.get("L3_X_eq_U3")))
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
