"""report_run.py - one full run; dump the nSign return value/blob, rand draws
with return-sites, srand log, and the tail of the call sequence.
"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import emu_8d6f4 as E


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--vary", type=str, default=None)
    args = ap.parse_args()
    override = json.loads(args.vary) if args.vary else {}
    e = E.Emu(cfg=override)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    print("stopped=%s wall=%.1fs calls=%d" % (st, getattr(e, "wall", 0), len(e.calls)))

    print("\n== result ==")
    for k, v in e.result.items():
        if k == "blob":
            print("  blob[%d]:" % len(v))
            for i in range(0, len(v), 16):
                print("    %04x  %s  %s" % (i, v[i:i + 16].hex(" "),
                      "".join(chr(c) if 32 <= c < 127 else "." for c in v[i:i + 16])))
        else:
            print("  %s: %r" % (k, v))

    print("\n== rand calls (idx, value, return-site) ==")
    for i, v, lr in e.rand_calls:
        print("  rand[%d] = %d (0x%x)  lr=0x%x" % (i, v, v, lr))
    print("== srand log ==", e.srand_log)
    print("== poll log (last 5) ==", e.poll_log[-5:] if e.poll_log else "none")

    print("\n== last 40 calls ==")
    for c in e.calls[-40:]:
        print("  ", c)

    print("\n== time/clock calls ==")
    for c in e.calls:
        if c[0] in ("clock_gettime", "gettimeofday", "time", "rand", "srand"):
            print("  ", c)

    # warnings/log
    if e.log:
        print("\n== harness log (warnings) ==")
        for l in e.log[:30]:
            print("  ", l)


if __name__ == "__main__":
    main()
