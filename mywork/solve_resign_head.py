"""solve_resign_head.py — find the d0 head that reproduces sign_id>=3 on device.

rows_full.json sign_id=3 is NOT reproduced by any of the six shipped head
tables (decide_d0.py: "F.region head that DOES match DEVICE: none"), while
sign_id 1 and 2 are reproduced exactly by mint_pipeline.DEVICE_SELECTORS.  That
is the concrete form of the "per-signing-ordinal d0 head selection differs
between implementations" suspect.

Rather than guess a prefix, SOLVE for it: d0 is
    W0 | X | U x8 | U[0] U[1]
and F._d0_words only changes the first len(head) selector slots, everything
after the prefix is the stable 0x40|(i&7) cycle.  So for a candidate head the
model is cheap; we brute-force selector prefixes up to length 8 over the
observed alphabet and report every one that reproduces the device bytes.

Run:  python solve_resign_head.py [sign_id]
"""
import itertools
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "signer"))
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")

import F as Fmod                                            # noqa: E402
import mint_pipeline as MP                                  # noqa: E402

ROWS = os.path.join(HERE, "artifacts", "rows_full.json")
ALPHA = (0x2B, 0x07, 0x22, 0x25, 0x2E, 0x44, 0x45, 0x46, 0x47, 0x40, 0x41, 0x42, 0x43)


DEVICE_HEAD_FIRST = (0x2B, 0x22, 0x25, 0x2E, 0x44)   # sign_id 1-2
DEVICE_HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x25, 0x2E, 0x45)  # sign_id 3+


def verify_device_heads(verbose=True):
    """Re-derive both device heads from the saved genuine captures.

    Run this before trusting the constants above; it is the evidence for them.
    """
    import json
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "artifacts", "rows_full.json")
    rows = json.load(open(p, encoding="utf-8"))["rows"]
    out = []
    for r in rows:
        S = int(r["S"])
        cap0 = bytes.fromhex(r["desc"]["0"]["hex"])
        hit = None
        for name, h in (("FIRST", DEVICE_HEAD_FIRST),
                        ("RESIGN", DEVICE_HEAD_RESIGN)):
            if be(Fmod.region(S, 0, 0, h)[0]) == cap0:
                hit = name
                break
        out.append((r.get("sign_id"), hit))
        if verbose:
            print("  sign_id=%s -> %s" % (r.get("sign_id"), hit or "NO MATCH"))
    return out


    if not found:
        print("  NO prefix of length <= 6 over the observed alphabet reproduces it")
        print("  -> the sign_id>=3 phase is not a prefix perturbation of the same")
        print("     model; it needs the real 0x1441e4 head captured from a live")
        print("     sign_id>=3 device signing (foldhook sign_row 'head').")
    print()
    print("  cross-check against the published constants:")
    for sid, hit in verify_device_heads():
        print("    sign_id=%s -> %s" % (sid, hit))
    return 0
def be(ws):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in ws)


def main():
    want = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    rows = json.load(open(ROWS, encoding="utf-8"))["rows"]
    row = next(r for r in rows if int(r["sign_id"]) == want)
    S = int(row["S"])
    cap0 = bytes.fromhex(row["desc"]["0"]["hex"])
    print("sign_id=%d seed=0x%08x  target d0 = %s ..."
          % (want, S, cap0[:16].hex()))

    found = []
    for n in range(0, 7):
        for combo in itertools.product(ALPHA, repeat=n):
            if be(Fmod.region(S, 0, 0, tuple(combo))[0]) == cap0:
                found.append(tuple(combo))
                print("  MATCH head (len %d) = %s"
                      % (n, " ".join("%02x" % c for c in combo)))
        if found and n >= 3:
            break
    if not found:
        print("  NO prefix of length <= 6 over the observed alphabet reproduces it")
        print("  -> the sign_id>=3 phase is not a prefix perturbation of the same")
        print("     model; it needs the real 0x1441e4 head captured from a live")
        print("     sign_id>=3 device signing (foldhook sign_row 'head').")
    return 0


if __name__ == "__main__":
    sys.exit(main())
