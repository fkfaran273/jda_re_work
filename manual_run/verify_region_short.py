"""verify_region_short.py — regression vectors for the region law.

This script used to prove the short region form against the long one
(_d4_words -> _d0_source -> _d0_words -> head_words), which has since been
deleted as dead.  The proof is done: 27,063/27,063 seed/phase combinations
were identical, and the parallel session independently showed the VM reads only
d0[0:16].

What remains is the part worth keeping: fixed vectors, so any future edit to
the region law fails here instead of silently shipping.  Regenerate with
`python verify_region_short.py --write` if the law legitimately changes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9_pure as P  # noqa: E402

VECTORS = [
    (0xDEADBEEF, (0x2B,), "07b968b1c4fc66b6cafb4beae7a76df0"),
    (0xA9CF7053, (0x2B,), "9e7f83cdbfbdd231ee419c5da02d8737"),
    (0xA9CF7053, (0x2B, 0x48), "9e7fbb47bfbdd231ee419c5da02d8737"),
    (0xC426AF1C, (0x2B,), "8d1a93efeff4e52b993023ff5fe4258f"),
    (0x00000000, (0x2B,), "9d7db1da501d839d625af88d194adb4e"),
    (0xFFFFFFFF, (0x2B, 0x48), "2149cf37d1f05d8b17c33fce7586857f"),
    (0x80000000, (0x2B,), "21499bb8d1f05d8b17c33fce7586857f"),
    (0x7FFFFFFF, (0x2B,), "2f6f06e51cb4aa74b025deb0c4e1f660"),
    (0x12345678, (0x2B, 0x48, 0x40, 0x00), "1867a550ab4d215d69d3f2c38a5bddc8"),
    (0x0000ABCD, (0x00,), "289161755edc8b72b4dbbcb88311bffa"),
]


def main():
    if "--write" in sys.argv:
        for seed, phase, _ in VECTORS:
            print("    (%#010x, %r, %r)," % (seed, phase,
                                            P.head16_for(seed, phase).hex()))
        return 0
    ok = bad = unknown = 0
    for seed, phase, want in VECTORS:
        got = P.head16_for(seed, phase).hex()
        if want is None:
            unknown += 1
            print("   %#010x %-22s %s" % (seed, str(phase), got))
        elif got == want:
            ok += 1
        else:
            bad += 1
            print("   %-12s %-22s MISMATCH" % ("%#010x" % seed, str(phase)))
            print("        want %s" % want)
            print("        got  %s" % got)
    print()
    print("RESULT: %d pinned vectors pass, %d mismatch, %d unrecorded"
          % (ok, bad, unknown))
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())