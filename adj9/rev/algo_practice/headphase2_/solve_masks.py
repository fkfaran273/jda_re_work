"""solve_masks.py -- decisive test.

Run the native VM in the emulator with a PINNED urandom8, decrypt the record,
read the seed out of rec[20:24], then solve (over GF(2)) for the selector mask
that each of the eight head halfwords actually used, given source halfwords
derived from that seed.

No guessing: the mask for halfword j satisfies
    XOR_{k : bit k of mask set} source[7-k]  ==  head_j
i.e. a 9-bit unknown against 16 equations.
"""
import os, sys, json, struct

REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")

import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as AP


def gf2_solve(rows, rhs, nbits):
    """rows: list of ints whose bit i is the coefficient of unknown i.
    Returns (solution_list, rank) or (None, rank)."""
    # augmented integer: low nbits = coefficients, bit nbits = rhs
    a = [(r & ((1 << nbits) - 1)) | ((b & 1) << nbits) for r, b in zip(rows, rhs)]
    rank = 0
    piv = []
    where = [-1] * nbits
    r = 0
    for col in range(nbits):
        pr = None
        for i in range(r, len(a)):
            if (a[i] >> col) & 1:
                pr = i
                break
        if pr is None:
            continue
        a[r], a[pr] = a[pr], a[r]
        for i in range(len(a)):
            if i != r and ((a[i] >> col) & 1):
                a[i] ^= a[r]
        where[col] = r
        piv.append(col)
        r += 1
    # inconsistency?
    for i in range(len(a)):
        if (a[i] & ((1 << nbits) - 1)) == 0 and ((a[i] >> nbits) & 1):
            return None, rank
    sol = 0
    for col in piv:
        if (a[where[col]] >> nbits) & 1:
            sol |= 1 << col
    return sol, rank


def selector_from_mask(mask):
    """mask = (selector << 1) + 3"""
    if mask < 3 or (mask - 3) % 2:
        return None
    return (mask - 3) // 2


def solve_head(seed, head_bytes):
    src = AP._transpose16(AP._raw16(seed))[8:16]
    out = []
    for j in range(8):
        val = int.from_bytes(head_bytes[2 * j:2 * j + 2], "big")
        # _selector_halfword: for bit k in 0..7 with (mask>>k)&1 -> ^= source[7-k]
        rows, rhs = [], []
        for b in range(16):
            row = 0
            for k in range(8):
                if (src[7 - k] >> b) & 1:
                    row |= 1 << k
            rows.append(row)
            rhs.append((val >> b) & 1)
        sol, rank = gf2_solve(rows, rhs, 8)
        out.append({"j": j, "val": val, "rank": rank,
                    "mask": sol, "sel": None if sol is None else selector_from_mask(sol)})
    return src, out


def run_vm(urandom_hex, n=0):
    cfg = FR.build_cfg(n)
    cfg["urandom8"] = bytes.fromhex(urandom_hex)
    e = E.Emu(cfg=cfg)
    st = e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    return st, (e.result.get("blob") or b"")


def main():
    tests = ["11223344", "deadbeef", "00000001", "a5a5a5a5", "01020304"]
    out = []
    for t in tests:
        st, blob = run_vm(t)
        if len(blob) < 192:
            print("FAILED", t, st, len(blob))
            continue
        rec = AP.whiten_body_inverse(blob[16:160], blob[:16])
        seed = struct.unpack_from(">I", rec, 20)[0]
        head = bytes(rec[3:19])
        pin_seed = int(t, 16)
        src, sol = solve_head(seed, head)
        print("=== urandom=%s stopped=%s" % (t, st))
        print("    rec seed=%08x (pin %08x) %s" % (seed, pin_seed,
                                                   "MATCH" if seed == pin_seed else "*** DIFFERS"))
        print("    head=%s" % head.hex(" "))
        # model prediction with HEAD_PHASE_DEFAULT
        pred = AP.head16_for(seed)
        print("    head16_for(seed,(0x2b,))=%s  %s" % (
            pred.hex(" "), "MATCH" if pred == head else "*** DIFFERS"))
        print("    source halfwords: %s" % [hex(x) for x in src])
        for s in sol:
            print("      j=%d val=%04x rank=%d mask=%s sel=%s" %
                  (s["j"], s["val"], s["rank"],
                   "None" if s["mask"] is None else hex(s["mask"]), s["sel"]))
        out.append({"urandom": t, "seed": seed, "head": head.hex(),
                    "pred_match": pred == head,
                    "solved": sol})
    json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "solve_masks.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
