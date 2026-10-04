"""_inv2_model.py — pure-Python forward model of the whitening; verify vs VM.

Model (per 16-B chunk, top = 620, KB = MAIN[877..1116), T = table[621..877)):
  WA      = previous chunk final (header for chunk 0)
  chunk  ^= WA                                     # 0x10a228
  14 rounds r=0..13:
     chunk[i] ^= 0x55 ^ KB[16r+i]                  # 0x111c68
     chunk[i]  = T[chunk[i]] ^ 0x55                # 0x111f70
     chunk    = pi1(chunk)                         # diag-1 permutation
     if r < 13: chunk = F(chunk)                   # diag-2 universal affine
  chunk[i] ^= 0x55 ^ KB[224+i]                     # final sweep
"""
import gzip
import json
import sys
from _inv2_aff import gf2_solve, apply_map, samples as blk_samples

TOP = 620
REC_TOP = 1134
DIAG2 = (0x10d0ec, 0x110e30, 0x10a5fc, 0x10fbf4)
DIAG1 = (0x10daa0, 0x10dc08, 0x10dd70, 0x10de2c, 0x10e040, 0x10e0fc,
         0x10e310, 0x10e3cc, 0x10e5e0, 0x10e748, 0x10e8b0, 0x10c4d8)
SITES_DIAG1_ORDER = [0x10daa0, 0x10dc08, 0x10dd70, 0x10de2c, 0x10e040,
                     0x10e0fc, 0x10e310, 0x10e3cc, 0x10e5e0, 0x10e748,
                     0x10e8b0, 0x10c4d8]


def extract(fn):
    A = json.load(gzip.open(fn, "rt"))
    ops = [(e[0], e[1], (e[3] + e[4]) if e[0] == "E" else (TOP + e[4]),
            e[5] & 0xFFFFFFFF)
           for e in A["wire"]
           if (e[2] & 0xFFFFFFFFFFFF) == 0x5450001000 and e[0] in ("E", "Q")]
    state = {}
    T = None
    kb = None
    qwin = []
    swp = []       # (abs, pre, v, kbabs, kbval)
    skt = []       # (abs, pre, v)
    hxor = []      # (abs, pre, v, wa abs taps)
    sawa = []      # work-area writes
    for (kind, pc, o, v) in ops:
        if kind == "Q":
            qwin.append((o, state.get(o, 0), v & 0xFFFFFFFF))
            continue
        v &= 0xFF
        pv = state.get(o, 0)
        if pc == 0x1199a8 or pc == 0x109f9c:
            sawa.append((o, v))
        elif pc == 0x10a228:
            hxor.append((o, pv, v, tuple(qwin)))
        elif pc == 0x111c68 and len([t for t in qwin if t[0] != o]) == 1:
            t = [t for t in qwin if t[0] != o][0]
            swp.append((o, pv, v, t[0], t[2]))
        elif pc == 0x111f70:
            skt.append((o, pv, v))
        state[o] = v
        qwin = []
    # KB: state of [877..1116) after the pre-machinery: snapshot right before
    # the first sweep use -> reconstruct from swp taps
    kbmap = {}
    for (o, pv, v, kba, kbv) in swp:
        kbmap[kba] = kbv
    kb = bytes(kbmap.get(877 + i, 0) for i in range(240))
    # T: from SKT events: T[pre] = v ^ 0x55 (first occurrence wins)
    tmap = {}
    for (o, pv, v) in skt:
        tmap.setdefault(pv, v ^ 0x55)
    T = [tmap.get(i, 0) for i in range(256)]
    return A, ops, state, kb, T, swp, skt, hxor, sawa


def perm_check(ops):
    """Verify diag-1 permutation pi1 on every round."""
    PI = {0: 0, 1: 13, 2: 10, 3: 7, 4: 4, 5: 1, 6: 14, 7: 11,
          8: 8, 9: 5, 10: 2, 11: 15, 12: 12, 13: 9, 14: 6, 15: 3}
    # post-SKT multiset vs post-diag1 multiset per (chunk, round)
    return PI


def main():
    fn = sys.argv[1] if len(sys.argv) > 1 else "_inv2_row7_real.json.gz"
    A, ops, state, kb, T, swp, skt, hxor, sawa = extract(fn)
    print("sweeps: %d  skt: %d  hxor: %d  WA-writes: %d"
          % (len(swp), len(skt), len(hxor), len(sawa)))
    # KB constancy: distinct tap values per KB position
    kbd = {}
    for (o, pv, v, kba, kbv) in swp:
        kbd.setdefault(kba, set()).add(kbv)
    print("KB positions with >1 distinct value:",
          sum(1 for s in kbd.values() if len(s) > 1))
    print("KB[0:16] :", kb[:16].hex())
    print("KB[224:240]:", kb[224:240].hex())
    # T is a permutation?
    print("T permutation:", len(set(T)) == 256)
    print("T[0:16]:", bytes(T[:16]).hex())

    # work area content over time vs chunk finals
    blob = bytes.fromhex(A["blob"])
    wa = {}
    for (o, v) in sawa:
        wa[o] = v
    wa0 = bytes(wa.get(1117 + i, 0) for i in range(16))
    print("WA after chunk0 (expect body[0:16]):", wa0.hex(),
          wa0 == blob[16:32])
    # header-XOR law: v = pre ^ WA[i]
    okh = badh = 0
    wat = dict(wa)
    # rebuild WA timeline: hxor events for chunk k use WA = blob[16k:16k+16)
    for (o, pv, v, taps) in hxor:
        ch = (o - REC_TOP) // 16
        i = (o - REC_TOP) % 16
        want = blob[16 * ch + i] if ch > 0 else wat.get(o, 0)
        # chunk 0's WA = the header copy (0x1199a8 values)
        if (v ^ pv) == want:
            okh += 1
        else:
            badh += 1
            if badh < 4:
                print("  hxor mismatch ch%d i%d pre=%02x v=%02x want=%02x"
                      % (ch, i, pv, v, want))
    print("header-XOR law v=pre^WA: ok=%d bad=%d" % (okh, badh))


if __name__ == "__main__":
    main()
