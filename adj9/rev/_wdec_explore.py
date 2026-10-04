"""_wdec_explore.py v2 — derive every whitening primitive from the row-7 trace.

Token-based phase segmentation (consecutive same-pc E runs), then per-phase law
verification on the 176-byte whitening span [1134..1310) = 9 record chunks +
2 digest chunks:
  hxor  (0x10a228)  : v = pre ^ WA[i]     (WA = prev chunk final / header)
  kxor  (0x111c68)  : v = pre ^ 0x55 ^ KB[16r+i]  (final sweep: KB[224+i])
  skt   (0x111f70)  : v = T[pre] ^ 0x55
  diag1 (12 sites)  : byte permutation pi1 (derived both directions)
  diag2 (4 sites)   : 32-bit GF(2) affine F per 4-byte block (fit + check)
"""
import gzip
import json
import sys
from collections import defaultdict

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev")
from _inv2_aff import gf2_solve, apply_map  # noqa: E402

TOP = 620
REC_TOP = 1134
SPAN = 176                       # [1134..1310)
HXOR_PC = 0x10A228
KXOR_PC = 0x111C68
SKT_PC = 0x111F70
DIAG2 = (0x10D0EC, 0x110E30, 0x10A5FC, 0x10FBF4)
DIAG1 = (0x10DAA0, 0x10DC08, 0x10DD70, 0x10DE2C, 0x10E040, 0x10E0FC,
         0x10E310, 0x10E3CC, 0x10E5E0, 0x10E748, 0x10E8B0, 0x10C4D8)
D1SET = set(DIAG1)
D2SET = set(DIAG2)
WPCS = D1SET | D2SET | {HXOR_PC, KXOR_PC, SKT_PC}


def load(fn):
    A = json.load(gzip.open(fn, "rt"))
    ops = [(e[0], e[1], (e[3] + e[4]) if e[0] == "E" else (TOP + e[4]),
            e[5] & 0xFFFFFFFF)
           for e in A["wire"]
           if (e[2] & 0xFFFFFFFFFFFF) == 0x5450001000 and e[0] in ("E", "Q")]
    return A, ops


def main():
    fn = sys.argv[1] if len(sys.argv) > 1 else "_inv2_row7_real.json.gz"
    A, ops = load(fn)
    blob = bytes.fromhex(A["blob"])
    record = bytes.fromhex(A["record"])
    state = {}

    # plaintext = first writes into the span
    first = {}
    for (kind, pc, o, v) in ops:
        if kind != "E":
            continue
        if REC_TOP <= o < REC_TOP + SPAN and o not in first:
            first[o] = v & 0xFF
    rec_pt = bytes(first.get(REC_TOP + i, 0) for i in range(144))
    dig_pt = bytes(first.get(REC_TOP + 144 + i, 0) for i in range(32))
    print("rec_pt == A['record']:", rec_pt == record)
    print("dig_pt:", dig_pt.hex())
    plain = rec_pt + dig_pt

    # whitening events in order
    wev = []
    for (kind, pc, o, v) in ops:
        if kind != "E":
            continue
        v &= 0xFF
        pv = state.get(o, 0)
        state[o] = v
        if REC_TOP <= o < REC_TOP + SPAN and pc in WPCS:
            wev.append((pc, o - REC_TOP, pv, v))

    # tokens of consecutive same-pc
    toks = []
    s = 0
    for k in range(1, len(wev) + 1):
        if k == len(wev) or wev[k][0] != wev[s][0]:
            toks.append((wev[s][0], wev[s:k]))
            s = k
    print("tokens:", len(toks), "events:", len(wev))

    # merge adjacent diag1 tokens into phases, diag2 tokens into phases;
    # hxor/kxor/skt tokens are phases by themselves
    phases = []      # (kind, events)
    for pc, evs in toks:
        kind = ("hxor" if pc == HXOR_PC else "kxor" if pc == KXOR_PC
                else "skt" if pc == SKT_PC else "d1" if pc in D1SET
                else "d2" if pc in D2SET else "?")
        if phases and phases[-1][0] == kind and kind in ("d1", "d2"):
            phases[-1][1].extend(evs)
        else:
            phases.append((kind, list(evs)))
    kinds = [k for k, _ in phases]
    print("phase sequence head:", kinds[:12])
    # expected per chunk: hxor (k kxor skt d1 d2)x13 kxor-final -> but hxor only
    # once per chunk: hxor, then 14 rounds of (kxor skt d1 [d2]), final kxor.
    # Verify segmentation: count chunks
    nchunk = kinds.count("hxor")
    print("hxor phases (chunks):", nchunk)

    T = {}
    tbad = tknow = 0
    kb = {}
    kbad = 0
    wa_groups = defaultdict(dict)
    d1_pairs = []
    d2_samples = []       # (bi, in32, out32)
    # replay buffer: per chunk 16 bytes
    buf = bytearray(16)
    chunk_plain = {}
    round_no = -1
    in_round = False
    d2_in = {}
    prev_phase = None
    for pi, (kind, evs) in enumerate(phases):
        ch = evs[0][1] // 16
        if kind == "hxor":
            round_no = 0
            in_round = True
            buf = bytearray(16)
            chunk_plain[ch] = bytes(e[2] for e in evs)  # pre values = plaintext
            for (pc, pos, pv, v) in evs:
                i = pos % 16
                wa_groups[ch][i] = v ^ pv
                buf[i] = v
            prev_phase = "hxor"
            continue
        if kind == "kxor":
            if prev_phase == "hxor":
                round_no = 0
                base = 0
            elif prev_phase == "d2":
                round_no += 1
                base = 0
            elif prev_phase == "d1":
                round_no = 14          # final sweep
                base = 224
            else:
                raise SystemExit("unexpected kxor after %s (chunk %d)"
                                 % (prev_phase, ch))
            for (pc, pos, pv, v) in evs:
                i = pos % 16
                key = 16 * round_no + i if base == 0 else 224 + i
                want = v ^ pv ^ 0x55
                if key in kb and kb[key] != want:
                    kbad += 1
                kb[key] = want
                buf[i] = v
            prev_phase = "kxor"
            continue
        if kind == "skt":
            for (pc, pos, pv, v) in evs:
                i = pos % 16
                if pv in T:
                    if T[pv] != v ^ 0x55:
                        tbad += 1
                else:
                    tknow += 1
                T.setdefault(pv, v ^ 0x55)
                buf[i] = v
            prev_phase = "skt"
            continue
        if kind == "d1":
            before = bytes(buf)
            for (pc, pos, pv, v) in evs:
                buf[pos % 16] = v
            d1_pairs.append((ch, round_no, before, bytes(buf)))
            prev_phase = "d1"
            continue
        if kind == "d2":
            before = bytes(buf)
            for (pc, pos, pv, v) in evs:
                buf[pos % 16] = v
            after = bytes(buf)
            for bi in range(4):
                xi = int.from_bytes(before[4 * bi:4 * bi + 4], "little")
                yi = int.from_bytes(after[4 * bi:4 * bi + 4], "little")
                d2_samples.append((bi, xi, yi))
            prev_phase = "d2"
            continue

    print("T known: %d/256 bad=%d" % (len(T), tbad))
    print("KB known: %d/240 bad=%d" % (len(kb), kbad))
    miss = [k for k in range(240) if k not in kb]
    print("KB missing:", miss)
    print("KB[0:16]   :", bytes(kb[i] for i in range(16)).hex())
    print("KB[224:240]:", bytes(kb[224 + i] for i in range(16)).hex())

    # WA law: WA(chunk k) == blob[16k:16k+16)  (chunk 0 -> header blob[0:16))
    wabad = 0
    for ch in sorted(wa_groups):
        wa = bytes(wa_groups[ch].get(i, 0) for i in range(16))
        exp = blob[16 * ch:16 * ch + 16]
        if wa != exp:
            wabad += 1
            print("  WA ch%d BAD %s exp %s" % (ch, wa.hex(), exp.hex()))
    print("WA law: %d/%d chunks OK" % (nchunk - wabad, nchunk))

    # pi1
    consA = [set(range(16)) for _ in range(16)]   # aft[i] = bef[PA[i]]
    consB = [set(range(16)) for _ in range(16)]   # aft[PB[i]] = bef[i]
    for (ch, r, bef, aft) in d1_pairs:
        for i in range(16):
            consA[i] &= {j for j in range(16) if bef[j] == aft[i]}
            consB[i] &= {j for j in range(16) if aft[j] == bef[i]}
    pA = [next(iter(c)) if len(c) == 1 else None for c in consA]
    pB = [next(iter(c)) if len(c) == 1 else None for c in consB]
    print("d1 phases:", len(d1_pairs))
    print("pi1 dirA aft[i]=bef[P[i]]:", all(p is not None for p in pA), pA)
    print("pi1 dirB aft[P[i]]=bef[i]:", all(p is not None for p in pB), pB)

    # diag2 affine fit (universal across blocks/chunks)
    res = gf2_solve([(x, y) for (b, x, y) in d2_samples])
    print("d2 samples:", len(d2_samples), "affine:", res is not None)
    if res:
        bad = sum(1 for (b, x, y) in d2_samples if apply_map(res, x) != y)
        print("d2 mismatches: %d/%d" % (bad, len(d2_samples)))
    # per-block fit (are they the same map?)
    for bi in range(4):
        sb = [(x, y) for (b, x, y) in d2_samples if b == bi]
        rb = gf2_solve(sb)
        same = rb is not None and res is not None and all(
            apply_map(res, x) == y for (x, y) in sb)
        print("  block %d: n=%d universal-map-fits=%s" % (bi, len(sb), same))

    # chunk plaintext check
    okp = all(chunk_plain.get(ch) == plain[16 * ch:16 * ch + 16]
              for ch in chunk_plain)
    print("chunk pre == plaintext for all chunks:", okp)
    print("chunks seen:", sorted(chunk_plain))

    # save derived constants for the next stage
    out = {"T": [T.get(i) for i in range(256)],
           "KB": [kb.get(i) for i in range(240)],
           "pi1A": pA, "pi1B": pB,
           "F_rows": res[0] if res else None,
           "F_consts": res[1] if res else None,
           "dig_pt": dig_pt.hex(), "rec_pt": rec_pt.hex(),
           "blob": blob.hex()}
    json.dump(out, open("_wdec_const.json", "w"))
    print("saved _wdec_const.json")


if __name__ == "__main__":
    main()
