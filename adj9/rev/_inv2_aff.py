"""_inv2_aff.py v2 — diag-2 block samples across all chunks; GF(2)-affine fit."""
import gzip
import json
import sys
from collections import defaultdict

TOP = 620
DIAG2 = (0x10d0ec, 0x110e30, 0x10a5fc, 0x10fbf4)
REC_TOP = 1134


def samples(fn):
    A = json.load(gzip.open(fn, "rt"))
    ops = [(e[0], e[1], (e[3] + e[4]) if e[0] == "E" else (TOP + e[4]),
            e[5] & 0xFFFFFFFF)
           for e in A["wire"]
           if (e[2] & 0xFFFFFFFFFFFF) == 0x5450001000
           and e[0] in ("E", "Q")]
    state = {}
    blocks = []
    cur = {}     # (chunk, blk) -> [4 in-bytes]
    cnt = defaultdict(int)
    for (kind, pc, o, v) in ops:
        if kind == "E":
            v &= 0xFF
            pv = state.get(o, 0)
            pos = o - REC_TOP
            if pos >= 0 and pc in DIAG2 and (pos % 16) < 16:
                ch, inpos = divmod(pos, 16)
                bi = inpos // 4
                key = (ch, bi)
                if key not in cur:
                    cur[key] = [None] * 4
                cur[key][inpos % 4] = pv
                state[o] = v
                cnt[key] += 1
                if cnt[key] == 4:
                    out = tuple(state[REC_TOP + ch * 16 + bi * 4 + j]
                                for j in range(4))
                    xi = cur[key]
                    xp = (xi[0] | (xi[1] << 8) | (xi[2] << 16) | (xi[3] << 24))
                    yp = (out[0] | (out[1] << 8) | (out[2] << 16) | (out[3] << 24))
                    blocks.append((bi, ch, xp, yp))
                    del cur[key]
                    del cnt[key]
                continue
            state[o] = v
        else:
            state[o] = v
    return blocks


def gf2_solve(pairs):
    """out = M*in ^ c over GF(2), bit-plane wise. Returns (rows, consts)|None."""
    rows, consts = [], []
    for j in range(32):
        piv = {}
        inconsistent = False
        for (x, y) in pairs:
            row = ([(x >> i) & 1 for i in range(32)] + [1], (y >> j) & 1)
            for i in range(33):
                if row[0][i]:
                    if i in piv:
                        pr, prr = piv[i]
                        row = ([a ^ b for a, b in zip(row[0], pr)],
                               row[1] ^ prr)
                    else:
                        piv[i] = row
                        row = None
                        break
            if row is not None:
                if any(row[0]) or row[1]:
                    inconsistent = True
                break
        if inconsistent:
            return None
        m = [0] * 33
        for i in sorted(piv.keys(), reverse=True):
            pr, prr = piv[i]
            val = prr
            for k in range(i + 1, 33):
                if pr[k] and m[k]:
                    val ^= 1
            m[i] = val
        rows.append(m[:32])
        consts.append(m[32])
    return rows, consts


def apply_map(res, x):
    rows, consts = res
    y = 0
    for j in range(32):
        b = consts[j]
        mi = rows[j]
        for i in range(32):
            if (x >> i) & 1 and mi[i]:
                b ^= 1
        y |= b << j
    return y


if __name__ == "__main__":
    fns = sys.argv[1:] or ["_inv2_row7_real.json.gz", "_inv2_row7_rand.json.gz"]
    allb = []
    for fn in fns:
        blocks = samples(fn)
        print("%s: %d block samples" % (fn, len(blocks)))
        allb += blocks
    for bi in range(4):
        sb = [(x, y) for (b, ch, x, y) in allb if b == bi]
        uniq = len(set(x for x, _ in sb))
        res = gf2_solve(sb) if sb else None
        ok = res is not None
        bad = -1
        if ok:
            bad = sum(1 for (x, y) in sb if apply_map(res, x) != y)
        print("block %d: %d samples (%d uniq) affine=%s mismatch=%d"
              % (bi, len(sb), uniq, ok, bad))
    res = gf2_solve([(x, y) for (b, ch, x, y) in allb])
    print("universal map:", "affine OK" if res else "NOT affine")
    if res:
        bad = sum(1 for (b, ch, x, y) in allb if apply_map(res, x) != y)
        print("  mismatches: %d/%d" % (bad, len(allb)))
