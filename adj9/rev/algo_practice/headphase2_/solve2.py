"""solve2.py -- THE decisive solve.

For each pinned urandom8:
  1. run the VM, take blob[16:] as the 192-B signature, whiten_body_inverse ->
     record;  seed = BE32(record[20:24]), head = record[3:19].
  2. src = adj9_pure._transpose16(_raw16(seed))[8:16]
  3. for each of the eight head halfwords solve over GF(2) for the 8 mask bits
     of  value = XOR_{k: mask_k} src[7-k]  and read the selector back out as
     sel = (mask - 3) / 2.
The recovered selector list IS the head phase, whatever it turns out to be.
"""
import os, sys, struct, json

REV = r"C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
sys.path.insert(0, REV)
sys.path.insert(0, r"C:/Users/Apps/Downloads/com.penti.app/manual_run")
import full_replay as FR
import emu_8d6f4 as E
import adj9_pure as AP
import adj9_signature as SG


def gf2_solve(rows, rhs, nbits):
    a = [(r & ((1 << nbits) - 1)) | ((b & 1) << nbits) for r, b in zip(rows, rhs)]
    rank, piv = 0, []
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
    for x in a:
        if (x & ((1 << nbits) - 1)) == 0 and ((x >> nbits) & 1):
            return None, rank
    sol = 0
    for col in piv:
        if (a[where[col]] >> nbits) & 1:
            sol |= 1 << col
    return sol, rank


def solve_sels(src, head):
    out = []
    for j in range(8):
        v = int.from_bytes(head[2 * j:2 * j + 2], "big")
        rows, rhs = [], []
        for b in range(16):
            row = 0
            for k in range(8):
                if (src[7 - k] >> b) & 1:
                    row |= 1 << k
            rows.append(row)
            rhs.append((v >> b) & 1)
        sol, rank = gf2_solve(rows, rhs, 8)
        sel = None
        if sol is not None and sol >= 3 and (sol - 3) % 2 == 0:
            sel = (sol - 3) // 2
        out.append((j, v, sol, rank, sel))
    return out


def run(ur):
    cfg = FR.build_cfg(0)
    cfg["urandom8"] = bytes.fromhex(ur)
    e = E.Emu(cfg=cfg)
    e.run(0xDB1CC, count=3_000_000_000, argstyle="nsign")
    blob = e.result["blob"]
    rec = SG.whiten_body_inverse(bytes(blob[16:160]), bytes(blob[:16]))
    return rec


def main():
    res = []
    for ur in ["11223344", "deadbeef", "a5a5a5a5", "01020304", "00000001", "7fffffff"]:
        rec = run(ur)
        seed = struct.unpack_from(">I", rec, 20)[0]
        head = bytes(rec[3:19])
        src = AP._transpose16(AP._raw16(seed))[8:16]
        s = solve_sels(src, head)
        sels = [x[4] for x in s]
        print("urandom=%s seed=%08x head=%s" % (ur, seed, head.hex(" ")))
        print("   src=%s" % [hex(x) for x in src])
        print("   recovered sels: %s   ranks=%s" %
              (" ".join("None" if x is None else "%02x" % x for x in sels),
               [x[3] for x in s]))
        print("   head16_for(seed,(0x2b,))   =%s" % AP.head16_for(seed).hex(" "))
        print("   head16_for(seed,(0x2b,0x48))=%s" % AP.head16_for(seed, (0x2b, 0x48)).hex(" "))
        res.append({"urandom": ur, "seed": seed, "head": head.hex(), "sels": sels})
    json.dump(res, open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "solve2.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
