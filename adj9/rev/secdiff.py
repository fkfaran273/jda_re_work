"""secdiff.py — is the region->body delta independent of the signing second?

Runs 4 mints: {base, zero region} x {s, s+1}.  If the whitening were
XOR-separable (body = P ^ A(second) ^ B(region)) the two deltas would be
identical.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M
from concurrent.futures import ProcessPoolExecutor

ROW = 7
Z = {0: b"\0" * 144, 2: b"\0" * 4, 4: b"\0" * 32}


def _run(job):
    sec_delta, zero = job
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    r, p = asg[ROW], ph3[ROW]
    sec = int(p["second"]) + sec_delta
    descs = []
    for bi in M.VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        descs.append((len(data) // 4, 0, data))
    if zero:
        z = list(descs)
        for pos, bi in ((0, 0), (4, 2), (3, 4)):
            z[pos] = (len(Z[bi]) // 4, descs[pos][1], Z[bi])
        descs = z
    blob, _ = M.finex_mint(descs, sec, max_steps=60_000_000)
    return list(struct.unpack(">48I", blob))[4:]


def main():
    with ProcessPoolExecutor(max_workers=4) as pool:
        f = list(pool.map(_run, [(0, False), (0, True), (1, False), (1, True)]))
    base_s, base_s1, zero_s, zero_s1 = f
    d1 = [base_s[i] ^ zero_s[i] for i in range(44)]
    d2 = [base_s1[i] ^ zero_s1[i] for i in range(44)]
    same = sum(1 for i in range(44) if d1[i] == d2[i])
    print("delta words equal at %d/44" % same)
    print("delta(s) :", " ".join("%08x" % x for x in d1[:6]))
    print("delta(s+1):", " ".join("%08x" % x for x in d2[:6]))
    print("c(s)     :", " ".join("%08x" % x for x in zero_s[:6]))
    print("c(s+1)   :", " ".join("%08x" % x for x in zero_s1[:6]))
    print("body(s)  :", " ".join("%08x" % x for x in base_s[:6]))
    print("body(s+1):", " ".join("%08x" % x for x in base_s1[:6]))
    json.dump({"base_s": base_s, "base_s1": base_s1, "zero_s": zero_s,
               "zero_s1": zero_s1},
              open(os.path.join(HERE, "secdiff_row7.json"), "w"))


if __name__ == "__main__":
    main()
