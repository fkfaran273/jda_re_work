"""Per-input GF(2) affinity test on the region -> body map (row 7).

For each of the 8 active region words W we check
    f(base) ^ f(base^W) ^ f(zeroRegion+W) ^ f(zeroRegion) == 0
which is exactly the condition "the map is GF(2)-affine in W alone".
"""
import json, os, struct
import mint_pipeline as M
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROW = 7
ACTIVE = ((0, 0), (0, 1), (0, 2), (0, 3), (4, 4), (4, 5), (4, 6), (2, 0))


def descriptors(region):
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    r, p = asg[ROW], ph3[ROW]
    d = {}
    for bi in M.VA_ORDER:
        hx = r.get("d%d" % bi, "")
        d[bi] = bytearray(bytes.fromhex(hx)) if hx else bytearray()
    if region is not None:
        for bi in (0, 2, 4):
            d[bi][:] = bytes(region.get("d%d" % bi, b"").ljust(len(d[bi]), b"\x00"))
    descs = [(len(d[bi]) // 4, 0, bytes(d[bi])) for bi in M.VA_ORDER]
    return descs, int(p["second"])


def run(region):
    descs, second = descriptors(region)
    blob, _info = M.finex_mint(descs, second, max_steps=60_000_000)
    return list(struct.unpack(">48I", blob))[4:]


def main():
    descs, second = descriptors(None)
    base = {k: bytes(v[2]) for k, v in zip(M.VA_ORDER, descs)}
    Z = {k: bytes(len(base[k])) for k in (0, 2, 4)}

    cases = {}
    for name, w in ACTIVE:
        v = bytes(base[name][4 * w:4 * w + 4])
        p1 = dict(Z)
        p1[name] = v                                    # zero region + W
        p3 = {k: bytearray(base[k]) for k in Z}          # base
        p3[name][4 * w:4 * w + 4] = b"\x00\x00\x00\x00"  # base minus W
        cases["%s[%d]" % (name, w)] = (p1, p3)

    B = {k: bytes(base[k]) for k in (0, 2, 4)}
    with ProcessPoolExecutor(max_workers=8) as pool:
        fut = [pool.submit(run, r) for r in
               [Z, B] + [c[0] for c in cases.values()] + [c[1] for c in cases.values()]]
        got = [f.result() for f in fut]
    fz, fb = got[0], got[1]
    n = len(cases)
    f1s, f3s = got[2:2 + n], got[2 + n:]

    out = {"f0": fz, "res": {}}
    for i, (k, case) in enumerate(cases.items()):
        f1, f3 = f1s[i], f3s[i]
        r = [fb[j] ^ f3[j] ^ f1[j] ^ fz[j] for j in range(44)]
        nz = sum(1 for x in r if x)
        print("%-8s affine residual nonzero: %2d/44  w0=%08x" % (k, nz, r[0]))
        out["res"][k] = r
    json.dump(out, open(os.path.join(HERE, "aff2_row7.json"), "w"))


if __name__ == "__main__":
    main()
