"""Complete the d4 (32-B region record) reach map: which of its 8 words reach
the wire, and which body-word ranges."""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M

A = json.load(open(os.path.join(HERE, "all_signings.json")))
P = json.load(open(os.path.join(HERE, "pair_h3.json")))
ORDER = M.VA_ORDER
R = 4

def raw(r):
    return {bi: bytes.fromhex(r.get("d%d" % bi, "")) for bi in ORDER}

def descs(d):
    return [(len(d[bi]) // 4, 0, d[bi][:(len(d[bi]) // 4) * 4]) for bi in ORDER]

def mint(d, second):
    blob, _ = M.finex_mint(descs(d), second, max_steps=60_000_600)
    return list(struct.unpack(">48I", blob))[4:]

def ranges(idxs):
    if not idxs:
        return "-"
    res, s, prev = [], idxs[0], None
    for k in idxs:
        if prev is not None and k != prev + 1:
            res.append((s, prev)); s = k
        prev = k
    res.append((s, prev))
    return ",".join("%d" % a if a == b else "%d-%d" % (a, b) for a, b in res)

def main():
    base = raw(A[R]); second = int(P[R]["second"])
    b0 = mint(base, second)
    for w in range(8):
        d = dict(base)
        bb = bytearray(d[4]); bb[4 * w] ^= 1
        d[4] = bytes(bb)
        b = mint(d, second)
        diff = [j for j in range(44) if b[j] != b0[j]]
        print("d4 word %d -> body words changed %2d/44  [%s]"
              % (w, len(diff), ranges(diff)), flush=True)
    # and the region words d0[4..35] sweep, sampled
    for w in (4, 8, 16, 24, 34, 35):
        d = dict(base)
        bb = bytearray(d[0]); bb[4 * w] ^= 1
        d[0] = bytes(bb)
        b = mint(d, second)
        diff = [j for j in range(44) if b[j] != b0[j]]
        print("d0 word %2d -> body words changed %2d/44  [%s]"
              % (w, len(diff), ranges(diff)), flush=True)

if __name__ == "__main__":
    main()
