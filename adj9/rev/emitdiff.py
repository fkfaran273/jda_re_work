"""emitdiff.py — locate exactly where the region enters the merge program.

Runs the merge twice (base row vs a perturbed region) and diffs the
EMIT trace (va, index, value) plus the final body.  Prints the first
divergence: which stream, which index arithmetic, which register held
the region word.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import mint_pipeline as M

ROW = 7
MODE = sys.argv[1] if len(sys.argv) > 1 else "zero"   # zero | d0bit0


def run(patch=None):
    """patch: {(bi, word_index): 4-byte bytes} -> overwrite region words."""
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    r, p = asg[ROW], ph3[ROW]
    descs = []
    for bi in M.VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytearray(bytes.fromhex(hx)) if hx else bytearray()
        descs.append([len(data) // 4, 0, bytes(data)])
    if patch:
        for (bi, wi), val in patch.items():
            i = M.VA_ORDER.index(bi)
            d = bytearray(descs[i][2])
            d[4 * wi:4 * wi + 4] = val
            descs[i][2] = bytes(d)
    descs = [tuple(d) for d in descs]
    ex = M.FinEx(int(p["second"]), descs)
    st = ex.run(max_steps=60_000_000)
    return ex, st


def body(ex):
    sink = ex.streams[M.SINK]
    return [sink.offs.get(k, 0) for k in range(48)]


def main():
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    r = asg[ROW]
    d0 = bytearray(bytes.fromhex(r["d0"]))
    d4 = bytearray(bytes.fromhex(r["d4"]))
    if MODE == "zero":
        patch = {(0, i): b"\0" * 4 for i in (0, 1, 2, 3)}
        patch.update({(4, i): b"\0" * 4 for i in (4, 5, 6)})
        patch[(2, 0)] = b"\0" * 4
    else:
        patch = {(0, 0): bytes([d0[0] ^ 1]) + bytes(d0[1:4])}
    a, _ = run(patch)
    b, st = run(None)
    print("steps", b.steps, "status", st)
    ta, tb = a.emit_trace, b.emit_trace
    print("emit counts", len(ta), len(tb))
    n = min(len(ta), len(tb))
    for i in range(n):
        if ta[i] != tb[i]:
            print("first EMIT divergence at #%d" % i)
            for j in range(max(0, i - 6), min(n, i + 6)):
                mark = ">>" if j == i else "  "
                print("%s #%5d %s" % (mark, j, tb[j]), (ta[j] if ta[j] != tb[j] else ""))
            break
    else:
        print("no divergence in first", n, "emits")
    ba, bb = body(a), body(b)
    print("body differ at", [i for i in range(48) if ba[i] != bb[i]][:20])


if __name__ == "__main__":
    main()


def second_diff():
    """Same descriptors, two seconds: where does the second enter?"""
    asg = json.load(open(os.path.join(HERE, "all_signings.json")))
    ph3 = json.load(open(os.path.join(HERE, "pair_h3.json")))
    r, p = asg[ROW], ph3[ROW]
    descs = []
    for bi in M.VA_ORDER:
        hx = r.get("d%d" % bi, "")
        data = bytes.fromhex(hx) if hx else b""
        descs.append((len(data) // 4, 0, data))
    out = []
    for s in (int(p["second"]), int(p["second"]) + 1):
        ex = M.FinEx(s, descs)
        ex.run(max_steps=60_000_000)
        out.append(ex.emit_trace)
    ta, tb = out
    print("emit counts", len(ta), len(tb))
    n = min(len(ta), len(tb))
    for i in range(n):
        if ta[i] != tb[i]:
            print("first EMIT divergence at #%d" % i)
            for j in range(max(0, i - 4), min(n, i + 8)):
                print((">>" if j == i else "  ") + " #%5d s1=%s s2=%s" %
                      (j, ta[j], tb[j]))
            return
    print("no divergence in first", n)
