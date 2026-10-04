"""chain_table.py — the per-word chain, read straight off the measured model.

For every body word j the model columns tell exactly which region bits can
reach it, so the whitening chain is reported as a dependency table instead of
a hand-traced one:

    body word j  <-  { (name, bit) : cols[32*n + bit] has bit j set }

Also reports, for each input bit, the first and last body word it touches.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bodymodel as BM          # noqa: E402


def table(cache, out=None):
    raw = json.load(open(cache))
    m = BM.Model.from_raw(raw)
    names = [a[0] for a in BM.ACTIVE]
    rows = []
    for j in range(BM.BODY_WORDS):
        src = []
        for n, nm in enumerate(names):
            hits = [b for b in range(32) if (m.cols[32 * n + b] >> j) & 1]
            if hits:
                src.append((nm, hits))
        rows.append(src)
    return m, names, rows


def main():
    cache = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "cache_row7.json")
    out = sys.argv[2] if len(sys.argv) > 2 else None
    m, names, rows = table(cache)
    doc = {"cache": os.path.basename(cache), "rank": m.rank, "words": {}}
    print("model rank %d  (%s)" % (m.rank, os.path.basename(cache)))
    hdr = "body word : " + " ".join("%-9s" % n for n in names)
    print(hdr)
    for j, src in enumerate(rows):
        cells = []
        for nm in names:
            h = dict(src).get(nm, [])
            cells.append("%-9s" % (("%d" % len(h)) if h else "."))
        print("  w%-6d  %s" % (j, " ".join(cells)))
        doc["words"]["w%d" % j] = {nm: h for nm, h in src}
    print()
    print("input bit -> body word span")
    for n, nm in enumerate(names):
        for b in range(32):
            ws = [j for j in range(BM.BODY_WORDS) if (m.cols[32 * n + b] >> j) & 1]
            if ws:
                print("  %-3s[%2d] : n=%3d  w%d..w%d" % (nm, b, len(ws), min(ws), max(ws)))
    if out:
        json.dump(doc, open(out, "w"))
        print("wrote", out)


if __name__ == "__main__":
    main()
