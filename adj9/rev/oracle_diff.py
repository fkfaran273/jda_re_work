"""Positional analysis of the oracle blobs: is ANY byte position stable
across repeated nSign calls with identical inputs?"""
import re
import os

CAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cap")
LOG = os.path.join(CAP, "oracle_run3.log")


def main():
    txt = open(LOG, encoding="utf-8", errors="replace").read()
    blobs = []   # (label, hex)
    cur = None
    for ln in txt.splitlines():
        m = re.match(r"###ADJ9_BEGIN type=(\S+)", ln)
        if m:
            cur = m.group(1)
            buf = []
            continue
        if cur:
            buf.append(ln)
        if cur and ln.startswith("###ADJ9_END"):
            body = "\n".join(buf)
            mh = re.search(r"(?:real_)?hex=([0-9a-f]{384})", body)
            if mh:
                blobs.append((cur, mh.group(1)))
            cur = None

    want = ["oracle_start", "oracle_same_0", "oracle_same_1", "oracle_same_2",
            "oracle_hflip", "oracle_mapflip"]
    sel = []
    for w in want:
        for lbl, h in blobs:
            if lbl == w:
                sel.append((w, bytes.fromhex(h)))
                break
    print("blobs: %d" % len(sel))
    for lbl, b in sel:
        print("  %-16s %s" % (lbl, b.hex()[:64]))

    if len(sel) < 2:
        return
    n = len(sel[0][1])
    print("\nlen = %d for all: %s" % (n, all(len(b) == n for _, b in sel)))

    print("\n=== per-position distinct values across %d blobs ===" % len(sel))
    const = []
    for i in range(n):
        vals = set(b[i] for _, b in sel)
        if len(vals) == 1:
            const.append((i, next(iter(vals))))
    print("  positions constant across ALL blobs: %d" % len(const))
    for i, v in const[:64]:
        print("    [%3d] = 0x%02x" % (i, v))

    # pairwise difference counts
    print("\n=== pairwise differing bytes ===")
    for i in range(len(sel)):
        for j in range(i + 1, len(sel)):
            d = sum(1 for a, b in zip(sel[i][1], sel[j][1]) if a != b)
            print("  %-16s vs %-16s : %d/%d differ" % (sel[i][0], sel[j][0], d, n))

    # is any 4/8/16-byte aligned window repeated between blobs?
    print("\n=== shared 16-byte aligned blocks between any two blobs ===")
    hits = 0
    for i in range(len(sel)):
        for j in range(i + 1, len(sel)):
            for k in range(0, n, 16):
                if sel[i][1][k:k + 16] == sel[j][1][k:k + 16]:
                    print("  %s == %s at block %d" % (sel[i][0], sel[j][0], k // 16))
                    hits += 1
    print("  shared blocks: %d" % hits)

    # byte-value histogram over all blobs
    allb = b"".join(b for _, b in sel)
    print("\ndistinct byte values overall: %d/256" % len(set(allb)))


if __name__ == "__main__":
    main()
