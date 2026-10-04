"""seg54_probe.py - seg54 shares the seg27 tile: same signing second phase,
or a different signing with the same #0?

seg54 sizes=[4,6,8,36], 36w head=fdda97ce. Compare: 36w content == seg27 36w?
4w/6w/8w contents vs seg27 singles/#8/#4. Any 48w/97w nearby?
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))


def segment(rows):
    segs, cur = [], {}
    for st, n, v in rows:
        if n == 0 and st in cur and cur[st]:
            segs.append(cur)
            cur = {}
        cur.setdefault(st, {})[n] = v
    segs.append(cur)
    return segs


def b(vs):
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in vs)


segs = segment([(st, n, v) for st, n, v in d["emits"]])
for k in (27, 54, 1, 2, 19, 4):
    s = segs[k]
    print("=== seg %d ===" % k)
    for st, m in s.items():
        vs = [m[i] for i in sorted(m)]
        print("  n=%-3d head=%s" % (len(vs), " ".join("%08x" % v for v in vs[:6])))
s27 = {len(m): [m[i] for i in sorted(m)] for st, m in segs[27].items()}
s54 = {len(m): [m[i] for i in sorted(m)] for st, m in segs[54].items()}
a, c = s27[36], s54[36]
print("36w seg27==seg54:", a == c, " diffs:", sum(1 for x, y in zip(a, c) if x != y), "/36")
for n in (4, 8):
    if n in s54 and n in s27:
        x, y = s27[n], s54[n]
        print("n=%d seg27==seg54: %s (seg27 %s / seg54 %s)" %
              (n, x == y, " ".join("%08x" % v for v in x[:4]),
               " ".join("%08x" % v for v in y[:4])))
