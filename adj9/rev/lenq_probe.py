"""lenq_probe.py - hunt the TRUE #2 for seg27 (fresh CLICK signing) in LENQ + all segments.

Seg27 (EMIT) has every role EXCEPT a valid #2 (cd9d3a91 refuted, diff 44/48).
The true #2 must be (a) a single in ANOTHER segment, or (b) LENQ-read from
memory/a stream written elsewhere. This probe:
 1. lists all 86 segments' stream-size profiles;
 2. collects every distinct single-word value across ALL segments;
 3. summarizes the LENQ plane: distinct streams, top values, values NEVER
    emitted (memory-sourced reads);
 4. prints the candidate set for FinEx trials.
"""
import json, os, struct, sys
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
d = json.load(open(os.path.join(HERE, "app_dump.json"), encoding="utf-8"))
print("nemit=%d nlenq=%d nblobs=%d" % (d["nemit"], d["nlenq"], len(d.get("blobs", []))))


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
print("segments: %d" % len(segs))
# 1. size profiles: which segments look like signings (have 36+48+97)?
print("--- segments with 36w+48w streams ---")
for k, seg in enumerate(segs):
    sizes = sorted(len(v) for v in seg.values())
    if 36 in sizes and 48 in sizes:
        heads = {}
        for st, m in seg.items():
            vs = [m[i] for i in sorted(m)]
            heads.setdefault(len(vs), []).append(vs[0])
        print("  seg %d sizes=%s" % (k, sizes))
        for cnt in sorted(heads):
            print("    n=%-3d streams=%d heads=%s" %
                  (cnt, len(heads[cnt]), ["%08x" % h for h in heads[cnt][:4]]))
# 2. every distinct single across all segments
singles = Counter()
single_loc = {}
for k, seg in enumerate(segs):
    for st, m in seg.items():
        if len(m) == 1:
            v = m[sorted(m)[0]]
            singles[v] += 1
            single_loc.setdefault(v, []).append(k)
print("--- distinct singles across all segments: %d ---" % len(singles))
for v, c in singles.most_common(40):
    print("  %08x x%d segs=%s" % (v, c, sorted(set(single_loc[v]))[:8]))
# 3. LENQ plane
L = d.get("lenq", [])
print("--- LENQ: %d reads ---" % len(L))
lstreams = Counter()
lvals = Counter()
for e in L:
    st, n, v = e[0], e[1], e[2]
    lstreams[st] += 1
    lvals[v] += 1
print("distinct LENQ streams: %d" % len(lstreams))
print("top LENQ streams:", [(str(s), c) for s, c in lstreams.most_common(8)])
print("top LENQ values:", [("%08x" % v, c) for v, c in lvals.most_common(15)])
# emitted values set (for memory-sourced detection)
emitted = set()
for st, n, v in d["emits"]:
    emitted.add(v & 0xFFFFFFFF)
memvals = [(v, c) for v, c in lvals.most_common(400) if v not in emitted]
print("--- LENQ values NEVER emitted (memory-sourced, top 40) ---")
for v, c in memvals[:40]:
    print("  %08x x%d" % (v, c))
print("memory-sourced distinct total: %d" % len([v for v in lvals if v not in emitted]))
