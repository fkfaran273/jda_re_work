# Extract all ST[0..15]-touching write "layers" with effective XOR deltas,
# for block 0 (pass 1) and block 1 (pass 2) init phases.
import gzip
from collections import defaultdict

STLO = 0x900e6e8
KEYLO = 0x900e3e8

stw = []
krd = []
evi = 0
with gzip.open("trace4.txt.gz", "rt") as f:
    for line in f:
        p = line.split()
        w = p[0] == "W"
        a = int(p[2], 16)
        s = int(p[3])
        v = int(p[4], 16) & ((1 << (s * 8)) - 1)
        if s == 4:
            if KEYLO <= a < KEYLO + 768 and not w:
                krd.append((evi, (a - KEYLO) // 4))
            elif STLO <= a < STLO + 1024 and w:
                stw.append((evi, (a - STLO) // 4, v))
        evi += 1

# key group boundaries (rounds)
groups = []
cur = [krd[0]]
for item in krd[1:]:
    if item[0] - cur[-1][0] > 4000:
        groups.append(cur)
        cur = [item]
    else:
        cur.append(item)
groups.append(cur)
g1 = groups[1][0][0]   # first slot-0 read = start of round 1 pass 1
# pass 2 round 1 start: the group after the IV group (slots 175..190)
iv_gi = [i for i, g in enumerate(groups) if g[0][1] == 175][0]
g2 = groups[iv_gi + 1][0][0]
print("pass1 round1 starts ev", g1, "; pass2 round1 starts ev", g2)


def layers_between(lo, hi, base=0):
    """Return list of (kind, detail) for ST[base..base+15] writes in [lo,hi)."""
    seg = [(e, i, v) for e, i, v in stw if lo <= e < hi and base <= i < base + 16]
    out = []
    st = {}
    i = 0
    while i < len(seg):
        e, idx, v = seg[i]
        if idx not in st or st[idx] is None:
            st[idx] = v
            out.append(("init", idx, v))
            i += 1
            continue
        # collect a run: writes to consecutive distinct idx (a layer)
        run = []
        j = i
        while j < len(seg) and len(run) < 16:
            run.append(seg[j])
            j += 1
        idxs = [r[1] for r in run]
        if len(set(idxs)) == len(idxs) and len(idxs) >= 8:
            delta = {}
            for e2, i2, v2 in run:
                delta[i2] = st.get(i2, 0) ^ v2
                st[i2] = v2
            out.append(("layer", idxs,
                        bytes(delta[k] for k in sorted(delta))))
            i = j
        else:
            st[idx] = v
            out.append(("single", idx, v))
            i += 1
    return out


print("\n===== BLOCK 0 init layers (ev 0 .. %d) =====" % g1)
for kind, a, b in layers_between(0, g1):
    if kind == "layer":
        print("layer idxs=%s delta=%s" % (a, b.hex()))
    else:
        pass  # skip singles for brevity

print("\n===== BLOCK 0 round-phase layers (ev %d .. %d) =====" % (g1, g2))
for kind, a, b in layers_between(g1, g2):
    if kind == "layer":
        print("layer idxs=%s delta=%s" % (a[:4], b.hex()))

print("\n===== BLOCK 1 init layers (ev %d .. %d) on ST[16..31] =====" % (0, g2))
for kind, a, b in layers_between(0, g2, base=16):
    if kind == "layer":
        print("layer idxs=%s delta=%s" % ([x - 16 for x in a[:4]], b.hex()))
