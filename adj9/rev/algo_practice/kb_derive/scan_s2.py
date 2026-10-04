"""scan_s2.py — byte-granular view of scratch stream regions; find T and KB."""
import sys, os, pickle
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "pure_signer"))
from pure_sign import KB as KB_REF, T as T_REF

kb55 = bytes(v ^ 0x55 for v in KB_REF)
t55 = bytes(v ^ 0x55 for v in T_REF)

with open(os.path.join(HERE, "trace_q.pkl"), "rb") as f:
    d = pickle.load(f)
offs = d["streams"][0x5450001000]
idxs = sorted(offs)

# group into runs of consecutive idx with 8-bit values
runs = []
cur = []
for i in idxs:
    v = offs[i]
    if v < 256:
        if cur and i == cur[-1][0] + 1:
            cur.append((i, v))
        else:
            if len(cur) >= 8:
                runs.append(cur)
            cur = [(i, v)]
    else:
        if len(cur) >= 8:
            runs.append(cur)
        cur = []
if len(cur) >= 8:
    runs.append(cur)
print("byte runs (len>=8):", [(r[0][0], r[-1][0], len(r)) for r in runs])

def find_all(bys, ref):
    out = []
    start = 0
    while True:
        p = bys.find(ref, start)
        if p < 0:
            break
        out.append(p)
        start = p + 1
    return out

for r in runs:
    base = r[0][0]
    bys = bytes(v for _, v in r)
    for name, ref in (("T", T_REF), ("T^55", t55), ("KB", KB_REF), ("KB^55", kb55)):
        ps = find_all(bys, ref)
        if ps:
            print("RUN@%d len %d: FULL %s found at offsets %s (idx %s)"
                  % (base, len(bys), name, ps[:4], [base + p for p in ps[:4]]))
    # 4-gram coverage
    for name, ref in (("T", T_REF), ("KB", KB_REF)):
        n4 = sum(1 for off in range(0, len(ref) - 3) if ref[off:off + 4] in bys)
        if n4:
            print("RUN@%d len %d: %s 4-grams %d/237" % (base, len(bys), name, n4))

# T-lookup reads: which idx range does lenq@0x111e40 read from?
print("== lenq@111e40 (T lookups?) first 48:")
n = 0
for (p, s, i, ret) in d["lenqs"]:
    if p == 0x111e40:
        print("   idx=%d ret=%02x" % (i, ret))
        n += 1
        if n >= 48:
            break
print("== lenq@111ea4 first 24:")
n = 0
for (p, s, i, ret) in d["lenqs"]:
    if p == 0x111ea4:
        print("   idx=%d ret=%02x" % (i, ret))
        n += 1
        if n >= 24:
            break

# which pcs EMIT into the byte runs? for each run, list emitting pcs
for r in runs[:6]:
    base = r[0][0]
    pcw = Counter()
    for (p, s, i, v) in d["emits"]:
        if s == 0x5450001000 and base <= i <= r[-1][0]:
            pcw[p] += 1
    print("RUN@%d writers: %s" % (base, pcw.most_common(8)))
