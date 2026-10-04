"""scan_q.py — deep analysis of the queue/stream channel logs."""
import sys, os, pickle
from collections import Counter, defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "pure_signer"))
from pure_sign import KB as KB_REF, T as T_REF

kb55 = bytes(v ^ 0x55 for v in KB_REF)
t55 = bytes(v ^ 0x55 for v in T_REF)
NAMES = (("KB", KB_REF), ("KB^55", kb55), ("T", T_REF), ("T^55", t55))

# every aligned 4-gram of each form -> (name, off)
gram = {}
for name, ref in NAMES:
    for off in range(0, len(ref) - 3):
        gram.setdefault(ref[off:off + 4], []).append((name, off))
print("4-gram map:", len(gram), "entries")

with open(os.path.join(HERE, "trace_q.pkl"), "rb") as f:
    d = pickle.load(f)

qops, emits, lenqs = d["qops"], d["emits"], d["lenqs"]

# ---- 1. per-value 4-gram scan (qops + lenqs + emits), both endians ----
hits = Counter()
hitmeta = defaultdict(list)
for (kind, p, qva, val) in qops:
    for end in ("little", "big"):
        b4 = val.to_bytes(4, end)
        if b4 in gram:
            for (nm, off) in gram[b4]:
                hits[(nm, kind, p)] += 1
                if len(hitmeta[(nm, kind, p)]) < 6:
                    hitmeta[(nm, kind, p)].append((off, qva, val, end))
for (p, sva, n, v) in emits:
    for end in ("little", "big"):
        b4 = v.to_bytes(4, end)
        if b4 in gram:
            for (nm, off) in gram[b4]:
                hits[(nm, "EMIT", p)] += 1
                if len(hitmeta[(nm, "EMIT", p)]) < 6:
                    hitmeta[(nm, "EMIT", p)].append((off, sva, v, end))
for (p, sva, n, ret) in lenqs:
    for end in ("little", "big"):
        b4 = ret.to_bytes(4, end)
        if b4 in gram:
            for (nm, off) in gram[b4]:
                hits[(nm, "LENQ", p)] += 1
                if len(hitmeta[(nm, "LENQ", p)]) < 6:
                    hitmeta[(nm, "LENQ", p)].append((off, sva, ret, end))
print("== value 4-gram hits by (name, kind, pc):")
for k, c in sorted(hits.items(), key=lambda kv: -kv[1])[:40]:
    print("  %-7s %-5s pc=%08x  n=%d  e.g. %s" %
          (k[0], k[1], k[2], c, hitmeta[k][:3]))

# ---- 2. pc histograms ----
for label, seq, idx in (("PUSHPOP", qops, 1), ("EMIT", emits, 0), ("LENQ", lenqs, 0)):
    c = Counter(x[idx] for x in seq)
    print("== %s pc histogram (top 25 of %d):" % (label, len(c)))
    print("  ", " ".join("%x:%d" % (p, n) for p, n in
                         sorted(c.items(), key=lambda kv: -kv[1])[:25]))

# ---- 3. qva histograms ----
c = Counter(x[2] for x in qops)
print("== qop qva histogram:", {hex(k): v for k, v in
      sorted(c.items(), key=lambda kv: -kv[1])[:12]})
c = Counter(x[1] for x in lenqs)
print("== lenq sva histogram:", {hex(k): v for k, v in
      sorted(c.items(), key=lambda kv: -kv[1])[:12]})
c = Counter(x[1] for x in emits)
print("== emit sva histogram:", {hex(k): v for k, v in
      sorted(c.items(), key=lambda kv: -kv[1])[:12]})

# ---- 4. where does the blob get emitted (the cipher tail)? ----
# find emit events of the SINK words 4..47 (post-header) and print the
# qop/lenq activity BETWEEN consecutive blob-word emits (the cipher rounds)
last = {}
for (sva, n, v) in [(0, 0, 0)]:
    pass
