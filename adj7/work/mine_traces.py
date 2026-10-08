"""mine_traces.py — extract the whitening's per-pass I/O from the stage-4
read/write traces (mint 0001, attribution, sec 1789382946).

reads:  idx pc addr size valuehex   (armed at whitening start)
stores: idx pc addr size valuehex

Outputs:
  - the KB copy (64 dwords read 16x) and its address
  - per pass: every non-KB read (addr, size, value)
  - the output writes (the word-swapped blob location)

    python mine_traces.py
"""
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))

reads = []
with open(os.path.join(WORK, "adj7s4_reads.txt")) as f:
    for ln in f:
        p = ln.split()
        if len(p) >= 5:
            reads.append((int(p[1], 16), int(p[2], 16), int(p[3]),
                          int(p[4], 16)))
print("reads:", len(reads))

stores = []
with open(os.path.join(WORK, "adj7s4_stores7.txt")) as f:
    for ln in f:
        p = ln.split()
        if len(p) >= 5:
            stores.append((int(p[1], 16), int(p[2], 16), int(p[3]),
                           int(p[4], 16)))
print("stores:", len(stores))

# --- KB copy: dwords (size 4) read exactly 16 times ---
c4 = Counter(a for pc, a, s, v in reads if s == 4)
kb = sorted(a for a, c in c4.items() if c == 16)
# find the longest ascending contiguous run
best = []
cur = [kb[0]] if kb else []
for a in kb[1:]:
    if a == cur[-1] + 4:
        cur.append(a)
    else:
        if len(cur) > len(best):
            best = cur
        cur = [a]
if len(cur) > len(best):
    best = cur
print("KB-copy candidates: dwords read 16x =", len(kb),
      " longest contiguous run:", len(best), "at %#x" % best[0] if best else "")
kb_base, kb_end = (best[0], best[-1]) if best else (None, None)

# --- pass segmentation on the first KB dword ---
times = [i for i, (pc, a, s, v) in enumerate(reads)
         if kb_base is not None and a == kb_base and s == 4]
print("pass starts:", len(times))

out_passes = []
for p in range(len(times) - 1):
    seg = reads[times[p]:times[p + 1]]
    nonkb = [(hex(a), s, hex(v)) for pc, a, s, v in seg
             if not (kb_base <= a <= kb_end)]
    out_passes.append(nonkb)
for p, np_ in enumerate(out_passes[:4]):
    print("pass %d: %d non-KB reads: %s" % (p, len(np_), np_[:14]))
if len(out_passes) > 4:
    print("pass 15:", len(out_passes[15]), out_passes[15][:10])

# tail after last KB read (finalization)
tail = reads[times[-1] + 1:]
tail_nonkb = [(hex(a), s, hex(v)) for pc, a, s, v in tail
              if not (kb_base <= a <= kb_end)]
print("tail non-KB reads:", len(tail_nonkb), tail_nonkb[:14])

# --- writes in the whitening window ---
if kb_base is not None:
    t0, t1 = times[0], times[-1]
    win = stores  # stores file is already whitening-filtered
    waddr = Counter(a for pc, a, s, v in win)
    hot = sorted(a for a, c in waddr.items() if c >= 8)
    print("\nstore addrs written >=8x:", len(hot))
    # contiguous output region of 16-B chunks written 16x each
    runs, cur = [], []
    for a in hot:
        if cur and a == cur[-1] + 4:
            cur.append(a)
        else:
            if len(cur) >= 32:
                runs.append(cur)
            cur = [a]
    if len(cur) >= 32:
        runs.append(cur)
    for r in runs[:6]:
        print("  write run %#x .. %#x (%d dwords)" % (r[0], r[-1], len(r)))

json.dump({"kb_base": kb_base, "kb_end": kb_end, "n_passes": len(times),
           "passes": out_passes, "tail": tail_nonkb},
          open(os.path.join(HERE, "mine_out.json"), "w"))
print("wrote mine_out.json")
