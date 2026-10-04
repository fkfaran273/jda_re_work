"""d0_struct.py - structure of #0 (144 B) across all 10 real signings.

Slice 115 said #0 = [W0][C1][C2][C3][W1][C1][C2][C3]x8, i.e. a 16-byte tile repeated.
If that holds for every sample, #0 is determined by only ~5 distinct words, which
shrinks the unknown to (W0, tile, #2, #4).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
S = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))

for i, x in enumerate(S):
    raw = bytes.fromhex(x["d0"])
    w = [int.from_bytes(raw[j:j + 4], "big") for j in range(0, len(raw), 4)]
    uniq = []
    for v in w:
        if v not in uniq:
            uniq.append(v)
    # best period over the 36 words
    best, blen = None, 0
    for p in (1, 2, 3, 4, 5, 6, 8):
        ok = sum(1 for j in range(p, len(w)) if w[j] == w[j - p])
        if ok > blen:
            blen, best = ok, p
    tail = w[1:]
    reps = 0
    if len(tail) >= 4:
        t = tail[:4]
        while reps * 4 + 4 <= len(tail) and tail[reps * 4:reps * 4 + 4] == t:
            reps += 1
    print("[%2d] words=%-3d distinct=%-3d bestperiod=%-2d(%-2d matches) tail-tile=%s reps=%d" %
          (i, len(w), len(uniq), best, blen,
           ["%08x" % t for t in w[1:5]], reps))
    print("      distinct words: %s" % ["%08x" % u for u in uniq[:10]])
    # is the tail a rotation of an 8-word cycle?
    if len(w) >= 9:
        per8 = sum(1 for j in range(8, len(w)) if w[j] == w[j - 8])
        print("      period-8 matches: %d/%d   period-4: %d/%d" %
              (per8, len(w) - 8,
               sum(1 for j in range(4, len(w)) if w[j] == w[j - 4]), len(w) - 4))