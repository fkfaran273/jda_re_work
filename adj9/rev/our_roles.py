"""our_roles.py - apply the GOLDEN role table to our own single-call capture.

Golden segment 0 roles (count, first word):
  #10 90  'KlcA…' ASCII claims      #0  36  13271271 (tile ×8)   #4  8  00100400
  #9   5  fad0f10d                  #8   4  bfffffff            #2  1  fb1a8296
  #7   1  00000168 (=360)           #5/#6 1  00000000
Our signing uses a 47-pair map -> claims 336 B -> #7 = 0x150, #10 = 84 dwords.

This script (a) segments the emit plane by the pos-0 rule, (b) prints each stream's
role, (c) reports whether a 5-word #9 stream is present at all.
"""
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)

d = json.load(open(os.path.join(HERE, "wh_out1.json"), encoding="utf-8"))
blob = base64.b64decode(d["blobB64"])
print("blob:", blob.hex())
print("nemit", d["nemit"], "nlenq", d["nlenq"], "map", len(d["mapPairs"]))

EM = [(st, n, v) for st, n, v in d["emits"]]
segs = []
cur = {}
for st, n, v in EM:
    if n == 0 and st in cur and cur[st]:
        segs.append(cur)
        cur = {}
    cur.setdefault(st, {})[n] = v
segs.append(cur)
print("emit segments:", len(segs), "sizes:", [sum(len(v) for v in s.values()) for s in segs])
seg = segs[-1] if len(segs) > 1 else segs[0]
print("using segment with %d emits" % sum(len(v) for v in seg.values()))

# claims for cross-checks
claims = None
try:
    sys.path.insert(0, HERE)
    import desc10_law
    claims = desc10_law.build_desc10(dict(d["mapPairs"]), "session")
    if isinstance(claims, tuple):
        claims = claims[0]
except Exception as e:
    print("claims law:", e)
if claims:
    print("claims len:", len(claims))

print()
print("--- our streams (count, first words) + role guess ---")
rows = []
for st, m in seg.items():
    vs = [m[k] for k in sorted(m)]
    first = vs[:4]
    guess = ""
    if len(vs) == 36:
        reps = 0
        for i in range(0, len(vs) - 4):
            t = vs[i:i + 4]
            if not any(t):
                continue
            r = 1
            while i + 4 * (r + 1) <= len(vs) and vs[i + 4 * r:i + 4 * (r + 1)] == t:
                r += 1
            reps = max(reps, r)
        guess = "#0 (36 w, tile reps=%d)" % reps if reps >= 6 else "36-word aux (reps=%d)" % reps
    elif len(vs) == 8:
        guess = "#4"
    elif len(vs) == 5:
        guess = "#9"
    elif len(vs) == 4:
        guess = "#8"
    elif len(vs) == 1:
        guess = "#2/#5/#6/#7"
    elif len(vs) == 84:
        guess = "#10 (claims)"
    elif len(vs) in (107, 113, 658):
        guess = "assembly buffer"
    rows.append((len(vs), vs[0], first, st, guess))
rows.sort(key=lambda r: -r[0])
for cnt, v0, first, st, guess in rows:
    print("  count=%-4d first=%08x %s  %s" %
          (cnt, v0, ["%08x" % y for y in first], guess))

# is the claims string in the 84-word stream?
print()
for st, m in seg.items():
    vs = [m[k] for k in sorted(m)]
    if len(vs) == 84:
        raw = b"".join(struct.pack(">I", v) for v in vs)
        print("84-word stream first16:", raw[:16])
        if claims:
            print("equals claims:", raw[:len(claims)] == claims[:len(raw)],
                  "| claims==raw:", bytes(claims) == raw)