"""wh_an.py - analyse the LENQ plane (what the VM READS) of a labelled mint.

Questions:
 1. recover the signing second from the blob header;
 2. do the blob's 48 dwords appear among LENQ returns (and on which streams/slots)?
 3. do the region signatures (#0 16-byte tile / #4 ascending density) appear there?
 4. can the descriptor set be read off directly (stream -> words) to feed FinEx?
"""
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from header_gen import make_header

d = json.load(open(os.path.join(HERE, "wh_out.json"), encoding="utf-8"))
blob = base64.b64decode(d["blobB64"])
bd = list(struct.unpack("<48I", blob))
print("nlenq=%d nemit=%d map=%d pairs" % (d["nlenq"], d["nemit"], len(d["mapPairs"])))
print("blob:", blob.hex())
sec = None
for s in range(1789830000, 1789860000):
    if make_header(s) == blob[:16]:
        sec = s
        break
print("second:", sec, "header OK:", make_header(sec) == blob[:16] if sec else None)

LENQ = d["lenq"]
EM = d["emits"]

# --- 1. blob dwords in LENQ ---
pos = {}
for i, x in enumerate(bd):
    pos.setdefault(x, []).append(i)
hits = {}
for st, n, v in LENQ:
    if v in pos:
        hits.setdefault(st, []).append((n, v, pos[v]))
print()
print("--- LENQ streams carrying blob dwords ---")
for st in sorted(hits, key=lambda x: -len(hits[x])):
    h = hits[st]
    print("stream %s : %d hits" % (st, len(h)))
    for n, v, idx in h[:20]:
        print("    n=%-6d %08x -> blob idx %s" % (n, v, idx))
print("total blob dwords seen in LENQ: %d / 48"
      % len(set(i for h in hits.values() for _, _, i in h)))

# --- 2. per-stream census ---
S = {}
for st, n, v in LENQ:
    S.setdefault(st, {})[n] = v
print()
print("--- LENQ streams (slots) ---")
for st in sorted(S, key=lambda x: -len(S[x]))[:20]:
    m = S[st]
    ns = sorted(m)
    print("  %-20s slots=%-5d n=%d..%d" % (st, len(m), ns[0], ns[-1]))

# --- 3. region signatures ---
def pc(x):
    return bin(x).count("1")

print()
print("--- 16-byte repeating tiles in LENQ streams ---")
for st in S:
    ns = sorted(S[st])
    vals = [S[st][n] for n in ns]
    for i in range(0, len(vals) - 16):
        t = vals[i:i + 4]
        if not any(t):
            continue
        reps = 1
        while i + 4 * (reps + 1) <= len(vals) and vals[i + 4 * reps:i + 4 * (reps + 1)] == t:
            reps += 1
        if reps >= 6:
            print("  stream %s slot %d tile=%s reps=%d" %
                  (st, ns[i], ["%08x" % x for x in t], reps))

print()
print("--- ascending-density 8-word runs in LENQ streams ---")
for st in S:
    ns = sorted(S[st])
    vals = [S[st][n] for n in ns]
    for i in range(0, len(vals) - 8):
        seg = vals[i:i + 8]
        p = [pc(x) for x in seg]
        if p[0] <= 3 and all(p[k] <= p[k + 1] for k in range(7)) and p[-1] >= 4 and sum(p) >= 20 and sum(p) <= 100:
            print("  stream %s slot %d pop=%s %s" %
                  (st, ns[i], p, ["%08x" % x for x in seg]))

# --- 4. header words in LENQ ---
hdr = list(struct.unpack(">4I", make_header(sec))) if sec else []
print()
print("--- header words in LENQ ---", ["%08x" % x for x in hdr])
for w in hdr:
    found = [(st, n) for st, n, v in LENQ if v == w]
    print("  %08x hits=%d %s" % (w, len(found), found[:4]))