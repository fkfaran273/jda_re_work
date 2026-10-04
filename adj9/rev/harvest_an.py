"""harvest_an.py - analyse the live mint: EMIT stream (sink,n,val) vs the blob.
Question: are the descriptor words (#0/#2/#4 region) visible in the EMIT plane?
Search targets: golden descriptor words (fin_descs) + the blob's own dwords.
"""
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)

d = json.load(open(os.path.join(HERE, "harvest_out.json"), encoding="utf-8"))
blob = base64.b64decode(d["blobB64"])
emits = d["emits"]
print("blob len      :", len(blob), "dwords", len(blob) // 4)
print("blob hex      :", blob.hex())
print("emits captured:", len(emits), "(cap reached:", d["nemits"] > 6000, ")")

# per-sink census
sinks = {}
for s, n, v in emits:
    e = sinks.setdefault(s, {"n": 0, "maxn": -1, "vals": set()})
    e["n"] += 1
    e["maxn"] = max(e["maxn"], n)
    if len(e["vals"]) < 4000:
        e["vals"].add(v)
print()
print("distinct sinks :", len(sinks))
for s in sorted(sinks, key=lambda x: -sinks[x]["n"])[:12]:
    e = sinks[s]
    print("  sink=%-12d n=%-5d maxn=%-5d distinct=%-5d" %
          (s, e["n"], e["maxn"], len(e["vals"])))

# blob dwords as targets
bd = list(struct.unpack("<%dI" % (len(blob) // 4), blob))
print()
print("blob dwords   :", " ".join("%08x" % x for x in bd))

# golden known values (from fin_descs/slice 104): #0 triad + #2 candidates
KNOWN = {
    0x13271271: "#0 W0 (golden)",
    0xb7d0992b: "#0 C1", 0xdb50f44c: "#0 C2", 0xb63798cc: "#0 C3",
    0xdab7f51a: "#0 W1", 0xfb1a8296: "#2 (golden)", 0x4bce691e: "#2 (det2)",
}
allvals = {}
for s, n, v in emits:
    allvals.setdefault(v, []).append((s, n))
print()
print("--- golden-word search in EMIT ---")
for w, nm in KNOWN.items():
    hits = allvals.get(w, [])
    print("  %-18s %08x  hits=%d %s" % (nm, w, len(hits), hits[:3]))

print()
print("--- blob-dword search in EMIT (body only, skip 4 header) ---")
found = 0
for i, w in enumerate(bd):
    hits = allvals.get(w, [])
    if hits:
        found += 1
        print("  blob[%2d] %08x hits=%-3d %s" % (i, w, len(hits), hits[:2]))
print("blob dwords present in EMIT: %d / %d" % (found, len(bd)))

# does any EMIT value appear in the blob?
val2blob = {}
for i, w in enumerate(bd):
    val2blob.setdefault(w, []).append(i)
cand = [(s, n, v) for s, n, v in emits if v in val2blob]
print()
print("emits whose value is a blob dword: %d" % len(cand))
for s, n, v in cand[:60]:
    print("   sink=%-12d n=%-6d val=%08x  blob idx %s" % (s, n, v, val2blob[v]))

# coverage: how many of the 48 blob dwords are reachable via EMIT
cov = sorted(set(i for i in val2blob if any(v == bd[i] for _, _, v in emits)))
print()
print("blob dword coverage in EMIT: %d / 48" % len(cov))
print("  covered idx:", cov)
print("  missing idx:", [i for i in range(48) if i not in cov])

# for each sink that carries blob words, print its full (n -> val) map
print()
print("--- sinks carrying blob words ---")
bysink = {}
for s, n, v in cand:
    bysink.setdefault(s, {})[n] = v
for s in sorted(bysink, key=lambda x: -len(bysink[x])):
    m = bysink[s]
    print("sink=%d  n=%d  maxn=%d" % (s, len(m), max(m)))
    items = sorted(m.items())
    for n, v in items[:60]:
        print("    n=%-6d %08x  -> blob idx %s" % (n, v, val2blob.get(v)))
    if len(items) > 60:
        print("    ... %d more" % (len(items) - 60))