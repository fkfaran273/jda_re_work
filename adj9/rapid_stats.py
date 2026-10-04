#!/usr/bin/env python3
"""rapid_stats.py — what is a pure function of the second, and what is per-signing?
Uses corpus.json (16 H + 22 canonicals) and 396 rapid blobs (each with known sec).
Tests: (1) header == Random3(second) across all blobs; (2) same-second signings:
  header identical? which body dwords vary?  (3) H vs canonical relations."""
import json, os, sys, hashlib, hmac, struct, collections
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "rev"))
sys.stdout.reconfigure(line_buffering=True)

d = json.load(open(os.path.join(HERE, "rev", "corpus.json")))
print("sign_inputs", len(d["sign_inputs"]), "| hs", len(d["hs"]),
      "| blobs", len(d["blobs"]), "| rapid", len(d["rapid"]))

# ---- gather (blob_hex, sec_or_None, ts) ----
items = []
for b in d["blobs"]:
    items.append({"hex": b["hex"], "ts": b["ts"], "sec": b.get("sec"), "src": "blob"})
for r in d["rapid"]:
    items.append({"hex": r["hex"], "ts": r["t0"], "sec": r.get("sec"), "src": "rapid"})
print("total blobs:", len(items))

# ---- find the Random3 header implementation in adj9_full_chain ----
import importlib.util
spec = importlib.util.spec_from_file_location(
    "afc", os.path.join(HERE, "rev", "adj9_full_chain.py"))
afc = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(afc)
    hdr_fn = None
    for name in ("make_header", "header_for_second", "rand3", "Random3",
                 "compute_header", "gen_header"):
        if hasattr(afc, name):
            hdr_fn = getattr(afc, name)
            break
    print("header fn:", hdr_fn)
except Exception as e:
    print("import afc failed:", e)
    hdr_fn = None
    afc = None

if hdr_fn is None and afc is not None:
    # look for anything second->16B-ish
    cands = [n for n in dir(afc) if not n.startswith("_")
             and callable(getattr(afc, n))]
    print("callers in afc:", cands)

def h16(bhex):
    return bytes.fromhex(bhex)[:16]

# ---- test 1: header equality for same second (model-free!) ----
bysec = collections.defaultdict(list)
for it in items:
    if it["sec"] is not None:
        bysec[it["sec"]].append(it)
same = {s: v for s, v in bysec.items() if len(v) > 1}
print(f"seconds with >1 blob: {len(same)}")
hdr_same = hdr_diff = 0
vary_dw = collections.Counter()
for s, lst in list(same.items())[:200]:
    hs = [h16(x["hex"]) for x in lst]
    if all(h == hs[0] for h in hs):
        hdr_same += 1
    else:
        hdr_diff += 1
    # body dwords that differ between pairs
    bodies = [bytes.fromhex(x["hex"])[16:] for x in lst]
    for i in range(len(bodies) - 1):
        a, b = bodies[i], bodies[i + 1]
        for w in range(min(len(a), len(b)) // 4):
            if a[w*4:(w+1)*4] != b[w*4:(w+1)*4]:
                vary_dw[w] += 1
print(f"same-second header: identical={hdr_same} differing={hdr_diff}")
print("body dwords varying across same-second signings (top12):",
      vary_dw.most_common(12))

# ---- test 2: header == Random3(sec) via our law, if callable ----
if hdr_fn is not None:
    ok = bad = skip = 0
    for it in items:
        if it["sec"] is None:
            continue
        try:
            pred = hdr_fn(it["sec"])
            pred = pred if isinstance(pred, (bytes, bytearray)) else bytes.fromhex(pred)
            if bytes(pred) == h16(it["hex"]):
                ok += 1
            else:
                bad += 1
        except Exception:
            skip += 1
    print(f"header==Random3(sec): ok={ok} bad={bad} skip={skip}")

# ---- test 3: pair (canonical, H) tuples by ts and test simple H laws ----
sigs = sorted(d["sign_inputs"], key=lambda x: x["ts"])
hsl = sorted(d["hs"], key=lambda x: x["ts"])
tuples = []
for h in hsl:
    cand = [s for s in sigs if 0 <= h["ts"] - s["ts"] <= 4000]
    if cand:
        tuples.append((cand[-1], h))
print("paired (canonical,H):", len(tuples))
KEY19 = b"Quoh8uafohgh7CahM2h"
laws = {
    "sha256(canon)": lambda c: hashlib.sha256(c.encode()).hexdigest(),
    "hmac19(canon)": lambda c: hmac.new(KEY19, c.encode(), hashlib.sha256).hexdigest(),
    "hmac19(canon|19)": lambda c: hmac.new(KEY19, c.encode() + KEY19, hashlib.sha256).hexdigest(),
}
for name, fn in laws.items():
    hit = sum(1 for s, h in tuples if fn(s["map_toString"]) == h["H"])
    print(f"  H law {name}: {hit}/{len(tuples)}")
json.dump([{"sec": s, "n": len(v)} for s, v in sorted(bysec.items())],
          open(os.path.join(HERE, "rev", "rapid_secs.json"), "w"))