#!/usr/bin/env python3
"""msg_test2.py — test H's message = Java LinkedHashMap.toString() of the signing map.
u2.a(): map = params(d) with activity_kind+client_sdk overwritten from e, then
msg = d3.a(map.toString()) = UTF-8 bytes; H = HMAC(key2, msg).  The capture logged
'in' = the 32B msg digest (sha256?) at t1.a time and 'fields' = the map contents.
Candidates: Java map toString over captured order, with/without client_sdk,
with/without adj_verification, null as 'null', several e-value guesses."""
import json, hashlib, os, sys, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
D = json.load(open(os.path.join(HERE, "..", "device", "triples_fresh.json")))
sys.stdout.reconfigure(line_buffering=True)

def jstr(m):  # java AbstractMap.toString()
    return "{" + ", ".join(f"{k}={v}" for k, v in m.items()) + "}"

def sha(b): return hashlib.sha256(b).hexdigest()

trip = [(D[i][2], D[i + 2][2]) for i in range(0, len(D), 3)]
SDKS = ["android5.7.0", "android 5.7.0"]
hits_total = 0
for ins, f in trip:
    kind = f.get("activity_kind", "?")
    print(f"== {kind}  target in={ins[:20]}…")
    base = [(k, v) for k, v in f.items()]
    cands = {}
    # 1..3: plain java toString of captured map
    cands["java_cap"] = dict(base)
    # 4..9: + client_sdk (append or before activity_kind), various values
    for si, sdk in enumerate(SDKS):
        m = dict(base); m["client_sdk"] = sdk
        cands[f"java_ck_end{si}"] = m
        m2 = {"client_sdk": sdk}; m2.update(base)
        cands[f"java_ck_beg{si}"] = m2
        m3 = dict(base); m3["client_sdk"] = sdk
        m3["activity_kind"] = kind
        cands[f"java_ck_ak{si}"] = m3
    # null rendering variants
    m = dict(base)
    m2 = {k: ("null" if v is None else v) for k, v in m.items()}
    cands["java_null"] = m2
    m3 = {k: ("" if v is None else v) for k, v in m.items()}
    cands["java_empty"] = m3
    for name, m in cands.items():
        s = jstr(m)
        h = sha(s.encode("utf-8", "replace"))
        mark = "   <<< MATCH" if h == ins else ""
        if mark: hits_total += 1
        print(f"   {name:14s} {h[:20]}…{mark}")
    if not any(h == ins for h in [sha(jstr(m).encode('utf-8','replace')) for m in cands.values()]):
        print("   -> no match; first cand string:", jstr(cands["java_cap"])[:160])
print("HITS:", hits_total)