#!/usr/bin/env python3
"""msg_test3.py — THE decisive test of the HMAC message rule.
u2.a: msg = java toString of (params d + client_sdk + adj_verification appended)
adj_verification = b64(xor19(json{"os_name":"android"}))  — PROVEN by round-trip.
triples_fresh 'in' (32B) is expected to be sha256(msg) logged by the t1 hook."""
import json, hashlib, os, sys, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.stdout.reconfigure(line_buffering=True)
KEY19 = b"Quoh8uafohgh7CahM2h"
ADJV = base64.b64encode(bytes(c ^ KEY19[i % 19] for i, c in
             enumerate(b'{"os_name":"android"}'))).decode()
print("adj_verification =", ADJV)
D = json.load(open(os.path.join(HERE, "..", "device", "triples_fresh.json")))

def jstr(m): return "{" + ", ".join(f"{k}={v}" for k, v in m.items()) + "}"
def sha(s): return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()

hits = 0
for i in range(0, len(D), 3):
    ins = D[i][2]; f = dict(D[i + 2][2])
    kind = f.get("activity_kind", "?")
    # null rendering as Java would
    fJ = {k: ("null" if v is None else v) for k, v in f.items()}
    cands = {}
    m = dict(fJ); m["client_sdk"] = "android5.7.0"; m["adj_verification"] = ADJV
    cands["ck_then_adjv"] = m
    m2 = dict(fJ); m2["adj_verification"] = ADJV; m2["client_sdk"] = "android5.7.0"
    cands["adjv_then_ck"] = m2
    m3 = dict(fJ); m3["adj_verification"] = ADJV
    cands["adjv_only"] = m3
    m4 = dict(fJ); m4["client_sdk"] = "android5.7.0"
    cands["ck_only"] = m4
    # sdk string with space, just in case
    m5 = dict(fJ); m5["client_sdk"] = "android 5.7.0"; m5["adj_verification"] = ADJV
    cands["ckspace_adjv"] = m5
    print(f"== {kind}  target in={ins[:20]}…")
    got = None
    for name, m in cands.items():
        s = jstr(m); h = sha(s)
        mark = "   <<< MATCH" if h == ins else ""
        if mark: got = name; hits += 1
        print(f"   {name:14s} {h[:20]}…{mark}")
    if not got:
        print("   sample:", jstr(cands["ck_then_adjv"])[:170])
print("HITS:", hits, "/ 3")