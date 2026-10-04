#!/usr/bin/env python3
"""msg_test.py — verify H's HMAC message = SHA-256(canonical params).
triples_fresh.json holds 3 real signings as (in, blob, fields) triples where
'in' is the 32-B digest the device logged at signing time (t0=1789207385185).
If any canonicalization of the captured fields hashes to 'in', the HMAC msg
model is confirmed -> server can verify from wire params alone (it holds key2)."""
import json, hashlib, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
D = json.load(open(os.path.join(HERE, "..", "device", "triples_fresh.json")))
sys.stdout.reconfigure(line_buffering=True)

def canon(f):
    out = {}
    out["json_sortkeys"] = json.dumps(f, sort_keys=True, separators=(",", ":"))
    out["json_default"] = json.dumps(f)
    out["qs_sorted"] = "&".join(f"{k}={f[k]}" for k in sorted(f))
    out["qs_wire"] = "&".join(f"{k}={f[k]}" for k in f)
    out["vals_sorted"] = "".join(str(f[k]) for k in sorted(f))
    out["keys_vals_sorted"] = "".join(f"{k}{f[k]}" for k in sorted(f))
    return out

trip = [(D[i], D[i + 2]) for i in range(0, len(D), 3)]  # (in, fields)
for rin, rfields in trip:
    ins = rin[2]
    f = rfields[2]
    kind = f.get("activity_kind", "?")
    print(f"== {kind}  in={ins[:24]}…  nparams={len(f)}")
    cands = canon(f)
    hit = None
    for name, s in cands.items():
        h = hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
        mark = "  <<< MATCH" if h == ins else ""
        print(f"   {name:18s} {h[:24]}…{mark}")
        if h == ins:
            hit = name
    if not hit:
        # try created_at value normalizations and urlencoding variants
        import urllib.parse
        f2 = dict(f)
        for k, v in list(f2.items()):
            if isinstance(v, str) and ("T" in v and "Z" in v):
                f2[k] = urllib.parse.quote(v)
        for name, s in canon(f2).items():
            h = hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()
            if h == ins:
                print(f"   MATCH after quote-stamps: {name}")
                hit = name
    print("   ->", hit or "no canonicalization matched (need d3.a semantics)")
