#!/usr/bin/env python3
"""decode_adjv.py — XOR-decode captured adj_verification values with the static key,
then rebuild them and confirm round-trip."""
import json, base64, re, sys
KEY = b"Quoh8uafohgh7CahM2h"  # s2.a from classes3.dex
HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.stdout.reconfigure(line_buffering=True)

def x(b):
    return bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate(b))

# 1. harvest candidate b64 values from our captured artifacts
blob = ""
for f in ("genuine_attr_reqs.json", "adj9_material.json", "corpus.json",
          "fresh_genuine.json", "genuine_attr_raw_query.txt"):
    try:
        blob += open(f"{HERE}\\{f}", encoding="utf-8", errors="replace").read()
    except OSError:
        pass
cands = sorted(set(re.findall(r"adj_verification[\"'=:\s]+([A-Za-z0-9+/=]{16,})", blob)))
print(f"candidates: {len(cands)}")
for c in cands[:4]:
    try:
        raw = base64.b64decode(c)
        dec = x(raw)
        print(f"  b64[{len(c)}] -> {dec[:120]!r}")
    except Exception as e:
        print("  err", e)

# 2. rebuild from scratch per o3.a: JSON then XOR then b64(NO_WRAP)
import io
inner = {"os_name": "android"}
s = json.dumps(inner, separators=(",", ":"))
enc = x(s.encode())
b64 = base64.b64encode(enc).decode()
print("rebuilt:", b64)
