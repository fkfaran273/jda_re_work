# saz_recon.py - what exactly is in the genuine /session captures?
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "saz_sessions.json"), encoding="utf-8"))
print("units: %d" % len(d))
u = d[0]
print("KEYS: %s" % sorted(u.keys()))
for k, v in u.items():
    s = v if isinstance(v, str) else json.dumps(v)
    print("-- %-14s : %s" % (k, s[:400]))
print()
for i, x in enumerate(d):
    print("[%d] status=%s sig_len=%s keys=%d" % (i, x.get("status"),
                                                 x.get("sig_len"),
                                                 len(x.get("params") or x.get("form") or {})))