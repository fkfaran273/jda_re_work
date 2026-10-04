#!/usr/bin/env python3
"""hkey3.py — final disambiguation.
F1: sha256(canonical)==triples 'in'?  (is the HMAC message rule computable?)
F2: #0 tile / #8 / #2 across the 8 wh4 blobs (per-install vs per-call words)
F3: brute #8/#2 vs canonical+static keys."""
import json, hashlib, hmac, base64, os, sys, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(HERE, "..", "device")
sys.stdout.reconfigure(line_buffering=True)
XOR19 = b"Quoh8uafohgh7CahM2h"
ADJV = base64.b64encode(bytes(c ^ XOR19[i % 19] for i, c in enumerate(b'{"os_name":"android"}'))).decode()

T = json.load(open(os.path.join(DEV, "triples_fresh.json")))
E = json.load(open(os.path.join(DEV, "events.json")))
W = [bytes.fromhex(e[2]) for e in json.load(open(os.path.join(DEV, "wh4_nsign.json")))]

# --- canonical candidates
cands = []
def harvest(o):
    if isinstance(o, dict):
        if "canonical" in o and isinstance(o["canonical"], str) and len(o["canonical"]) > 50:
            cands.append(("canonical", o["canonical"]))
        if o.get("type") == "canonical" and isinstance(o.get("value"), str):
            cands.append(("evt.canonical", o["value"]))
        for v in o.values(): harvest(v)
    elif isinstance(o, list):
        for v in o: harvest(v)
harvest(E)
print(f"canonical candidates: {len(cands)}")

# --- F1: sha256(canonical) == triples in ?
def dw(B, a, b): return B[16 + 4*a:16 + 4*b]
hits_f1 = False
for i in range(0, len(T), 3):
    ins = bytes.fromhex(T[i][2]); blob = bytes.fromhex(T[i+1][2])
    for nm, c in cands:
        for enc in ("utf-8", "utf-16-le"):
            h = hashlib.sha256(c.encode(enc)).digest()
            if h == ins:
                print(f"F1 MATCH: {nm} enc={enc} kind={dict(T[i+2][2]).get('activity_kind')}"); hits_f1 = True
            if h[:16] == dw(blob[16:], 41, 45):
                print(f"F1b #8==sha256(c)[:16] {nm} {enc}")
print("F1:", "MATCH" if hits_f1 else "no match")

# --- F2: which body words are per-install stable across 8 blobs?
import collections
nb = len(W)
stable, varying = [], []
for wi in range(44):
    vals = collections.Counter(b[16+4*wi:20+4*wi] for b in W)
    (stable if len(vals) == 1 else varying).append(wi)
print(f"stable words ({len(stable)}):", stable)
print(f"varying words ({len(varying)}):", varying)

# --- F3: brute #8-like varying slots vs canonical
sess_i = next(i for i in range(0, len(T), 3) if dict(T[i+2][2]).get("activity_kind") == "session")
sblob = bytes.fromhex(T[sess_i+1][2])
sfields = dict(T[sess_i+2][2])
def u2msg(f):
    m = {k: ("null" if v is None else str(v)) for k, v in f.items()
         if k not in ("client_sdk", "adj_verification")}
    m["client_sdk"] = "android5.7.0"; m["adj_verification"] = ADJV
    return "{" + ", ".join(f"{k}={v}" for k, v in m.items()) + "}"
msg = u2msg(sfields)
keys = {"XOR19": XOR19, "adjv": ADJV.encode(), "sha1cert": bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"),
        "empty": b"", "adj9": b"adj9"}
H16 = dw(sblob[16:], 41, 45)
found = []
for (kn, K), (hn, hf) in itertools.product(keys.items(),
        {"sha256": lambda k, m: hashlib.sha256(k+m).digest(),
         "hmac": lambda k, m: hmac.new(k, m, hashlib.sha256).digest()}.items()):
    d = hf(K, msg.encode("utf-8", "replace"))
    if d[:16] == H16 or d[-16:] == H16:
        found.append(("slot41", kn, hn))
print("F3:", found if found else "no static-key relation for the 41..45 window")
