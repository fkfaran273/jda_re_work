#!/usr/bin/env python3
"""hkey2.py — the self-contained-check battery.
Server can't know key2 (proven: format=null, never transmitted, no writer).
So any per-package verification it does MUST be self-contained or static-secret.
Candidates: #8 (16B) and #2 (4B) as HMAC/hash(static_key, canonical_msg) truncations."""
import json, hmac, hashlib, base64, os, sys, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(HERE, "..", "device")
sys.stdout.reconfigure(line_buffering=True)
XOR19 = b"Quoh8uafohgh7CahM2h"
ADJV = base64.b64encode(bytes(c ^ XOR19[i % 19] for i, c in enumerate(b'{"os_name":"android"}'))).decode()

T = json.load(open(os.path.join(DEV, "triples_fresh.json")))
W = json.load(open(os.path.join(DEV, "wh4_nsign.json")))
blobs8 = [bytes.fromhex(e[2]) for e in W]

def body(blob): return blob[16:]
def dw(blob, a, b=None):
    B = body(blob)
    b = b if b is not None else a + 1
    return B[a*4:b*4]
def slot8(blob): return dw(blob, 41, 45)
def slot4(blob): return dw(blob, 45, 53)
def slot2(blob): return dw(blob, 53, 54)

print(f"triples={len(T)//3}  wh4blobs={len(blobs8)}")
# 1. is triples 'in' == slot4 (H)?
for i in range(0, len(T), 3):
    ins, blob, fields = bytes.fromhex(T[i][2]), bytes.fromhex(T[i+1][2]), dict(T[i+2][2])
    print(f"  {fields.get('activity_kind','?'):8s} in==slot4? {ins == slot4(blob)}  #8={slot8(blob).hex()}  #2={slot2(blob).hex()}")
    kind = fields.get("activity_kind")
    if kind == "session":
        s_blob, s_fields, s_in = blob, fields, ins

# 2. #8 variance across 8 blobs
s8 = [slot8(b).hex() for b in blobs8]
s2 = [slot2(b).hex() for b in blobs8]
print("#8 set:", sorted(set(s8)), " #2 set:", sorted(set(s2)))

# 3. brute #8 = trunc16( HMAC/Hash( key, msg ) ) over candidate msgs/keys
def canon_u2(f):
    m = {k: ("null" if v is None else str(v)) for k, v in f.items()
         if k not in ("client_sdk", "adj_verification")}
    m["client_sdk"] = "android5.7.0"; m["adj_verification"] = ADJV
    return "{" + ", ".join(f"{k}={v}" for k, v in m.items()) + "}"
def canon_maporder(f):
    m = {k: ("null" if v is None else str(v)) for k, v in f.items()
         if k not in ("client_sdk", "adj_verification")}
    m["client_sdk"] = "android5.7.0"; m["adj_verification"] = ADJV
    return "\x01".join(f"{k}\x02{v}" for k, v in m.items())
msgs = {"u2": canon_u2(s_fields), "maporder": canon_maporder(s_fields),
        "u2_noADJ": canon_u2({k: v for k, v in s_fields.items()})}
keys = {"XOR19": XOR19, "empty": b"", "adjv": ADJV.encode(), "key2": b"key2",
        "adj9": b"adj9", "1500000": b"1500000"}
found = []
t8 = slot8(s_blob)
hfs = {"sha256": lambda k, m: hashlib.sha256(k + m).digest(),
       "hmac": lambda k, m: hmac.new(k, m, hashlib.sha256).digest(),
       "hmacX": lambda k, m: hmac.new(m, k, hashlib.sha256).digest()}
for (mn, msg), (kn, K), (hn, hf) in itertools.product(msgs.items(), keys.items(), hfs.items()):
    d = hf(K, msg.encode("utf-8", "replace"))
    if d[:16] == t8 or d[-16:] == t8 or hashlib.sha256(d).digest()[:16] == t8:
        found.append((mn, kn, hn))
    d2 = d[:4]
    if d2 == slot2(s_blob):
        found.append(("#2", mn, kn, hn))
print("brute hits:", found if found else "none")
