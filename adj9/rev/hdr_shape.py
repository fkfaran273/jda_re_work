"""hdr_shape.py - shape of the Authorization header per signing.

Confirms: the header carries the 192-byte blob as base64 (nothing else
cryptographic — no H), the envelope fields, and an `adj_verification` token.
Prints whether that token varies per signing (= claims-derived) or is constant.
"""
import base64
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.stdout.reconfigure(line_buffering=True)
raw = open(os.path.join(DEV, "adj9_wh4.log"), "rb").read().decode("utf-8", "replace")
blocks = re.findall(r"###ADJ9_BEGIN type=(\w+)[^\n]*ts=(\d+)\n(.*?)###ADJ9_END", raw, re.S)
auth = [(int(ts), body) for t, ts, body in blocks if t == "authorization_header"]
ns = []
for t, ts, body in blocks:
    if t == "nsign":
        m = re.search(r"hex=([0-9a-f]+)", body)
        if m:
            ns.append((int(ts), m.group(1)))
print("authorization_header=%d  nsign=%d" % (len(auth), len(ns)))

F = {
    "signature": r'signature="([^"]+)"',
    "adj_signing_id": r'adj_signing_id="([^"]+)"',
    "algorithm": r'algorithm="([^"]+)"',
    "headers_id": r'headers_id="([^"]+)"',
    "native_version": r'native_version="([^"]+)"',
    "adj_verification": r'adj_verification="([^"]+)"',
}
tokens = []
for ts, body in auth:
    g = {}
    for k, pat in F.items():
        m = re.search(pat, body)
        g[k] = m.group(1) if m else None
    blob = base64.b64decode(g["signature"] + "==")
    hit = [t for t, h in ns if bytes.fromhex(h)[:8] == blob[:8]]
    tokens.append(g["adj_verification"])
    print("ts=%-14d blob=%s n=%d  signing_id=%s headers_id=%s nver=%s verif=%s  ==nsign:%s" %
          (ts, blob.hex()[:16], len(blob), g["adj_signing_id"], g["headers_id"],
           g["native_version"], g["adj_verification"], bool(hit)))
print()
print("distinct adj_verification values: %d" % len(set(tokens)))
for t in set(tokens):
    print("   %s" % t)
print()
print("len(adj_verification):", [len(t) for t in tokens if t])
print("note: the canonical claim string starts with the same 'KlcA…' text, so this")
print("      token is a claims-derived prefix; it is sent in the header.")