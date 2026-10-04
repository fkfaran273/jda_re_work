#!/usr/bin/env python3
"""pair_hunt.py — decisive offline test of 'H is verifiable from transmitted bytes'.
Uses REAL (msg, H, blob) triples captured by kp.js on the moto:
  hmac events:  inHex = exact d3/HMAC message, outB64 = real H (key2 output)
  nsign events: outB64 = 192-B blob from the same signing
Sweeps every byte-window of the blob as candidate MAC key K:
  H ?= HMAC-SHA256(K, msg) / sha256(K||msg) / sha256(msg||K)
Plus param-derived keys (auid/gps/app_token) and known statics.
"""
import re, base64, hmac, hashlib, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(HERE, "..", "device")
sys.stdout.reconfigure(line_buffering=True)

raw = open(os.path.join(DEV, "adj9_wh4.log"), encoding="utf-8", errors="replace").read()

def grab(pat, s):
    m = re.search(pat, s)
    return m.group(1) if m else None

hmacs, nsigns = [], []
for obj in re.findall(r"\{[^{}]*\}", raw):
    if "'hmac'" in obj or '"hmac"' in obj:
        hx = grab(r"""[\"']inHex[\"']\s*:\s*[\"']([0-9a-fA-F]*)[\"']""", obj)
        b6 = grab(r"""[\"']inB64[\"']\s*:\s*[\"']([A-Za-z0-9+/=]+)[\"']""", obj)
        out = grab(r"""[\"']outB64[\"']\s*:\s*[\"']([A-Za-z0-9+/=]+)[\"']""", obj)
        if out:
            msg = bytes.fromhex(hx) if hx else (base64.b64decode(b6) if b6 else None)
            if msg:
                hmacs.append((msg, base64.b64decode(out)))
    if "'nsign'" in obj or '"nsign"' in obj:
        out = grab(r"""[\"']outB64[\"']\s*:\s*[\"']([A-Za-z0-9+/=]+)[\"']""", obj)
        arg = grab(r"""[\"']argHmacB64[\"']\s*:\s*[\"']([A-Za-z0-9+/=]+)[\"']""", obj)
        if out:
            nsigns.append((base64.b64decode(out), arg))

print(f"hmac events: {len(hmacs)}  nsign events: {len(nsigns)}")
data = []
for i in range(min(len(hmacs), len(nsigns))):
    m, H = hmacs[i]
    b, arg = nsigns[i]
    ok_arg = (arg is not None and base64.b64decode(arg) == H)
    data.append((m, H, b, ok_arg))
for i, (m, H, b, ok) in enumerate(data):
    print(f"  pair{i}: msg={len(m)}B H={H.hex()[:16]}… blob={len(b)}B argH-match={ok}")

if not data:
    sys.exit("no usable pairs")

m0 = data[0][0].decode("utf-8", "replace")
open(os.path.join(HERE, "pair_msg.txt"), "w", encoding="utf-8").write(m0)
print("\n--- first msg (first 500 chars) ---")
print(m0[:500])
print("--- msgs distinct:", len({d[0] for d in data}),
      " blobs distinct:", len({d[2] for d in data}), "---")

# ---- candidate keys ----
statics = [b"Quoh8uafohgh7CahM2h", b"adj9", b"1500000", b"5.0.0",
           bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd"),
           b"fad0f10d60f93c17937b2f1eb6c09691ae7d74bd", b"jut9tib0eeps"]
mm = re.findall(r"(auid|gps_adid|app_token|android_uuid)=([^,]+)", m0)
kv = {k: v for k, v in mm}
print("params found in msg:", list(kv.items())[:6])
vals = list(kv.values())
for a in vals:
    statics.append(a.encode())
    statics.append(hashlib.sha256(a.encode()).digest())
for a, b in [(x, y) for x in vals for y in vals if x != y]:
    statics.append(hashlib.sha256((a + b).encode()).digest())

def macs(k, m):
    yield "hmac", hmac.new(k, m, hashlib.sha256).digest()
    yield "sha(k|m)", hashlib.sha256(k + m).digest()
    yield "sha(m|k)", hashlib.sha256(m + k).digest()

hits = []
for idx, (m, H, b, _) in enumerate(data):
    cands = {}
    for L in (16, 19, 20, 32, 64):
        for off in range(0, len(b) - L + 1):
            cands[(L, off)] = b[off:off + L]
    for k in statics:
        cands[("static", len(k))] = k
    for (L, off), k in cands.items():
        for name, dg in macs(k, m):
            if dg == H:
                hits.append((idx, name, L, off, k.hex() if isinstance(k, bytes) else k))

print("\n=== SWEEP RESULT:", "HIT!" if hits else "no hit")
for h in hits:
    print("   ", h)
if not hits:
    # sanity: is H even reproducible as ANY mac of msg with blob keys? cross-check
    # also verify two pairs with identical msg produce identical H (HMAC determinism)
    seen = {}
    for m, H, b, _ in data:
        seen.setdefault(m, set()).add(H)
    multi = {len(v) for v in seen.values()}
    print("sanity: same-msg->same-H groups:", [len(v) for v in seen.values()])
