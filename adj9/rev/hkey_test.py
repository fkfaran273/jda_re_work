#!/usr/bin/env python3
"""hkey_test.py — test whether H is a self-contained HMAC whose key is IN the blob (#8).
If H == HMAC-SHA256(K, msg) for K derived from #8 (or any blob slot), the server can
verify packages WITHOUT knowing key2 — and we can forge consistent packages offline."""
import json, hmac, hashlib, base64, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(HERE, "..", "device")
sys.stdout.reconfigure(line_buffering=True)

# --- 1. load (msg, H) hmac events from adj9_wh4.log
pairs = []
txt = open(os.path.join(DEV, "adj9_wh4.log"), encoding="utf-8", errors="replace").read()
for m in re.finditer(r"\{[^{}]*\"type\"\s*:\s*\"hmac\"[^{}]*\}", txt):
    try:
        e = json.loads(m.group(0))
        msg = base64.b64decode(e.get("inB64") or "")
        H = base64.b64decode(e.get("outB64") or "")
        if msg and len(H) == 32:
            pairs.append((msg, H))
    except Exception:
        pass
print(f"hmac pairs: {len(pairs)}")

# --- 2. load nSign blobs (same install) and extract #8 (body dwords 41..44)
blobs = []
try:
    W = json.load(open(os.path.join(DEV, "wh4_nsign.json")))
    items = W if isinstance(W, list) else W.get("nsign", W.get("events", []))
    for e in items:
        b = e.get("outB64") or e.get("blob")
        if b:
            blobs.append(base64.b64decode(b))
except Exception as ex:
    print("wh4 load:", ex)
print(f"blobs: {len(blobs)}")

def slots(body):
    dw = [int.from_bytes(body[i*4+16:(i+1)*4+16], "big") for i in range(len(body)//4)]
    return {
        "0":  b"".join(dw[i].to_bytes(4, "big") for i in range(0, 36)),
        "9":  b"".join(dw[i].to_bytes(4, "big") for i in range(36, 41)),
        "8":  b"".join(dw[i].to_bytes(4, "big") for i in range(41, 45)),
        "4H": b"".join(dw[i].to_bytes(4, "big") for i in range(45, 53)),
        "2":  dw[53].to_bytes(4, "big"),
        "7":  dw[54].to_bytes(4, "big"),
    }

def keyfams(s):
    k8 = s["8"]
    out = {"#8raw": k8, "#8hex": k8.hex().encode(), "#8rev": k8[::-1],
           "sha(#8)": hashlib.sha256(k8).digest(),
           "md5(#8)": hashlib.md5(k8).digest(),
           "#8^XOR19": bytes(c ^ b"Quoh8uafohgh7CahM2h"[i % 19] for i, c in enumerate(k8))}
    return out

hits = []
for bi, blob in enumerate(blobs):
    s = slots(blob)
    for mi, (msg, H) in enumerate(pairs):
        if s["4H"] == H:
            tag = f"blob{bi}~pair{mi}"
            for kn, K in keyfams(s).items():
                for hn, hf in (("hmac", hmac.new), ("hmac-b", lambda k, m, d: hmac.new(m, k, d))):
                    try:
                        d = hf(K, msg, hashlib.sha256).digest() if hn == "hmac" else hf(K, msg, hashlib.sha256).digest()
                    except Exception:
                        continue
                    if d == H:
                        hits.append((tag, kn, hn))
            print(f"{tag}: H-in-blob==hook-H, keyfams tested")
if hits:
    print("JACKPOT:", hits)
else:
    print("no simple #8-key relation (will extend family)")
