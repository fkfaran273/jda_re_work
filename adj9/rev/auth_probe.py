"""auth_probe.py - what exactly does the app SEND?

If the Authorization header carries H (= the keystore MAC, arg3 of nsign_in), the
server has a keyed MAC it can verify (key2 registered per app) and the descriptor
region would be irrelevant; if the header carries only the 192-byte blob, the region
is the only body the server sees.

Method: from adj9_wh4.log, align per signing -- nsign_in (arg3 = H), nsign (blob),
authorization_header (content) -- by timestamp, then inspect the header for H and for
the blob, and dump its shape.
"""
import base64
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
sys.stdout.reconfigure(line_buffering=True)
LOG = os.path.join(DEV, "adj9_wh4.log")

raw = open(LOG, "rb").read().decode("utf-8", "replace")
blocks = re.findall(r"###ADJ9_BEGIN type=(\w+)[^\n]*ts=(\d+)\n(.*?)###ADJ9_END", raw, re.S)
print("blocks: %d" % len(blocks))
print("types: %s" % dict(Counter(t for t, _, _ in blocks)))

recs = []
for t, ts, body in blocks:
    recs.append((int(ts), t, body))


def field(body, name):
    m = re.search(r"(?:^|\n)%s=([^\n]*)" % re.escape(name), body)
    return m.group(1).strip() if m else None


ins = [(ts, field(b, "arg3_hex")) for ts, t, b in recs if t == "nsign_in"]
ins = [(ts, h) for ts, h in ins if h]
nsi = [(ts, field(b, "hex")) for ts, t, b in recs if t == "nsign"]
nsi = [(ts, hx) for ts, hx in nsi if hx]
auth = [(ts, b) for ts, t, b in recs if t in ("authorization_header",)]
print("nsign_in=%d nsign=%d authorization_header=%d" % (len(ins), len(nsi), len(auth)))

if auth:
    print()
    print("=== first authorization_header (raw, first 1200 chars) ===")
    print(auth[0][1].strip()[:1200])

print()
print("=== per signing: does the header carry H? carry the blob? ===")
for ts, hx in nsi[:8]:
    blob = bytes.fromhex(hx)
    H = None
    prev = [p for p in ins if p[0] <= ts]
    if prev:
        H = max(prev, key=lambda p: p[0])[1]
    # nearest authorization_header (within 3 s)
    near = [a for a in auth if abs(a[0] - ts) <= 3000]
    found_h = found_blob = found_b64h = None
    for ats, body in near:
        hb = H.lower() if H else None
        if hb:
            found_h = (hb in body.lower())
            try:
                found_b64h = (base64.b64encode(bytes.fromhex(hb)).decode() in body)
            except Exception:
                pass
        found_blob = (blob.hex() in body.lower()) or \
                     (base64.b64encode(blob).decode() in body)
    print("ts=%d blob=%s H=%s | header near=%d  H-as-hex=%s H-as-b64=%s blob-in-header=%s" %
          (ts, blob[:8].hex(), (H[:16] + "..") if H else None, len(near),
           found_h, found_b64h, found_blob))
    # structural: which keys appear in the headers at all
print()
print("=== header key names seen across all authorization_header blocks ===")
keys = Counter()
for _, body in auth:
    for m in re.finditer(r"(?:^|\n)([A-Za-z_][A-Za-z0-9_\-]{2,40})[=: ]", body):
        keys[m.group(1)] += 1
print(dict(keys.most_common(25)))