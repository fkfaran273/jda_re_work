"""extract_wh4_blobs2.py - pull the 192-B nsign blobs from the ADJ9ORA capture logs.

Log format: ###ADJ9_BEGIN type=<TYPE> utf8len=.. ts=<ts>
text: <fields>
hex: <hex>
###ADJ9_END

Types seen: jca_b64_encodeToString, authorization_header, nsign, nsign_in, ...
We want the records whose hex/text holds the 384-hex (192-byte) blob.
"""
import base64
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")

rec_re = re.compile(
    r"###ADJ9_BEGIN type=(\S+) [^\n]*ts=(\d+)\n(.*?)###ADJ9_END", re.S)
b64_re = re.compile(r'signature="([A-Za-z0-9+/]{256})"')
hex384_re = re.compile(r"hex=(?:[0-9a-f]{0,60}?)([0-9a-f]{384})")

blobs = {}   # hex384 -> [(log, type, ts)...]
sig_headers = {}  # hex384 (from b64 decode) -> [(log, ts)...]

for logname in ("adj9_wh4.log", "adj9_wh2.log", "adj9_wh.log"):
    p = os.path.join(DEV, logname)
    if not os.path.exists(p):
        continue
    with open(p, encoding="utf-8", errors="replace") as f:
        txt = f.read()
    n = 0
    for m in rec_re.finditer(txt):
        typ, ts, body = m.group(1), int(m.group(2)), m.group(3)
        sm = b64_re.search(body)
        if sm:
            try:
                hx = base64.b64decode(sm.group(1)).hex()
            except Exception:
                continue
            sig_headers.setdefault(hx, []).append((logname, ts))
            n += 1
            continue
        if typ in ("nsign", "nsign_out"):
            hm = hex384_re.search(body)
            if hm:
                blobs.setdefault(hm.group(1), []).append((logname, ts))
                n += 1
    print("%s -> %d records" % (logname, n))

print("sig-header blobs: %d, nsign blobs: %d" % (len(sig_headers), len(blobs)))
for hx in sorted(set(sig_headers) | set(blobs))[:10]:
    print("  ", hx[:32], sig_headers.get(hx), blobs.get(hx))

json.dump({"auth": sig_headers, "nsign": blobs},
          open(os.path.join(HERE, "wh_blobs2.json"), "w"), indent=0)
print("saved wh_blobs2.json")
