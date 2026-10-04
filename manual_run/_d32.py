"""_d32.py — how much of the signature is actually still unknown?

The record is 144 B.  Every field is computable EXCEPT block32, and the
whitening is solved and verified.  So if block32 were the LAST unknown, the
whole signature could be built in Python with no VM at all.

The other unknown is the 32-byte trailer: blob[160:192].
This checks whether that trailer is derivable from things we can compute.
"""
import hashlib
import re
import sys

sys.path.insert(0, ".")
import adj9_signature as SG

CAPS = [
    "../adj9/rev/creditsea/adj9_cap_declic.log",
    "../adj9/rev/creditsea/adj9_cap_fresh.log",
    "../adj9/rev/creditsea/adj9_cap_live_tarsan.log",
    "../adj9/rev/creditsea/adj9_cap_scopefix.log",
]

for cap in CAPS:
    try:
        text = open(cap, "rb").read().decode("utf-8", "replace")
    except OSError:
        continue
    hexes = re.findall(r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", text)
    if not hexes:
        continue
    h = hexes[0]
    blob = bytes.fromhex(h)
    header, body, trailer = blob[:16], blob[16:160], blob[160:192]
    dec = SG.decode_blob(blob)
    rec = dec["record"]
    cands = {
        "sha256(body)": hashlib.sha256(body).digest(),
        "sha256(record)": hashlib.sha256(rec).digest(),
        "sha256(header+body)": hashlib.sha256(blob[:160]).digest(),
        "sha256(rec[:78])": hashlib.sha256(rec[:78]).digest(),
        "block32": rec[46:78],
        "sha256(block32)": hashlib.sha256(rec[46:78]).digest(),
    }
    print("=== %s ===" % cap.split("/")[-1])
    print("  trailer: %s" % trailer.hex())
    hits = [k for k, v in cands.items() if v == trailer]
    print("  derivable from: %s" % (hits if hits else "NOT from any simple input"))
    # does the trailer change when only the seed changes? gather same-map pairs
    break

# now: across many blobs, is the trailer a function of the record alone?
print("\n=== cross-check: trailer vs record across all blobs ===")
pairs = []
for cap in CAPS:
    try:
        text = open(cap, "rb").read().decode("utf-8", "replace")
    except OSError:
        continue
    for h in dict.fromkeys(re.findall(
            r"out_len=192\s*\r?\nout_hex='?([0-9a-fA-F]{384})", text)):
        blob = bytes.fromhex(h)
        dec = SG.decode_blob(blob)
        pairs.append((blob[160:192], dec["record"], blob[:16]))
print("blobs examined: %d" % len(pairs))
for i, (tr, rec, hd) in enumerate(pairs[:6]):
    print("  blob%d trailer=%s" % (i, tr.hex()[:32]))
if len(pairs) >= 2:
    same_rec = pairs[0][1] == pairs[1][1]
    same_tr = pairs[0][0] == pairs[1][0]
    print("  first two: same record=%s  same trailer=%s" % (same_rec, same_tr))
    if same_rec and not same_tr:
        print("  -> trailer is NOT a pure function of the record")
    if not same_rec:
        print("  -> records differ, so no conclusion from this pair")
