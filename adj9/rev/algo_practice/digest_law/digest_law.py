"""digest_law.py — SOLVED: closed-form law for the adj9 signature digest.

The final 32 bytes of the 192-byte blob (sink words 40..47) are NOT whitened
and are NOT a plain hash/HMAC of the blob. The VM computes a custom two-pass
SHA-256 MAC with a HARD-CODED 32-byte key K (the 8 dwords are literal
mov/movk immediates in the VM program — constant across devices and runs):

    inner  = sha256( (K^ipad) || ipad || body )    # message = 208 bytes
    digest = sha256( (K^opad) || opad || inner )   # message =  96 bytes

with body = blob[16:160) (the whitened 144-B record), ipad = 0x36363636*8,
opad = 0x5c5c5c5c*8.

NOTE it is not standard HMAC: the raw pad block is hashed a second time after
the keyed block, which is why the standard compositions in hunt_quick.py were
refuted.

Usage:
    python digest_law.py        # validates 7/7 (sample0 run + 6 genuine wins)

predict_digest(body) -> 32 bytes is the drop-in for pure_mint.py.
"""
import base64
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(os.path.dirname(HERE))

K = bytes.fromhex(
    "690f60944dddd9847db55cd7d2d576b3"
    "0451723fbcfa92df62b55f6fec60f2de"
)
IPAD = b"\x36" * 32
OPAD = b"\x5c" * 32
K_IPAD = bytes(a ^ b for a, b in zip(K, IPAD))
K_OPAD = bytes(a ^ b for a, b in zip(K, OPAD))


def predict_digest(body):
    """body = whitened record, blob[16:160), 144 bytes -> digest, 32 bytes."""
    inner = hashlib.sha256(K_IPAD + IPAD + body).digest()
    return hashlib.sha256(K_OPAD + OPAD + inner).digest()


def parse_win_blobs():
    """The 6 genuine winning blobs from the un-instrumented capture."""
    log = open(os.path.join(REV, "win_capture", "module_win_capture.log"),
               encoding="utf-8", errors="replace").read()
    seen, out = set(), []
    for m in re.finditer(r'Signature signature="([A-Za-z0-9+/=]{256})"', log):
        b = base64.b64decode(m.group(1))
        if b[:16] not in seen:
            seen.add(b[:16])
            out.append(b)
    return out


def main():
    ok = total = 0
    print("== sample0 controlled VM run (streams_sample0.json) ==")
    s0 = json.load(open(os.path.join(HERE, "..", "streams_sample0.json")))
    blob = bytes.fromhex(s0["blob_hex"])
    hit = predict_digest(blob[16:160]) == blob[160:192]
    ok += hit
    total += 1
    print("sample0: %s" % ("EXACT" if hit else "MISS"))
    print("== 6 genuine winning blobs ==")
    for i, blob in enumerate(parse_win_blobs()):
        hit = predict_digest(blob[16:160]) == blob[160:192]
        ok += hit
        total += 1
        print("win%d: %s" % (i, "EXACT" if hit else "MISS"))
    print("\nRESULT: %d/%d digests predicted byte-exact" % (ok, total))
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
