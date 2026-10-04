"""forward_known.py — PHASE 1: prove the forward pipeline in pure Python.

For each genuine winning blob:
  1. decode the record (whiten_body_inverse) — ground truth
  2. rebuild the record from KNOWN parts only (magic, head, S, cert=D9,
     block=ground-truth placeholder, SHA256(""), tags, padding)
  3. whiten_forward with the blob's own header
  4. compare with the genuine body

If all 6 match byte-exact, the ONLY VM-only outputs are:
  - record[46:78)  block  (9 dwords of the VM's main stream)
  - blob[160:192)  digest (8 words)
i.e. 17 dwords out of 48 — everything else is closed-form already.
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.dirname(HERE)
sys.path.insert(0, REV)
from whiten_decoder import whiten_body_inverse, whiten_forward  # noqa: E402

CERT = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")  # D9
SHA0 = hashlib.sha256(b"").digest()


def parse_win_blobs():
    """The 6 genuine winning blobs from the un-instrumented capture."""
    log = open(os.path.join(REV, "win_capture", "module_win_capture.log"),
               encoding="utf-8", errors="replace").read()
    blobs = []
    for m in re.finditer(r'Signature signature="([A-Za-z0-9+/=]{256})"', log):
        blobs.append(__import__("base64").b64decode(m.group(1)))
    # dedupe, keep order
    seen, out = set(), []
    for b in blobs:
        if b[:16] not in seen:
            seen.add(b[:16])
            out.append(b)
    return out


def rebuild_record(rec):
    """Rebuild the 144-B record from KNOWN parts (block kept from rec)."""
    out = bytearray(144)
    out[0:3] = b"\x01\x00\x08"
    out[3:19] = rec[3:19]                 # d0 head (region law separately)
    out[19] = 0x02
    out[20:24] = rec[20:24]               # S (d2 LE)
    out[24] = 0x03
    out[25:45] = CERT                     # cert SHA-1 = D9 (constant!)
    out[45] = 0x04
    out[46:78] = rec[46:78]               # BLOCK — ground-truth placeholder
    out[78] = 0x05
    out[79:111] = SHA0                    # SHA256("")
    out[111:114] = b"\x06\x01\x07"
    out[114:128] = b"\x00" * 14
    out[128:130] = b"\x00\x00"
    out[130:144] = b"\x0e" * 14
    return bytes(out)


def main():
    blobs = parse_win_blobs()
    print("win blobs parsed: %d" % len(blobs))
    ok = 0
    for i, blob in enumerate(blobs):
        header, body, digest = blob[:16], blob[16:160], blob[160:192]
        rec = whiten_body_inverse(body, header)
        rec2 = rebuild_record(rec)
        rebuilt_body = whiten_forward(rec2, header)
        match = rebuilt_body == body
        # also: is the record fully described by our known structure?
        rec_known = rebuild_record(bytearray(144))  # without block
        unknown_positions = [j for j in range(144)
                             if rec[j] != rec_known[j]
                             and not (46 <= j < 78)
                             and not (3 <= j < 19) and not (20 <= j < 24)]
        print("win%d: body match=%s  structurally-unexpected bytes=%s"
              % (i, match, unknown_positions or "NONE"))
        ok += match
    print("\nPHASE 1: %d/%d forward-exact" % (ok, len(blobs)))
    print("=> remaining VM-only: block record[46:78) (9 dwords) + "
          "digest blob[160:192) (8 dwords)" if ok == len(blobs) else
          "=> FORWARD MODEL INCOMPLETE — inspect diffs")
    return 0 if ok == len(blobs) else 1


if __name__ == "__main__":
    sys.exit(main())
