"""commit_hunt.py — brute-force the 3.62.0 claims commitments (c20, c32).

Targets (from the pass-0 heap snapshots; identical across seconds, change
with claims):
  c20 (20 B) @ heap 0x900bb84 + 3 more copies
  c32 (32 B) @ heap 0x900be98 + 3 more copies

    python commit_hunt.py
"""
import hashlib
import hmac
import itertools
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "adj7_work"))

C20 = bytes.fromhex("6cffea5110a9940910e85257b51dc608c577c522")
C32 = bytes.fromhex("095ccb389439543bf3bad2abc05e42aab2994c5a7c2084aeeb899e6d1ee1656b")

DK37 = bytes.fromhex("2a4cc07960d647623cc386dcefafbf25"
                     "b669914d32cc8585a1ed7f920ef591eb")
imm = json.load(open(os.path.join(ROOT, "adj7_work", "adj7s4_immruns.json")))["d20a0"]
KB_BE = b"".join(struct.pack(">I", w) for w in imm)
KB_LE = b"".join(struct.pack("<I", w) for w in imm)
KB_BE_U = bytes(w ^ 0xCC for w in KB_BE)
KB_LE_U = bytes(w ^ 0xCC for w in KB_LE)
SHA0 = hashlib.sha256(b"").digest()

import adj7_signer as sg
bodies = {b["sid"]: b for b in
          json.load(open(os.path.join(ROOT, "adj7_work", "adj7b_bodies.json")))}
params = dict(bodies["0015"]["body_params_dict"])
claims = sg.build_claims("session", params)
print("claims len", len(claims))

def swapN(b, n):
    out = bytearray()
    for i in range(0, len(b) - len(b) % n, n):
        out += b[i:i + n][::-1]
    return bytes(out) + b[len(b) - len(b) % n:]

def swap_le_words(b, w):
    """reverse bytes within each w-byte word (LE view of BE data)."""
    return swapN(b, w)

INPUTS = {}
for w in (2, 4, 8, 16):
    INPUTS[f"swap{w}"] = swap_le_words(claims, w)
INPUTS["raw"] = claims
INPUTS["raw_1300"] = claims + b"1300000"
INPUTS["1300_raw"] = b"1300000" + claims
INPUTS["len4be"] = struct.pack(">I", len(claims)) + claims
INPUTS["len4le"] = struct.pack("<I", len(claims)) + claims
INPUTS["raw_sha0"] = claims + SHA0
INPUTS["sha0_raw"] = SHA0 + claims
# the swapped form as found in the heap (claims reversed 4-byte, from a
# reversed-bytes dump): try byte-reversed whole
INPUTS["rev"] = claims[::-1]

KEYS = {"none": b"", "dk37": DK37, "kb_be": KB_BE, "kb_le": KB_LE,
        "kb_be_u": KB_BE_U, "kb_le_u": KB_LE_U, "sha0": SHA0}

def hashes(data, key):
    out = {}
    out["sha1"] = hashlib.sha1(data).digest()
    out["sha256"] = hashlib.sha256(data).digest()
    out["sha256_20"] = out["sha256"][:20]
    out["sha512_20"] = hashlib.sha512(data).digest()[:20]
    out["md5"] = hashlib.md5(data).digest()
    out["sha1_sha256"] = hashlib.sha1(hashlib.sha256(data).digest()).digest()
    out["sha256_sha1"] = hashlib.sha256(hashlib.sha1(data).digest()).digest()
    if key:
        out["hmac_sha1"] = hmac.new(key, data, hashlib.sha1).digest()
        out["hmac_sha256"] = hmac.new(key, data, hashlib.sha256).digest()
        out["hmac_sha256_20"] = out["hmac_sha256"][:20]
    return out

hits = []
for iname, data in INPUTS.items():
    hs = hashes(data, b"")
    for hname, dig in hs.items():
        if dig[:20] == C20:
            hits.append((iname, hname, "c20"))
        if dig == C32:
            hits.append((iname, hname, "c32"))
    for kname, key in KEYS.items():
        if not key:
            continue
        hs2 = hashes(data, key)
        for hname, dig in hs2.items():
            if dig[:20] == C20:
                hits.append((iname, hname + "/" + kname, "c20"))
            if dig == C32:
                hits.append((iname, hname + "/" + kname, "c32"))
    # double-hash chains
    d1 = hashlib.sha256(data).digest()
    for kname, key in KEYS.items():
        if not key:
            continue
        if hmac.new(key, d1, hashlib.sha256).digest() == C32:
            hits.append((iname, "hmac_sha256(sha256)/" + kname, "c32"))
        if hmac.new(key, d1, hashlib.sha1).digest() == C20:
            hits.append((iname, "hmac_sha1(sha256)/" + kname, "c20"))
    d2 = hashlib.sha1(data).digest()
    if hashlib.sha256(d2).digest() == C32:
        hits.append((iname, "sha256(sha1)", "c32"))

print("hits:", hits if hits else "NONE")

# also: is c20/c32 maybe a hash of the SWAPPED claims as stored in the heap?
# extract the claims-swapped region from snap_A (find "US2026" reversed)
snap = open(os.path.join(HERE, "snap_A.bin"), "rb").read()
needle = swap_le_words(b"US2026", 4)[:6]
print("swapped-US2026 needle:", needle.hex())
idxs = []
i = snap.find(needle)
while i != -1:
    idxs.append(hex(0x9000000 + i))
    i = snap.find(needle, i + 1)
print("claims-swapped copies at:", idxs)
