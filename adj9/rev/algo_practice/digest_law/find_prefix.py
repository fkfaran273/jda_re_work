"""find_prefix.py — identify the unknown prefix groups (HASH_IN, hashA) by
testing every 8-word group observed in the trace as sha256(G||pad||Y)."""
import hashlib
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "..", "streams_sample0.json")))
tr = d["full_emit_trace"]
blob = bytes.fromhex(d["blob_hex"])
body = blob[16:160]
digest = blob[160:192]
MAIN = 0x5450001000

HASH_IN = bytes.fromhex("5f3956a27bebefb24b836ae1e4e34085326744098acca4e954836959da56c4e8")
hashA = bytes.fromhex("35533cc8118185d821e9008b8e892aef580d2e63e0a6ce833ee90333b03cae82")
hashB = bytes.fromhex("04333c9dcc2d100cc697012e2eec3aad390818c2461d2a472210bc8437d3cb68")
KPAD_IN = bytes.fromhex("690f60944dddd9847db55cd7d2d576b30451723fbcfa92df62b55f6fec60f2de")

ZEROS = bytes(32)
IPAD = b"\x36" * 32
OPAD = b"\x5c" * 32

# collect all 8-word aligned groups ever on MAIN (snapshot at every event)
snap = {}
groups = {}   # 32-B bytes -> first trace idx
for i, (sva, n, v) in enumerate(tr):
    if sva != MAIN:
        continue
    snap[n] = v & 0xFFFFFFFF
    # check aligned groups ending at n
    for base in (n - 7, n):
        if base < 0 or base % 8:
            continue
        if all((base + k) in snap for k in range(8)):
            g = b"".join(struct.pack(">I", snap[base + k]) for k in range(8))
            if g not in groups:
                groups[g] = i
print("distinct 8-word groups on MAIN:", len(groups))

targets = {
    "HASH_IN": HASH_IN, "hashA": hashA, "hashB": hashB,
    "digest": digest, "KPAD_IN": KPAD_IN,
}
pads = {"zeros": ZEROS, "ipad": IPAD, "opad": OPAD}
tails = {"body": body, "hashB": hashB, "none": b""}

hits = 0
for g, gi in groups.items():
    for pn, p in pads.items():
        for tn, t in tails.items():
            h = hashlib.sha256(g + p + t).digest()
            for tgn, tg in targets.items():
                if h == tg:
                    print("HIT: sha256(G@%d || %s || %s) == %s" % (gi, pn, tn, tgn))
                    print("     G =", g.hex())
                    hits += 1
print("hits:", hits)

# also: maybe HASH_IN/hashA are the sha256 of single groups
print("\n== sha256(G) / sha256(G||pad) checks ==")
for g, gi in groups.items():
    for name, h in [("sha256(G)", hashlib.sha256(g).digest()),
                    ("sha256(G||zeros)", hashlib.sha256(g + ZEROS).digest())]:
        for tgn, tg in targets.items():
            if h == tg:
                print("HIT: %s == %s (G@%d = %s)" % (name, tgn, gi, g.hex()))
