"""test_groups.py — test hash relationships between the 8-word groups seen in
the trace of streams_sample0.json.

Groups (big-endian 32-bit words, as staged on MAIN 0x5450001000):
  KPAD_IN  = words 0..7  of message 1 (pass A)
  ZEROS    = words 8..15 of message 1
  body     = words 16..51 (whitened record, 144 B)
  HASH_IN  = words 0..7  of message 2 (pass B)
  ipad     = words 8..15 of message 2 (0x36363636 x8)
  hashA    = words 0..7  of message 3
  opad     = words 8..15 of message 3 (0x5c5c5c5c x8)
  hashB    = words 16..23 of message 3
  digest   = final blob[160:192)
"""
import hashlib
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "..", "streams_sample0.json")))
blob = bytes.fromhex(d["blob_hex"])
body = blob[16:160]
digest = blob[160:192]

KPAD_IN = bytes.fromhex("690f60944dddd9847db55cd7d2d576b3045172" "3fbcfa92df62b55f6fec60f2de")
HASH_IN = bytes.fromhex("5f3956a27bebefb24b836ae1e4e3408532674409" "8acca4e954836959da56c4e8")
hashA = bytes.fromhex("35533cc8118185d821e9008b8e892aef580d2e63" "e0a6ce833ee90333b03cae82")
hashB = bytes.fromhex("04333c9dcc2d100cc697012e2eec3aad390818c2" "461d2a472210bc8437d3cb68")
ZEROS = bytes(32)
IPAD = b"\x36" * 32
OPAD = b"\x5c" * 32

groups = {"KPAD_IN": KPAD_IN, "HASH_IN": HASH_IN, "hashA": hashA,
          "hashB": hashB, "digest": digest, "sha256(body)": hashlib.sha256(body).digest()}

msgs = {
    "KPAD_IN||Z||body": KPAD_IN + ZEROS + body,
    "KPAD_IN||body": KPAD_IN + body,
    "Z||body": ZEROS + body,
    "body": body,
    "HASH_IN||ipad||body": HASH_IN + IPAD + body,
    "HASH_IN||body": HASH_IN + body,
    "ipad||body": IPAD + body,
    "hashA||opad||hashB": hashA + OPAD + hashB,
    "opad||hashB": OPAD + hashB,
    "hashA||hashB": hashA + hashB,
    "KPAD_IN": KPAD_IN,
    "HASH_IN": HASH_IN,
}

print("== which message hashes (sha256) to which group ==")
for mn, m in msgs.items():
    h = hashlib.sha256(m).digest()
    for gn, g in groups.items():
        if h == g:
            print("HIT: sha256(%s) == %s" % (mn, gn))

print("== sha256 midstate chain checks (64-B blocks) ==")
# if sha256, hashing 208B = 3.25 blocks; try chain: sha256(A+B) vs midstate
def sha(x):
    return hashlib.sha256(x).digest()

# HMAC standard forms
print("hmac(body,key=KPAD_IN)?", hashlib.sha256(OPAD + sha(KPAD_IN + body)).digest() == digest)
print("hmac-like variants:")
tests = [
    ("sha256(opad||sha256(ipad||body))", OPAD, IPAD),
    ("sha256(opad||sha256(ipad||body)nokey)", OPAD, IPAD),
]
for name, o, i in tests:
    inner = sha(i + body)
    outer = sha(o + inner)
    print(" ", name, outer.hex()[:16], "== digest?", outer == digest)

# word-swapped / byte-swapped variants of the messages
def bswap_words(b):
    return b"".join(b[i:i+4][::-1] for i in range(0, len(b), 4))

variants = {
    "bswap(KPAD_IN)+Z+body": bswap_words(KPAD_IN) + ZEROS + body,
    "KPAD_IN+Z+bswap(body)": KPAD_IN + ZEROS + bswap_words(body),
    "bswap-all(KPAD_IN||Z||body)": bswap_words(KPAD_IN + ZEROS + body),
}
for mn, m in variants.items():
    h = sha(m)
    for gn, g in groups.items():
        if h == g or bswap_words(h) == g:
            print("HIT(variant): sha256(%s) == %s" % (mn, gn))

# Is HASH_IN sha256 of anything simple?
print("\nHASH_IN =", HASH_IN.hex())
print("sha256(KPAD_IN) =", sha(KPAD_IN).hex())
print("sha256(KPAD_IN||Z) =", sha(KPAD_IN + ZEROS).hex())
