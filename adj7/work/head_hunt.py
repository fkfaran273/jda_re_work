"""head_hunt.py — is the corpus record's 16-B prefix PRNG material?

For each corpus record: compute BionicRand draws for its signing second,
compare various slices/packings against the record prefix (16 B) and the
varying d-field (4 B) and the trailing digits.
"""
import json, os, re, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
sys.path.insert(0, WORK)
from adj7_signer import BionicRand

recs = json.load(open(os.path.join(HERE, "corpus_records.json")))
data = {r["sid"]: r for r in json.load(
    open(os.path.join(WORK, "adj7_data.json"))) if r["app"] == "doodhvale_android"}

def draws(sec, n):
    R = BionicRand(sec)
    return [R.next() for _ in range(n)]

for cr in recs[:8]:
    sid = cr["sid"]
    R = bytes.fromhex(cr["record"])
    blob = bytes.fromhex(data[sid]["sig_hex"])
    header = blob[:16]
    sec = int(data[sid]["created_at"])
    d = draws(sec, 24)
    px = R[:16]
    print("sid", sid, "sec", sec)
    print("  record prefix :", px.hex())
    print("  header        :", header.hex())
    # pair-XOR of draws 8..15, 16..23
    w8 = [d[2*i] ^ d[2*i+1] for i in range(4)]
    w12 = [d[2*i] ^ d[2*i+1] for i in range(4, 8)]
    w16 = [d[2*i] ^ d[2*i+1] for i in range(8, 12)]
    p8 = b"".join(v.to_bytes(4, "big") for v in w8)
    p12 = b"".join(v.to_bytes(4, "big") for v in w12)
    p16 = b"".join(v.to_bytes(4, "big") for v in w16)
    print("  pairXOR(0..7) :", p8.hex(), "(== header:", p8 == header, ")")
    print("  pairXOR(8..15):", p12.hex(), " match px:", p12 == px)
    print("  pairXOR(16..23):", p16.hex(), " match px:", p16 == px)
    # draws 8..15 packed BE directly (32 B) vs px+next 16
    d8 = b"".join(v.to_bytes(4, "big") for v in d[8:12])
    print("  draws8..11 BE :", d8.hex(), " match px:", d8 == px)
    # trailing digits before ' ,"b"'
    m = re.search(rb'(\d+) ,"b"', R)
    digits = m.group(1) if m else None
    # find digits: region between prefix and ' ,"b"'
    i = R.find(b' ,"b"')
    pre = R[16:i] if i >= 16 else None
    print("  pre-' ,'b' region:", pre, "(len %d)" % len(pre) if pre else "")
    print("  d-field:", R[R.find(b'","d": "')+8:R.find(b'","d": "')+16]
          if b'","d": "' in R else None)
