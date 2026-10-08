"""block2_mint_test.py — does the native's H track the block2 map?

Mint with include_block2=True (Java-faithful d.sign), then:
  1. invert the blob body -> record; parse b (H)
  2. compare with commitments(build_claims(kind, params, include_block2=True),
     PREFIX12)
If it matches, the native's H is composition-agnostic and the funnel's
include_block2 flag directly controls the signed claims.
"""
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
os.chdir(WORK)                                   # the emu loads bins/ relative
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)
import adj7_signer as sg
import commit2_hunt as c2
sys.path.insert(0, HERE)
from corpus_inv import core_inv, K   # AES inverse core + key schedule

SEC = 1771239001
bodies = {b["sid"]: b for b in json.load(
    open(os.path.join(WORK, "adj7b_bodies.json")))}
params = dict(bodies["0015"]["body_params_dict"])

t0 = time.time()
blob, auth, meta = sg.mint_adj7("session", params, unix_sec=SEC,
                                include_block2=True, return_meta=True)
print("mint ok in %.1fs tag=%s header=%s" % (
    time.time() - t0, meta["tag_ok"], meta["header_ok"]))

header = blob[:16]
body = blob[16:272]
R = b""
prev = header
for k in range(16):
    P = core_inv(body[16*k:16*k+16])
    if k > 0:
        P = bytes(a ^ b for a, b in zip(P, prev))
    R += P
    prev = body[16*k:16*k+16]
txt = "".join(chr(b) if 32 <= b < 127 else "." for b in R)
print("record:", txt[:100])
i_b = R.find(b' ,"b": "')
b_hex = R[i_b+8:i_b+72].decode()
print("record H  :", b_hex)

claims_b2 = sg.build_claims("session", params, include_block2=True)
claims_plain = sg.build_claims("session", params)
for name, cl in (("block2-claims", claims_b2), ("plain-claims", claims_plain)):
    c20, c32, H = c2.commitments(cl)
    Hhex = b"".join(x.to_bytes(4, "big") for x in H).hex().upper()
    print("%-14s H=%s  match=%s" % (name, Hhex, Hhex == b_hex))
print("claims_b2 tail:", claims_b2[-60:])
print("meta claims_law tail:", meta["claims_law"][-60:])
