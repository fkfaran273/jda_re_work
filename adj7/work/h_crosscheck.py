"""h_crosscheck.py — corpus b-field == commit2-law H with per-record nonce12?

nonce12 = u64le(a) || unhex(d).  H = custom-IV0 sha256 over
00*40 || nonce12 || sha0hex-upper || claims.
"""
import json, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)
import adj7_signer as sg
import commit2_hunt as c2

recs = json.load(open(os.path.join(HERE, "corpus_records.json")))
bodies = {b["sid"]: b for b in json.load(
    open(os.path.join(WORK, "adj7b_bodies.json")))}

ok = bad = miss = 0
for cr in recs:
    sid = cr["sid"]
    R = bytes.fromhex(cr["record"])
    i_b = R.find(b' ,"b": "')
    a = R[8:i_b].decode()
    b_hex = R[i_b+8:i_b+72].decode()
    i_d = R.find(b'","d": "')
    d8 = R[i_d+8:i_d+16].decode()
    nonce12 = struct.pack("<Q", int(a)) + bytes.fromhex(d8)
    ent = bodies.get(sid)
    if ent is None:
        print("sid %s: no bodies entry" % sid)
        miss += 1
        continue
    claims = sg.build_claims("session", dict(ent["body_params_dict"]))
    c20, c32, H = c2.commitments(claims, prefix12=nonce12)
    Hhex = b"".join(x.to_bytes(4, 'big') for x in H).hex().upper()
    match = Hhex == b_hex
    ok += match
    bad += (not match)
    print("sid %s a=%s d=%s H_match=%s" % (sid, a, d8, match))
print("H cross-check: %d ok, %d bad, %d missing" % (ok, bad, miss))
