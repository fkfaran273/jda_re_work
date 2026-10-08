"""h_cross2.py — H cross-check with full wire-map params from the captures."""
import hashlib, json, os, struct, sys, urllib.parse
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.path.join(HERE, "..", "..", "adj7_work"))
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)
import adj7_signer as sg
import commit2_hunt as c2

recs = json.load(open(os.path.join(HERE, "corpus_records.json")))
data = {r["sid"]: r for r in json.load(
    open(os.path.join(WORK, "adj7_data.json"))) if r["app"] == "doodhvale_android"}
bodies = {b["sid"]: b for b in json.load(
    open(os.path.join(WORK, "adj7b_bodies.json")))}

def nonce12_of(R):
    i_b = R.find(b' ,"b": "')
    a = R[8:i_b].decode()
    i_d = R.find(b'","d": "')
    d8 = R[i_d+8:i_d+16].decode()
    return struct.pack("<Q", int(a)) + bytes.fromhex(d8), a, d8

def kind_of(sid):
    d = data.get(sid)
    path = d["path"]
    if "/attribution" in path:
        return "attribution"
    if "/event" in path:
        return "event"
    if "/click" in path:
        return "click"
    return "session"

def try_H(claims, nonce12):
    c20, c32, H = c2.commitments(claims, prefix12=nonce12)
    return b"".join(x.to_bytes(4, "big") for x in H).hex().upper()

for cr in recs[:6]:
    sid = cr["sid"]
    R = bytes.fromhex(cr["record"])
    nonce12, a, d8 = nonce12_of(R)
    b_hex = R[R.find(b' ,"b": "')+8:R.find(b' ,"b": "')+72].decode()
    ent = bodies.get(sid)
    q = ent["raw_body_or_query"] if ent else None
    d = data[sid]
    results = []
    # variant 1: reconstructed body_params_dict
    bp = dict(ent["body_params_dict"])
    results.append(("recon", sg.build_claims("session", bp)))
    # variant 2: full query params (if GET-ish)
    try:
        q2 = urllib.parse.parse_qsl(
            urllib.parse.urlparse(d["path"]).query, keep_blank_values=True)
        full = dict(q2)
        results.append(("fullquery", sg.build_claims("session", full)))
        results.append(("fullquery+block2",
                        sg.build_claims(kind_of(sid), full,
                                        include_block2=True)))
    except Exception as e:
        pass
    # variant 3: recon + block2
    results.append(("recon+block2",
                    sg.build_claims(kind_of(sid), bp, include_block2=True)))
    for name, claims in results:
        h = try_H(claims, nonce12)
        print("sid %s %-16s H_match=%s" % (sid, name, h == b_hex))
