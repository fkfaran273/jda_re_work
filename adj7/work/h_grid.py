"""h_grid.py — genuine-record H grid: claims composition x nonce12 encoding.

Known-good machinery: commit2.commitments(claims, prefix12) (verified on 3
mint claims variants).  Genuine records give H (from the record's b field),
a/d (candidate nonce12 encodings), and the raw wire maps.
"""
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

def parse_map(s):
    if not s:
        return {}
    return dict(urllib.parse.parse_qsl(s, keep_blank_values=True))

def nonce_variants(a_str, d_hex):
    n = int(a_str)
    dh = bytes.fromhex(d_hex)
    yield "le||d", struct.pack("<Q", n) + dh
    yield "be||d", struct.pack(">Q", n) + dh
    yield "le||drev", struct.pack("<Q", n) + dh[::-1]
    yield "be||drev", struct.pack(">Q", n) + dh[::-1]

def claims_variants(sid):
    ent = bodies.get(sid)
    d = data[sid]
    recon = dict(ent["body_params_dict"]) if ent else {}
    body_map = parse_map(ent.get("raw_body_or_query")) if ent else {}
    query_map = parse_map(urllib.parse.urlparse(d["path"]).query)
    kind = ("session" if "/session" in d["path"] else
            "click" if "/click" in d["path"] else
            "event" if "/event" in d["path"] else "attribution")
    out = []
    out.append(("recon", sg.build_claims("session", recon)))
    out.append(("recon+b2", sg.build_claims(kind, recon, include_block2=True)))
    if body_map:
        out.append(("bodymap", sg.build_claims("session", body_map)))
        out.append(("bodymap+b2", sg.build_claims(kind, body_map,
                                                  include_block2=True)))
    out.append(("querymap", sg.build_claims("session", query_map)))
    out.append(("querymap+b2", sg.build_claims(kind, query_map,
                                               include_block2=True)))
    merged = dict(query_map); merged.update(body_map); merged.update(recon)
    out.append(("merged", sg.build_claims("session", merged)))
    out.append(("merged+b2", sg.build_claims(kind, merged,
                                             include_block2=True)))
    return out

hits = 0
tested = 0
for cr in recs:
    sid = cr["sid"]
    R = bytes.fromhex(cr["record"])
    i_b = R.find(b' ,"b": "')
    a = R[8:i_b].decode()
    b_hex = R[i_b+8:i_b+72].decode()
    i_d = R.find(b'","d": "')
    d8 = R[i_d+8:i_d+16].decode()
    for cname, claims in claims_variants(sid):
        for ename, n12 in nonce_variants(a, d8):
            tested += 1
            c20, c32, H = c2.commitments(claims, prefix12=n12)
            Hhex = b"".join(x.to_bytes(4, "big") for x in H).hex().upper()
            if Hhex == b_hex:
                hits += 1
                print("HIT sid %s claims=%s nonce=%s" % (sid, cname, ename))
print("grid: %d combos tested, %d hits" % (tested, hits))
