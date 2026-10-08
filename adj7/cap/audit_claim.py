"""audit_claim.py -- for a genuine capture blob: recover the record,
extract nonce12, and test which build_claims variant reproduces the
record's H.  This pins the genuine signing path (block2? pool order?).
"""
import json, re, sys, urllib.parse

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7\cap')
import adj7_pure as sg
from decrypt_rec import cbc_decrypt

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))

for sid in ("42", "43", "44", "45"):
    e = next(x for x in D if str(x["sid"]) == sid)
    auth = None
    for k, v in e["request_headers"]:
        if k.lower() == "authorization":
            auth = v
    blob = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1))
    rec = cbc_decrypt(blob[16:272], blob[:16])
    body = rec.rstrip(b"\x10").rstrip(b"\x00")
    print("=== sid", sid, e["url"].split("?")[0])
    print("   record head:", body[:120])
    a = re.search(rb'"a":\s+(\d+)', body).group(1).decode()
    H = re.search(rb'"b": "([0-9A-F]+)"', body).group(1).decode()
    c = re.search(rb'"c": "([^"]+)"', body).group(1)
    d8 = re.search(rb'"d": "([0-9A-F]+)"', body).group(1).decode()
    nonce12 = int(a).to_bytes(8, "little") + bytes.fromhex(d8)
    print("   cert:", c.decode(), "| nonce12:", nonce12.hex())
    # wire fields
    if e["method"] == "GET":
        q = e["url"].split("?", 1)[1]
        fields = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        kind = "attribution"
    else:
        fields = e["body"] if isinstance(e["body"], dict) else json.loads(e["body"])
        kind = e["url"].rstrip("/").split("/")[-1]
    for block2 in (False, True):
        claims = sg.build_claims(kind, fields, client_sdk="android5.6.0",
                                 include_block2=block2)
        Hx = sg.commitment_digest(claims, nonce12, c).hex().upper()
        print("   block2=%-5s H match: %s" % (block2, Hx == H))
