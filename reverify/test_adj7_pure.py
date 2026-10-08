"""Feed each capture's exact wire inputs through the SHIPPED adj7_pure.py
signer and compare its blob with the genuine device blob byte-for-byte."""
import os
import re
import sys
import urllib.parse

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "..", "adj7"))
sys.path.insert(0, BASE)

from verify_from_scratch import (CAPS, parse_request, request_fields,
                                 cbc_decrypt, REQ_RE, ts_candidates)
import adj7_pure as ap

CAMPAIGNS = {
    "smxi7gqwu39c": {
        "cert_sha1": "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF",
        "client_sdk": "android5.6.0",
        "adj_signing_id": "1300000", "headers_id": "8",
        "native_version": "3.62.0"},
    "vf3lochhmgw0": {
        "cert_sha1": "AA92A18790F85D4E9B5199C7792C55F2FB0F61E1",
        "client_sdk": "flutter5.5.0@android5.5.0",
        "adj_signing_id": "1300000", "headers_id": "8",
        "native_version": "3.62.0"},
}

npass = nfail = 0
for cap in sorted(os.listdir(CAPS)):
    d = os.path.join(CAPS, cap, "raw")
    sids = sorted({f.split("_")[0] for f in os.listdir(d)
                   if f.endswith("_c.txt")}, key=int)
    for sid in sids:
        data = open(os.path.join(d, sid + "_c.txt"), "rb").read()
        meth, pth, hdrs, body = parse_request(data)
        if ".adjust." not in hdrs.get("host", "").lower():
            continue
        auth = hdrs.get("authorization", "")
        if "signature=" not in auth:
            continue
        endpoint = pth.split("?")[0].rsplit("/", 1)[-1]
        kind = "click" if endpoint == "sdk_click" else endpoint
        blob = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"',
                                       auth).group(1))
        rec = cbc_decrypt(blob[16:272], blob[:16])
        m = REQ_RE.search(rec.decode("latin1"))
        nonce12 = int(m.group("A")).to_bytes(8, "little") \
            + bytes.fromhex(m.group("D"))
        fields = request_fields(meth, pth, body)
        app_token = fields.get("app_token", "")
        camp = CAMPAIGNS[app_token]
        sec = next(c for c in ts_candidates(fields)
                   if ap.make_header(c) == blob[:16])
        ours = ap.sign_request(fields, kind, second=sec, nonce12=nonce12,
                               campaign=camp, include_block2=True)
        m2 = re.search(r'signature="([0-9A-Fa-f]+)"', ours)
        ok = m2 and bytes.fromhex(m2.group(1)) == blob
        print("%-14s sid%-4s %-11s -> %s" % (
            cap, sid, endpoint, "OK" if ok else "** FAIL **"))
        if not ok:
            print("   ours:", m2.group(1)[:64])
            print("   real:", blob.hex().upper()[:64])
        npass += 1 if ok else 0
        nfail += 0 if ok else 1
print("shipped-signer: %d OK, %d FAIL" % (npass, nfail))
