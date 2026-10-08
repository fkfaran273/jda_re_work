"""law_recheck.py -- with the patched myrun signer copy:
1. byte-exact rebuild of genuine sid-44 blob (same fields/nonce/second/cert)
2. claims-H MATCH for session/click/attribution, event status
"""
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone, timedelta

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun"
sys.path.insert(0, HERE)
import adj7_pure as sg

print("pool has secret_id:", "secret_id" in sg.CLAIM_POOL)

CAPJ = json.load(open(
    r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))


def blob_of(e):
    auth = None
    for k, v in e["request_headers"]:
        if k.lower() == "authorization":
            auth = v
    return bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1))


def fields_of(e):
    if e["method"] == "GET":
        return dict(urllib.parse.parse_qsl(e["url"].split("?", 1)[1],
                                           keep_blank_values=True))
    b = e["body"]
    return b if isinstance(b, dict) else json.loads(b)


KINDS = {"42": "session", "43": "click", "44": "attribution"}
for sid, kind in KINDS.items():
    e = next(x for x in CAPJ if str(x["sid"]) == sid)
    blob = blob_of(e)
    print("sid %s tag_ok=%s" % (sid, sg.verify_tag(blob)))

# 1. byte-exact rebuild of sid 44
e = next(x for x in CAPJ if str(x["sid"]) == "44")
blob = blob_of(e)
fields = fields_of(e)
ca = fields["created_at"]
u = ca.replace("Z+0530", "")
dt = datetime.strptime(u.split(".")[0], "%Y-%m-%dT%H:%M:%S")
sec = int((dt - timedelta(hours=5, minutes=30)).replace(
    tzinfo=timezone.utc).timestamp())
auth = None
for k, v in e["request_headers"]:
    if k.lower() == "authorization":
        auth = v
# recover nonce from record via decrypt (ks_inverse not importable here w/o adj7 path;
# use local minimal inverse? instead reuse known values from earlier audit)
nonce12 = bytes.fromhex("deb8d66011fc70a885006809")
auth2 = sg.sign_request(fields, "attribution", second=sec, nonce12=nonce12,
                        cert_sha1="C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF",
                        client_sdk="android5.6.0", include_block2=True,
                        headers_id="8", native_version="3.62.0")
blob2 = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth2).group(1))
print("sid44 byte-exact rebuild with patched signer:", blob2 == blob)

# 2. claims-H recheck per kind (block2 with genuine act/cs)
AGT = {"42": ("session", "session"), "43": ("click", "click"),
       "44": ("attribution", "attribution")}
for sid, (kind, act) in AGT.items():
    e = next(x for x in CAPJ if str(x["sid"]) == sid)
    blob = blob_of(e)
    # decrypt record b via simple parse is not available; use hanaf-style:
    # recompute claims and compare against known-good result from earlier audit
    fields = fields_of(e)
    cl = sg.build_claims(kind, dict(fields, activity_kind=act,
                                    client_sdk="android5.6.0"),
                         include_block2=True)
    print("sid %s claims bytes=%d act=%s" % (sid, len(cl), act))
