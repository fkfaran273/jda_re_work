r"""crosscheck_control.py — positive/negative endpoint control, re-run today.

Proves /attribution still verifies signatures right now, using the transport
test's proven oracle: identity 2db6422f (genuinely non-organic, 24xg6t54) with
its own captured genuine blob (genuine -> campaign; flipped -> Organic).
Run AFTER the device-oracle + genuine-blob reads of gps 1e63c600 so the
Organic verdicts there cannot be blamed on a broken endpoint.
"""
import base64
import http.client
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import transport_fingerprint_test as T  # noqa: E402
import transport_test as tt  # noqa: E402

ORACLE = "2db6422f-0045-41bd-99ef-2264d70beec9"
REAL = "24xg6t54"

rows = tt.parse_capture()
attr = next(r for r in rows if r["kind"] == "attribution" and r["gps_adid"] == ORACLE)
ks = [k for k in attr["order"] if k in attr["claims"] and k not in T.CANON_ONLY]
q = "/attribution?" + "&".join(
    "%s=%s" % (urllib.parse.quote(k, safe=""), urllib.parse.quote(str(attr["claims"][k]), safe=""))
    for k in ks)
blob = attr["blob_b64"]
auth = attr["auth"]
print("oracle row %d, query %d B, blob %d B" % (attr["row"], len(q), len(base64.b64decode(blob))))

out = []
for tag, a in (("GENUINE-ORACLE", auth), ("FLIP-ORACLE", None)):
    if a is None:
        # flip byte0 bit0 of the blob inside the genuine auth header
        b = base64.b64decode(blob)
        fb = base64.b64encode(bytes([b[0] ^ 1]) + b[1:]).decode()
        a = 'Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",' \
            'headers_id="10",native_version="5.0.0",' \
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % fb
    st, txt, el, enc = T.send_httpclient("GET", q, a, None)
    try:
        at = json.loads(txt).get("attribution", {})
        verdict = at.get("tracker_token")
    except Exception:
        at, verdict = {}, "HTTP%s:%s" % (st, txt[:120])
    print("%-15s HTTP %d -> %s / %s" % (tag, st, verdict, at.get("network")))
    out.append({"arm": tag, "http": st, "tracker_token": verdict,
                "body": txt[:600]})
    time.sleep(3)

json.dump(out, open(os.path.join(HERE, "crosscheck_control_result.json"), "w"), indent=1)
print("saved crosscheck_control_result.json")
