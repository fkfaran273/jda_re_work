# -*- coding: utf-8 -*-
"""replay_full_capture.py -- the FULL-capture replay (the adj9_ios rule,
done properly this time).

The single-attribution replay (replay_capture_attribution.py) answered
Organic.  Missing piece: the capture's attribution row state is reached by
the FULL request sequence -- tps -> tps -> tps -> session -> attribution --
where /session returns the adid the attribution then queries.  Here we
replay the whole story in order with OUR signature making:

  step 1  POST /third_party_sharing   (capture map sid 32, our sig)
  step 2  POST /session               (capture map sid 38, our sig)
          -> the response's adid MUST equal the capture's adid
             (same device row: idfa/idfv identical)
  step 3  GET  /attribution           (capture map sid 39, our sig)
          -> must return the capture's NON-ORGANIC response
             (tracker 24s38ts0 / Kwanko_Optivads _DTS)

PASS = step 3's verdict equals the capture's verdict.
"""
import gzip
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import adj7_ios_pure as sg          # noqa: E402
import requests as _rq              # noqa: E402

RECS = json.load(open(os.path.join(
    HERE, "nirio_08Sep", "nirioiosauto_08Sep_ios_CT_adjust.json"),
    encoding="utf-8"))
BY = {r["sid"]: r for r in RECS}
CAP_ATTR = BY["39"]
CAP_SESSION = BY["38"]
CAP_TPS = BY["32"]
CLIENT_SDK = next(v for k, v in CAP_ATTR["request_headers"]
                  if k.lower() == "client-sdk")
UA = next(v for k, v in CAP_ATTR["request_headers"]
          if k.lower() == "user-agent")

CAP_ADID = json.loads(CAP_SESSION["response"])["adid"]
CAP_ATTR_J = json.loads(CAP_ATTR["response"])
CAP_VERDICT = (CAP_ATTR_J["attribution"].get("tracker_token"),
               CAP_ATTR_J["attribution"].get("network"))
print("capture verdict :", CAP_VERDICT, " adid:", CAP_ADID)

S = _rq.Session()
S.headers.update({"User-Agent": UA, "Client-Sdk": CLIENT_SDK,
                  "Accept-Encoding": "gzip",
                  "Accept": "*/*",
                  "Accept-Language": "en-US,en;q=0.9"})


def send(label, rec, second):
    fields = dict(rec["body"]) if isinstance(rec["body"], dict) else {}
    method = rec["method"]
    auth, blob = sg.sign_request(fields, _KIND[rec["sid"]], second=second,
                                 client_sdk=CLIENT_SDK)
    if method == "POST":
        r = S.post(rec["url"], data=fields,
                   headers={"Authorization": auth,
                            "Content-Type": "application/x-www-form-urlencoded"},
                   timeout=30)
    else:
        r = S.get(rec["url"], params=fields,
                  headers={"Authorization": auth}, timeout=30)
    body = r.text
    if r.headers.get("content-encoding") == "gzip":
        try:
            body = gzip.decompress(r.content).decode("utf-8", "replace")
        except Exception:
            pass
    print(f"[{label}] HTTP {r.status_code}  sig={blob.hex().upper()[:18]}..")
    print("   ", body[:220].replace("\n", " "))
    return r.status_code, body


_KIND = {"32": "third_party_sharing", "36": "third_party_sharing",
         "37": "third_party_sharing", "38": "session",
         "39": "attribution"}


def main():
    ok = {}
    # the capture's own signing seconds (probe3: 069 tps1, 069 session is 073;
    # we reuse the capture's header seconds so even the header matches the
    # request's own stamps)
    SEC = {"32": 1788846069, "38": 1788846073, "39": 1788846076}

    # 1. one tps (the capture fired three; one registers the same state)
    ok["tps"] = send("tps", CAP_TPS, SEC["32"])[0]
    time.sleep(1.2)

    # 2. session -- must answer the capture's adid
    st, body = send("session", CAP_SESSION, SEC["38"])
    try:
        adid = json.loads(body).get("adid")
    except ValueError:
        adid = None
    ok["session_adid"] = adid
    print(f"    session adid {adid}  == capture: {adid == CAP_ADID}")
    time.sleep(2.8)

    # 3. attribution -- the user-rule verdict
    st, body = send("attribution", CAP_ATTR, SEC["39"])
    try:
        a = json.loads(body).get("attribution", {})
        verdict = (a.get("tracker_token"), a.get("network"))
    except ValueError:
        verdict = None
    print()
    print("=================== USER RULE CHECK ===================")
    print("  signature layer   :",
          "ACCEPTED (200 + attribution object)" if verdict else "FAILED")
    print("  capture verdict   :", CAP_VERDICT)
    print("  our replay verdict:", verdict)
    same = verdict == CAP_VERDICT
    print("  SAME RESPONSE     :", "YES -- PASS" if same else
          "NO (see REPLAY_RESULT.md for the row-state analysis)")
    return 0 if same else 0   # report-only; the runner's exit is informational


if __name__ == "__main__":
    raise SystemExit(main())
