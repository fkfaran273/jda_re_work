# -*- coding: utf-8 -*-
"""replay_phaseb_nirio.py -- the adj8 Phase B rule applied LITERALLY to nirio.

The one element never replayed before: sid-33, the POST /sdk_click with
source=apple_ads and the capture's REAL attribution_token.  adj8's own rule
only returned non-organic when the full sequence ran, sdk_click included
(replay_bevietnam Phase B: session -> sdk_click -> attribution).

This script replays the capture in its own chronological order, every
request signed by our adj7 signer, maps byte-identical to the capture:

  1  POST /third_party_sharing  (sid 32)
  2  POST /sdk_click            (sid 33, source=apple_ads, capture's token)
  3  POST /session              (sid 38)  -> adid must equal capture adid
  4  GET  /attribution          (sid 39)  -> PASS = the logged verdict
                                             (tracker 24s38ts0 / Kwanko)

If step 4 still answers Organic, a second attempt runs the be-Phase-B
order (session -> sdk_click -> attribution) with fresh seconds.

PASS = attribution network/tracker_token equal the capture's logged response.
"""
import gzip
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import adj7_ios_pure as sg          # noqa: E402
import requests as _rq              # noqa: E402

RECS = json.load(open(os.path.join(
    HERE, "nirio_08Sep", "nirioiosauto_08Sep_ios_CT_adjust.json"),
    encoding="utf-8"))
BY = {r["sid"]: r for r in RECS}
CAP_TPS, CAP_CLICK = BY["32"], BY["33"]
CAP_SESSION, CAP_ATTR = BY["38"], BY["39"]
CLIENT_SDK = next(v for k, v in CAP_ATTR["request_headers"]
                  if k.lower() == "client-sdk")
UA = next(v for k, v in CAP_ATTR["request_headers"]
          if k.lower() == "user-agent")

CAP_ADID = json.loads(CAP_SESSION["response"])["adid"]
CAP_A = json.loads(CAP_ATTR["response"])["attribution"]
CAP_VERDICT = (CAP_A.get("tracker_token"), CAP_A.get("network"))
CLICK_RESP = CAP_CLICK["response"][:200]
print("capture verdict :", CAP_VERDICT, " adid:", CAP_ADID)
print("capture click   :", CLICK_RESP)

S = _rq.Session()
S.headers.update({"User-Agent": UA, "Client-Sdk": CLIENT_SDK,
                  "Accept-Encoding": "gzip", "Accept": "*/*",
                  "Accept-Language": "en-US,en;q=0.9"})

_KIND = {"32": "third_party_sharing", "33": "click", "38": "session",
         "39": "attribution"}


def send(label, rec, second=None):
    fields = dict(rec["body"]) if isinstance(rec["body"], dict) else {}
    second = int(time.time()) if second is None else second
    auth, blob = sg.sign_request(fields, _KIND[rec["sid"]], second=second,
                                 client_sdk=CLIENT_SDK)
    if rec["method"] == "POST":
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
    print("[%s] HTTP %d  sig=%s.." % (label, r.status_code,
                                      blob.hex().upper()[:16]))
    print("    ", body[:240].replace("\n", " "))
    return r.status_code, body


def verdict_of(body):
    try:
        a = json.loads(body).get("attribution") or {}
        return (a.get("tracker_token"), a.get("network"))
    except ValueError:
        return None


def run_sequence(name, order):
    print()
    print("=" * 74)
    print(name)
    print("=" * 74)
    adid = None
    for rec, gap in order:
        st, body = send(rec["sid"], rec)
        if rec["sid"] == "38":
            try:
                adid = json.loads(body).get("adid")
            except ValueError:
                adid = None
            print("    session adid %s == capture: %s"
                  % (adid, adid == CAP_ADID))
        time.sleep(gap)
    return verdict_of(body)


def main():
    # 1) capture's own chronological order (sdk_click BEFORE session)
    v1 = run_sequence(
        "SEQUENCE 1: capture order  tps -> apple_ads sdk_click -> "
        "session -> attribution",
        [(CAP_TPS, 1.5), (CAP_CLICK, 3.0), (CAP_SESSION, 3.0),
         (CAP_ATTR, 0.5)])
    print("sequence 1 verdict:", v1)

    ok = v1 == CAP_VERDICT or (v1 and v1[1] and v1[1] != "Organic"
                               and v1[1] == CAP_VERDICT[1])
    if not ok:
        # 2) adj8 be Phase B order: session -> sdk_click -> attribution
        time.sleep(6)
        v2 = run_sequence(
            "SEQUENCE 2: be Phase B order  session -> apple_ads sdk_click "
            "-> attribution",
            [(CAP_SESSION, 2.0), (CAP_CLICK, 3.0), (CAP_ATTR, 0.5)])
        print("sequence 2 verdict:", v2)
        ok = (v2 == CAP_VERDICT or
              (v2 and v2[1] and v2[1] != "Organic" and v2[1] == CAP_VERDICT[1]))

    print()
    print("=================== USER RULE CHECK ===================")
    print("  logged verdict     :", CAP_VERDICT)
    print("  replay verdict seq1:", v1)
    print("  RESULT             :", "PASS -- NON-ORGANIC AS IN LOGS"
          if ok else "not returned (see responses above)")
    json.dump({"logged": CAP_VERDICT, "seq1": v1, "pass": bool(ok)},
              open(os.path.join(HERE, "phaseb_nirio_result.json"), "w"),
              indent=1)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
