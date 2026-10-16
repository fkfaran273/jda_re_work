# -*- coding: utf-8 -*-
"""replay_attr_test.py -- the ATTRIBUTION REPLAY RULE for adj7 iOS.

The user rule: replay the capture's attribution exchange with OUR signature
making; the server must answer with the same verdict the genuine device got
in the log.

Default golden capture: Watsons sid 110 (analytics.adjust.com, adj7 /
native 3.62.0 / headers_id 8), whose logged answer is the stable no-consent
row state:

    HTTP 200  adid ca7afe2af868639f9e8d06be7441137b
    tracker_token "unattr" / tracker_name + network "No User Consent"
    installed_at = first_session_time = 2026-08-18T05:22:22Z

Probes
  G    genuine control -- the exact logged request bytes re-sent today
  O    ours            -- same wire map, fresh second + nonce, our mint
  ARM  the SDK-shaped decisive path: POST /session (ours) -> wait the
       response's ask_in -> GET /attribution (ours)  ==>  compare against
       the LOGGED verdict field-by-field.

Interpretation (established 2026-10-08): a 400 with {adid, ask_in} is the
row's ask-cadence throttle -- the GENUINE signature receives the identical
answer under the same conditions; it is row state, not a signature verdict.
The armed path is how the device itself gets the 200 attribution object,
and it is the comparison that decides the rule.

    python replay_attr_test.py                # G + O + ARM on Watsons
    python replay_attr_test.py --fresh-row   # + enforcement triad
                                              # (ours/tampered/unsigned
                                              #  sessions on fresh rows)
"""
import json
import os
import re
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj7ios_pure as sg                                   # noqa: E402
from make_gold import carve                                 # noqa: E402

WATSONS = r"C:\Users\Apps\Downloads\ct_Watson_logs_18Aug_ios.saz"
import zipfile                                             # noqa: E402
import urllib.parse as up                                  # noqa: E402


def fields_of(rec):
    q = rec["url"].split("?", 1)[1]
    return {k: up.unquote_plus(v) for k, v in
            (p.split("=", 1) for p in q.split("&"))}


def logged_response(saz, sid):
    zf = zipfile.ZipFile(saz)
    body = zf.read("raw/%s_s.txt" % sid).partition(b"\r\n\r\n")[2]
    return json.loads(body.decode("utf-8", "replace"))


def headers(rec, auth=None):
    h = {"User-Agent": rec["ua"], "Client-Sdk": rec["client_sdk"],
         "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}
    if auth:
        h["Authorization"] = auth
    return h


def stamp_now(off=0.0):
    import datetime
    t = time.time() + off
    d = (datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
         + datetime.timedelta(hours=4))
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0400" % int(t % 1 * 1000)


def main():
    with_controls = "--fresh-row" in sys.argv
    recs = carve(WATSONS)
    atr = next(r for r in recs if r["sid"] == "110")
    ses = next(r for r in recs if r["sid"] == "034")
    kv = atr["auth_kv"]
    base = atr["url"].split("?", 1)[0]
    f_atr = fields_of(atr)
    genuine_auth = ('Signature signature="%s",adj_signing_id="%s",'
                    'algorithm="%s",headers_id="%s",native_version="%s"'
                    % (atr["sig"], kv["adj_signing_id"], kv["algorithm"],
                       kv["headers_id"], kv["native_version"]))
    logged = logged_response(WATSONS, "110")["attribution"]
    print("logged (capture): adid %s | %s / %s / %s | installed %s\n"
          % (logged_response(WATSONS, "110")["adid"],
             logged.get("tracker_token"), logged.get("tracker_name"),
             logged.get("network"), logged.get("installed_at")))

    out = {}

    # ---- G genuine verbatim -------------------------------------------
    r = requests.get(atr["url"], headers=headers(atr, genuine_auth),
                     timeout=30)
    out["G_genuine"] = {"http": r.status_code, "body": r.text[:300]}
    print("[G genuine verbatim]  HTTP %s  %s" % (r.status_code, r.text[:160]))
    time.sleep(2)

    # ---- O ours, capture map -------------------------------------------
    auth_o, _ = sg.sign_request(f_atr, "attribution",
                                client_sdk=atr["client_sdk"])
    r = requests.get(base, params=f_atr, headers=headers(atr, auth_o),
                     timeout=30)
    out["O_ours"] = {"http": r.status_code, "body": r.text[:300]}
    print("[O ours fresh sig]    HTTP %s  %s" % (r.status_code, r.text[:160]))
    time.sleep(2)

    # ---- ARM: session (ours) -> ask_in -> attribution (ours) -----------
    auth_s, _ = sg.sign_request(ses["params"], "session",
                                client_sdk=ses["client_sdk"])
    h = headers(ses, auth_s)
    h["Content-Type"] = "application/x-www-form-urlencoded"
    r1 = requests.post("https://analytics.adjust.com/session",
                       data=ses["params"], headers=h, timeout=30)
    print("[ARM session ours]    HTTP %s  %s"
          % (r1.status_code, r1.text[:160]))
    ask = None
    try:
        ask = r1.json().get("ask_in")
    except ValueError:
        pass
    if r1.status_code == 200 and ask:
        time.sleep(ask / 1000.0 + 2)
        auth_a, _ = sg.sign_request(f_atr, "attribution",
                                    client_sdk=atr["client_sdk"])
        r2 = requests.get(base, params=f_atr, headers=headers(atr, auth_a),
                          timeout=30)
        got = {}
        try:
            got = r2.json().get("attribution") or {}
        except ValueError:
            pass
        out["ARM_attribution_ours"] = {"http": r2.status_code,
                                       "adid": r2.json().get("adid"),
                                       "attribution": got}
        print("[ARM attribution]    HTTP %s  %s"
              % (r2.status_code, r2.text[:220]))
        same = all(got.get(k) == logged.get(k)
                   for k in ("tracker_token", "tracker_name", "network",
                             "engagement_time", "installed_at",
                             "first_session_time", "is_reattributed"))
        adid_same = out["ARM_attribution_ours"]["adid"] == \
            logged_response(WATSONS, "110")["adid"]
        print("\n================== REPLAY RULE ===================")
        print("  armed ask, OUR signature -> logged verdict: %s"
              % ("REPRODUCED (every field identical)"
                 if same and adid_same else "MISMATCH"))
        out["replay_rule_pass"] = bool(same and adid_same)
    else:
        print("\n  ARM could not run (session %s) -- see body; if it is "
              "400 ask_in / check-interval, the row cadence is closed; "
              "retry later or use --fresh-row." % r1.status_code)
        out["replay_rule_pass"] = False

    # ---- optional: enforcement triad on fresh rows ----------------------
    if with_controls:
        import uuid

        def fresh(kind):
            m = dict(ses["params"] if kind == "session" else f_atr)
            st = stamp_now()
            m.update({"primary_dedupe_token": str(uuid.uuid4()).lower(),
                      "idfv": str(uuid.uuid4()).upper(),
                      "installed_at": st, "created_at": st,
                      "sent_at": st, "started_at": st,
                      "session_count": "1", "retry_count": "0"})
            return m

        for label, mode in (("fresh-row OURS", "ours"),
                            ("fresh-row TAMPERED", "tampered"),
                            ("fresh-row UNSIGNED", "none")):
            m = fresh("session")
            auth, blob = sg.sign_request(m, "session",
                                         client_sdk=ses["client_sdk"])
            if mode == "tampered":
                sig = auth.split('"')[1]
                b = bytearray(bytes.fromhex(sig))
                b[272 + 16] ^= 0xFF
                auth = auth.replace(sig, bytes(b).hex().upper())
            if mode == "none":
                auth = None
            h = headers(ses, auth)
            h["Content-Type"] = "application/x-www-form-urlencoded"
            r = requests.post("https://analytics.adjust.com/session",
                              data=m, headers=h, timeout=30)
            out[label] = {"http": r.status_code, "body": r.text[:200]}
            print("[%s] HTTP %s  %s" % (label, r.status_code, r.text[:160]))
            time.sleep(2)

    with open(os.path.join(HERE, "replay_attr_result.json"), "w") as f:
        json.dump(out, f, indent=1)
    print("\nwritten: replay_attr_result.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
