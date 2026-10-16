# -*- coding: utf-8 -*-
"""replay_saz.py -- generic adj7-iOS attribution replay from a Fiddler .saz.

    python replay_saz.py <capture.saz> [attr_sid [session_sid]]

Finds the signed attribution GET (default: first) + signed session, then:
  G   genuine verbatim (exact URL bytes + capture Authorization)
  O   ours (same map, fresh second + nonce)
  ARM our signed /session -> wait ask_in -> our signed /attribution
and compares everything against the capture's LOGGED attribution body.
"""
import json
import re
import sys
import time
import zipfile

import requests

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7ios")
import adj7ios_pure as sg                                   # noqa: E402
from make_gold import carve                                 # noqa: E402


def logged_response(zf, sid):
    body = zf.read("raw/%s_s.txt" % sid).partition(b"\r\n\r\n")[2]
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None


def main():
    path = sys.argv[1]
    recs = carve(path)
    zf = zipfile.ZipFile(path)
    atr_sid = sys.argv[2] if len(sys.argv) > 2 else \
        next(r["sid"] for r in recs if r["endpoint"] == "attribution")
    ses_sid = sys.argv[3] if len(sys.argv) > 3 else \
        next((r["sid"] for r in recs if r["endpoint"] == "session"), None)
    atr = next(r for r in recs if r["sid"] == atr_sid)
    kv = atr["auth_kv"]
    logged_full = logged_response(zf, atr_sid)
    logged = (logged_full or {}).get("attribution") or {}
    host = atr["url"].split("/")[2]
    print("capture %s sid %s (%s)" % (path, atr_sid, host))
    if logged:
        print("logged : adid %s | tracker %s | name %s | network %s | "
              "installed %s"
              % (logged_full.get("adid"), logged.get("tracker_token"),
                 logged.get("tracker_name"), logged.get("network"),
                 logged.get("installed_at")))
    else:
        print("logged : (response not captured)")
    print()

    hdr = {"User-Agent": atr["ua"], "Client-Sdk": atr["client_sdk"],
           "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"}
    genuine_auth = ('Signature signature="%s",adj_signing_id="%s",'
                    'algorithm="%s",headers_id="%s",native_version="%s"'
                    % (atr["sig"], kv["adj_signing_id"], kv["algorithm"],
                       kv["headers_id"], kv["native_version"]))
    base = atr["url"].split("?", 1)[0]

    out = {}

    def go(label, url_or_params, auth, params=False):
        h = dict(hdr)
        h["Authorization"] = auth
        if params:
            r = requests.get(base, url_or_params, headers=h, timeout=30)
        else:
            r = requests.get(url_or_params, headers=h, timeout=30)
        try:
            j = r.json()
        except ValueError:
            j = {}
        a = j.get("attribution") or {}
        print("[%s] HTTP %s adid=%s ask_in=%s"
              % (label, r.status_code, j.get("adid"), j.get("ask_in")))
        if a:
            print("     tracker=%s name=%s network=%s engage=%s "
                  "installed=%s"
                  % (a.get("tracker_token"), a.get("tracker_name"),
                     a.get("network"), a.get("engagement_time"),
                     a.get("installed_at")))
        else:
            print("     body:", r.text[:160])
        out[label] = {"http": r.status_code, "json": j}
        return j, a

    # G -- genuine verbatim (the capture's exact URL)
    gj, ga = go("G", atr["url"], genuine_auth)
    time.sleep(3)
    # O -- ours fresh sig
    auth_o, _ = sg.sign_request(atr["params"], "attribution",
                                client_sdk=atr["client_sdk"])
    oj, oa = go("O", atr["params"], auth_o, params=True)

    # ARM -- armed via our session
    if ses_sid:
        ses = next(r for r in recs if r["sid"] == ses_sid)
        auth_s, _ = sg.sign_request(ses["params"], "session",
                                    client_sdk=ses["client_sdk"])
        h = dict(hdr)
        h["Authorization"] = auth_s
        h["Content-Type"] = "application/x-www-form-urlencoded"
        r1 = requests.post("https://%s/session" % host, data=ses["params"],
                           headers=h, timeout=30)
        sj = {}
        try:
            sj = r1.json()
        except ValueError:
            pass
        print("[ARM session ours] HTTP %s %s"
              % (r1.status_code, json.dumps(sj)[:160]))
        out["ARM_session"] = {"http": r1.status_code, "json": sj}
        if r1.status_code == 200:
            time.sleep((sj.get("ask_in", 2000) / 1000.0) + 2)
            auth_a, _ = sg.sign_request(atr["params"], "attribution",
                                        client_sdk=atr["client_sdk"])
            aj, aa = go("ARM", atr["params"], auth_a, params=True)
        else:
            print("     (session %s -- not arming)" % r1.status_code)
            aa = {}
    else:
        aa = {}

    def state(a, http):
        if http != 200 or not a:
            return "http %s / no object" % http
        if logged and a.get("tracker_token") == logged.get("tracker_token") \
                and a.get("network") == logged.get("network"):
            return "LOGGED VERDICT REPRODUCED"
        if a.get("network") == "Organic":
            return "Organic (row re-evaluated)"
        return "state %s/%s" % (a.get("tracker_token"), a.get("network"))

    print("\n================= REPLAY RULE =================")
    for k, v in out.items():
        a = (v["json"] or {}).get("attribution") or {}
        print("  %-14s %s" % (k, state(a, v["http"])))
    sig_layer = out["G"]["json"] == out["O"]["json"]
    print("\n  signature layer (O == G): %s"
          % ("PASS" if sig_layer else "DIFFER"))
    rname = re.sub(r"[^A-Za-z0-9]+", "_", path.split("\\")[-1])[:-4]
    with open(r"C:\Users\Apps\Downloads\com.penti.app\adj7ios\replay_%s_"
              "result.json" % rname[:40], "w") as f:
        json.dump(out, f, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
