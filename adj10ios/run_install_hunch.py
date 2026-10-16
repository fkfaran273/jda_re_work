# -*- coding: utf-8 -*-
"""run_install_hunch.py -- live install funnel for hunch (adj7 iOS).

Tracker (user link):  https://app.adjust.com/1yzhva5b
    ?campaign=SOHYPE_ADH&adgroup={affiliate_id}&creative=[app_name}
with sub3=<fresh idfa> appended (the adj8ios device-matched-click rule:
the tracker forwards sub3 straight into the Adjust link as idfa=).

Two installs, one run:
    #1 att_status=3  (idfa everywhere, sub3=same idfa)
    #2 att_status=0  (idfa-less SDK shape; click still carries sub3=idfa)
Both sdk_clicks: source=apple_ads with a RANDOM attribution_token
(user request: "random attr token").

Per install: click -> CTIT 20 s -> signed /session -> signed /sdk_click
(apple_ads, random token) -> wait ask_in -> signed /attribution.
Everything signed by adj7ios_pure (headers_id 8 / native 3.62.0 /
client-sdk flutter5.5.0@ios5.5.0, verbatim from the capture).

    python run_install_hunch.py            # live
    python run_install_hunch.py --dry-run  # sign only, no click/send
"""
import base64
import json
import os
import sys
import time
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7ios_pure as sg                                   # noqa: E402
from make_gold import carve                                 # noqa: E402

SAZ = r"C:\Users\Apps\Downloads\hunchdatingiosauto_newapp_1appril2026 (1).saz"
LINK = ("https://app.adjust.com/1yzhva5b?campaign=SOHYPE_ADH"
        "&adgroup={affiliate_id}&creative=[app_name}")
CTIT = 20
HOST = "https://analytics.adjust.com"
SDK = "flutter5.5.0@ios5.5.0"
UA = "hunch/3 CFNetwork/1410.1 Darwin/22.6.0"
TZ = 3                                      # capture stamps are +0300


def stamp(off=0.0):
    import datetime
    t = time.time() + off
    d = (datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
         + datetime.timedelta(hours=TZ))
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0%03d" % (
        int(t % 1 * 1000), TZ * 100)


def fresh_maps(att):
    ses = next(r for r in carve(SAZ) if r["endpoint"] == "session")
    sdk = next(r for r in carve(SAZ) if r["endpoint"] == "sdk_click")
    atr = next(r for r in carve(SAZ) if r["endpoint"] == "attribution")
    idfa = str(uuid.uuid4()).upper()
    idfv = str(uuid.uuid4()).upper()
    dedupe = str(uuid.uuid4()).lower()
    fb = ("XZ" + uuid.uuid4().hex[:6].upper() + "-89FD-4894-85CF-"
          + uuid.uuid4().hex[:12].upper())
    installed = stamp()

    def base(m):
        m = dict(m)
        m.update({"primary_dedupe_token": dedupe, "idfv": idfv,
                  "fb_anon_id": fb, "installed_at": installed,
                  "created_at": stamp(), "sent_at": stamp(),
                  "started_at": stamp(), "session_count": "1",
                  "retry_count": "0", "att_status": str(att),
                  "enqueue_size": "0"})
        if att == 3:
            m["idfa"] = idfa
        else:
            m.pop("idfa", None)
        return m

    tok = base64.b64encode(os.urandom(420)).decode()[:560]
    sdkm = base(sdk["params"])
    sdkm["attribution_token"] = tok
    sdkm["source"] = "apple_ads"
    return {"idfa": idfa, "idfv": idfv,
            "session": base(ses["params"]), "sdk_click": sdkm,
            "attribution": base(atr["params"])}


def sign(mp, kind):
    return sg.sign_request(mp, kind, client_sdk=SDK,
                           headers_id="8", native_version="3.62.0")


def hdrs(auth=None):
    h = {"User-Agent": UA, "Client-Sdk": SDK, "Accept": "*/*",
         "Accept-Language": "en-US,en;q=0.9"}
    if auth:
        h["Authorization"] = auth
    return h


def one_install(att, dry=False):
    m = fresh_maps(att)
    print("=" * 70)
    print("INSTALL att_status=%d   idfa=%s idfv=%s"
          % (att, m["idfa"], m["idfv"]))
    res = {"att": att, "idfa": m["idfa"], "idfv": m["idfv"]}

    # device-match rule: on a DIRECT app.adjust.com link the matcher param
    # is idfa= (sub3 alone is just a publisher macro -- first run proved the
    # click does not join without idfa=).  Keep sub3 for the macro trail.
    url = LINK + "&idfa=" + m["idfa"] + "&sub3=" + m["idfa"]
    if dry:
        for kind in ("session", "sdk_click", "attribution"):
            a, blob = sign(m[kind], kind)
            print("  [dry %s] %d-B blob %s.." % (kind, len(blob),
                                                 blob.hex().upper()[:24]))
        return res

    r = requests.get(url, headers={"User-Agent": UA}, allow_redirects=False,
                     timeout=30)
    loc = r.headers.get("Location", "")
    print("[click] HTTP %s" % r.status_code)
    print("        loc: %s" % loc[:170])
    res["click"] = {"http": r.status_code, "location": loc[:500]}
    print("        sleeping CTIT %d s" % CTIT)
    time.sleep(CTIT)

    # session
    st = stamp()
    m["session"]["sent_at"] = st
    m["session"]["created_at"] = stamp(-0.02)
    auth, _ = sign(m["session"], "session")
    h = hdrs(auth)
    h["Content-Type"] = "application/x-www-form-urlencoded"
    r = requests.post(HOST + "/session", data=m["session"], headers=h,
                      timeout=30)
    print("[session] HTTP %s %s" % (r.status_code, r.text[:180]))
    try:
        sj = r.json()
    except ValueError:
        sj = {}
    res["session"] = {"http": r.status_code, "json": sj}
    adid = sj.get("adid")
    ask = sj.get("ask_in")

    # sdk_click (apple_ads, random token)
    m["sdk_click"]["sent_at"] = stamp()
    m["sdk_click"]["created_at"] = stamp(-0.02)
    auth, _ = sign(m["sdk_click"], "click")
    h = hdrs(auth)
    h["Content-Type"] = "application/x-www-form-urlencoded"
    r = requests.post(HOST + "/sdk_click", data=m["sdk_click"], headers=h,
                      timeout=30)
    print("[sdk_click random apple_ads token] HTTP %s %s"
          % (r.status_code, r.text[:180]))
    try:
        cj = r.json()
    except ValueError:
        cj = {}
    res["sdk_click"] = {"http": r.status_code, "json": cj}

    # attribution (armed by ask_in when present)
    if ask:
        time.sleep(ask / 1000.0 + 2)
    m["attribution"]["sent_at"] = stamp()
    m["attribution"]["created_at"] = stamp(-0.02)
    auth, _ = sign(m["attribution"], "attribution")
    r = requests.get(HOST + "/attribution", params=m["attribution"],
                     headers=hdrs(auth), timeout=30)
    try:
        aj = r.json()
    except ValueError:
        aj = {}
    a = aj.get("attribution") or {}
    print("[attribution] HTTP %s adid=%s" % (r.status_code, aj.get("adid")))
    print("   tracker=%s name=%s network=%s campaign=%s adgroup=%s"
          % (a.get("tracker_token"), a.get("tracker_name"),
             a.get("network"), a.get("campaign"), a.get("adgroup")))
    print("   engage=%s installed=%s reattr=%s"
          % (a.get("engagement_time"), a.get("installed_at"),
             a.get("is_reattributed")))
    res["attribution"] = {"http": r.status_code, "json": aj}
    verdict = "BOOKED " + str(a.get("tracker_token")) if (
        a.get("tracker_token") and a.get("network") not in
        ("Organic", None)) else ("No-consent/unattr" if a.get(
            "tracker_token") == "unattr" else "Organic/other")
    res["verdict"] = verdict
    print("VERDICT: %s" % verdict)
    return res


def main():
    dry = "--dry-run" in sys.argv
    out = {"link": LINK}
    for att in (3, 0):
        try:
            out["att%d" % att] = one_install(att, dry)
        except Exception as e:                              # noqa: BLE001
            out["att%d" % att] = {"error": repr(e)}
            print("ERROR:", repr(e))
        if not dry:
            time.sleep(5)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "run_install_hunch_result.json"), "w") as f:
        json.dump(out, f, indent=1)
    print("\nwritten: run_install_hunch_result.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
