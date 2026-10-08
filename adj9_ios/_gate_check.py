# -*- coding: utf-8 -*-
"""Cross-verify the server gate: same request, corrupted signature.
Expect the silent 200 Organic fallback (proof Adjust verifies the claims envelope).
"""
import sys, os, time, base64, json
from datetime import datetime, timedelta
from urllib.parse import urlencode
from curl_cffi import requests as cr

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9ios_pure as sg

CAMPAIGN = {
    "app_name": "niceoneautoios",
    "device_name": "iPhone12,3",
    "os_name": "ios",
    "os_version": "18.4.1",
    "head_phase": [0x09],
    "adjust": {
        "app_token": "1ri26ekrhwtc",
        "sdk": "ios5.8.0",
        "adj_signing_id": "1500000",
        "headers_id": "10",
        "algorithm": "adj9",
        "native_version": "5.0.0",
        "adj_verification": "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb",
    },
}
BUNDLE_ID = "com.niceonesa"
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/18.0 Mobile/22E252 Safari/604.1")
LINK = ("https://app.adjust.com/67sl63t?campaign=campaign2&adgroup=Aff1_AQ_06_CRTADS_44wnfl41o1o72e195l"
        "&click_id={click_id}&idfa={sub3}&ip_address={sub6}"
        "&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
        "%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D{click_id}"
        "%26advertising_id%3Dcrustalads%26p_sub1%3Dadjust%26offer_id%3Dncycrymmp"
        "&event_callback_fveg9l=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
        "%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D{click_id}"
        "%26goal%3Dfveg9l%26advertising_id%3Dcrustalads%26p_sub1%3Dadjust%26offer_id%3Dncycrymmp")

MODE = sys.argv[1] if len(sys.argv) > 1 else "corrupt"   # good | corrupt | none
ATT_STATUS = sys.argv[2] if len(sys.argv) > 2 else "3"

S = cr.Session(impersonate="safari17_0")
HOST = ("https://consent.adjust.com" if ATT_STATUS == "3"
        else "https://analytics.adjust.com")


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0300" % (dt.microsecond // 1000)


def mangle(auth):
    """Flip one byte inside the base64 signature blob."""
    head, sig, tail = auth.split('"')[0], auth.split('"')[1], auth.rsplit('"', 1)[1]
    raw = bytearray(base64.b64decode(sig))
    raw[8] ^= 0x01
    return head + '"' + base64.b64encode(bytes(raw)).decode() + '"' + tail


def signed(method, path, params, kind):
    t = int(time.time()) + 1
    while time.time() < t:
        time.sleep(0.02)
    p = dict(params)
    now = fmt(datetime.utcnow())
    p["created_at"] = p["sent_at"] = now
    if MODE == "none":
        auth = None
    else:
        auth = sg.sign_request(p, kind, c=CAMPAIGN, second=t)
        if MODE == "corrupt":
            auth = mangle(auth)
    h = {"User-Agent": UA, "Client-Sdk": CAMPAIGN["adjust"]["sdk"]}
    if auth:
        h["Authorization"] = auth
    if method == "POST":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return S.post(HOST + path, data=p, headers=h, timeout=30)
    return S.get(HOST + path + "?" + urlencode(p), headers=h, timeout=30)


def hexid(n):
    return base64.b16encode(os.urandom(n)).decode("ascii")


def main():
    idfa = str(__import__("uuid").uuid4()).upper()
    idfv = str(__import__("uuid").uuid4()).upper()
    ip = (S.get("https://api.ipify.org", timeout=15).text or "").strip() or "1.1.1.1"
    link = (LINK.replace("{click_id}", idfa).replace("{sub3}", idfa)
                .replace("{sub6}", ip))
    S.get(link, headers={"User-Agent": UA}, timeout=30, allow_redirects=True)
    print("MODE=%s ATT_STATUS=%s  host=%s" % (MODE, ATT_STATUS, HOST))
    print("idfa:", idfa)
    time.sleep(60)

    now = datetime.utcnow()
    skan = fmt(now - timedelta(seconds=10))
    base = {
        "bundle_id": BUNDLE_ID, "app_token": CAMPAIGN["adjust"]["app_token"],
        "app_version": "3", "app_version_short": "5.8.7",
        "device_name": CAMPAIGN["device_name"], "device_type": "iPhone",
        "os_name": "ios", "os_version": CAMPAIGN["os_version"], "os_build": "22E252",
        "environment": "production", "idfv": idfv, "att_status": ATT_STATUS,
        "country": "SA", "mcc": "420", "mnc": "03", "currency": "SAR",
        "tracking_enabled": "1" if ATT_STATUS == "3" else "0",
        "primary_dedupe_token": str(__import__("uuid").uuid4()),
        "needs_response_details": "1", "attribution_deeplink": "1",
        "ff_odm_enabled": "1",
        "installed_at": fmt(now - timedelta(minutes=1)),
        "started_at": fmt(now - timedelta(minutes=1)),
        "skadn_registered_at": skan,
        "last_skan_update": ('{"coarse_value":"low","lock_window":false,'
                             '"timestamp":"%s","source":"sdk",'
                             '"conversion_value":0}' % skan),
        "partner_params": json.dumps({"insider_id": hexid(16)}, separators=(",", ":")),
        "send_in_background_enabled": "0",
    }
    if ATT_STATUS == "3":
        base["idfa"] = idfa

    r = signed("POST", "/session",
               dict(base, session_count="1", foreground="1", enqueue_size="0",
                    offline_mode_enabled="0", retry_count="0"), "session")
    print("[session]", r.status_code, "|", r.text[:200])
    time.sleep(8)
    r = signed("POST", "/sdk_click",
               dict(base, source="apple_ads", session_count="1", subsession_count="1",
                    session_length="0", time_spent="0",
                    attribution_token=base64.b64encode(os.urandom(40)).decode().rstrip("="),
                    click_time=fmt(now - timedelta(hours=1))), "click")
    print("[sdk_click]", r.status_code, "|", r.text[:200])
    time.sleep(5)
    r = signed("GET", "/attribution", dict(base, initiated_by="sdk"), "attribution")
    print("[attribution]", r.status_code, "|", r.text[:400])
    try:
        a = r.json().get("attribution", {})
        name = a.get("tracker_name")
        print("\n  tracker_token:", a.get("tracker_token"))
        print("  tracker_name :", name)
        if name == "Organic":
            print("  -> GATE PROVEN: signature not accepted, silent Organic fallback")
        elif name and "No User Consent" in name:
            print("  -> claims accepted, att_status=0 state")
        elif name:
            print("  -> claims accepted, BOOKED")
    except Exception as e:
        print("  json err", e)
    json.dump({"mode": MODE, "att_status": ATT_STATUS, "idfa": idfa,
               "resp": r.text[:500]},
              open(os.path.join(HERE, "_gate_%s.json" % MODE), "w"), indent=1)


if __name__ == "__main__":
    main()