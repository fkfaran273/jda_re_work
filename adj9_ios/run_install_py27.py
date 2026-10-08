# -*- coding: utf-8 -*-
"""run_install_py27.py -- adj9-iOS fresh-install funnel, Python 2.7
(stdlib httplib transport; TLS impersonation is py3-only).

run_install.py — adj9-iOS fresh-install funnel, signed with the SOLVED claims
law via adj9ios_pure.sign_request.

APP: niceoneautoios (Adjust app_token 1ri26ekrhwtc, bundle com.niceonesa),
adgroup link 67sl63t (campaign2 / crustalads).  Flow:
[optional click] -> signed /session -> signed /sdk_click -> signed /attribution.
Verdict: "No User Consent" = the non-organic state (user's rule).

Device identity (idfa / device_id / click_id) is FRESH per run; the rest of the
device profile below is fixed.  Python 3 (curl_cffi).  Python 2.7:
run_install_py27.py (regenerate with make_py27_adj9ios.py).
"""
import time, base64, sys, os, json, uuid
from datetime import datetime, timedelta
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode
import httplib as httpclient
import urllib2
from urllib import urlencode as _urlencode

class _Resp:
    def __init__(self, status, body, url=''):
        self.status_code = status
        self.text = body
        self.url = url
    def json(self):
        import json as _j
        return _j.loads(self.text)

class _Session:
    def get(self, url, headers=None, timeout=30, allow_redirects=True):
        c = httpclient.HTTPSConnection(url.split('/')[2], 443, timeout=timeout)
        p = '/' + url.split('/', 3)[3] if url.count('/') >= 3 else '/'
        c.request('GET', p, headers=headers or {})
        resp = c.getresponse()
        return _Resp(resp.status, resp.read(), url)
    def post(self, url, data=None, headers=None, timeout=30):
        c = httpclient.HTTPSConnection(url.split('/')[2], 443, timeout=timeout)
        p = '/' + url.split('/', 3)[3] if url.count('/') >= 3 else '/'
        if isinstance(data, dict):
            data = _urlencode(data)
        c.request('POST', p, body=data, headers=headers or {})
        resp = c.getresponse()
        return _Resp(resp.status, resp.read())

def cr_Session(impersonate=None):
    return _Session()

S = cr_Session()

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9ios_pure_py27 as sg

# ============================ CAMPAIGN (hardcoded, backend format) ======
CAMPAIGN = {
    "app_name": "niceoneautoios",
    "device_name": "iPhone12,3",        # iPhone 11 Pro
    "os_name": "ios",
    "os_version": "18.4.1",
    "head_phase": [0x09],
    "adjust": {
        "app_token": "1ri26ekrhwtc",
        "sdk": "ios5.8.0",              # Client-Sdk value AND the claims' client_sdk
        "adj_signing_id": "1500000",
        "headers_id": "10",
        "algorithm": "adj9",
        "native_version": "5.0.0",
        "adj_verification": "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb",  # ios-simulator service
    },
}
BUNDLE_ID = "com.niceonesa"
APP_VERSION = "3"
APP_VERSION_SHORT = "5.8.7"
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/18.0 Mobile/22E252 Safari/604.1")
ATT_STATUS = "3"        # device-faithful: "No User Consent"
COUNTRY, MCC, MNC, CURRENCY = "SA", "420", "03", "SAR"
OS_BUILD = "22E252"
SUB2 = "44wnfl41o1o72e195l"            # subAgent -> adgroup suffix
# google_odm click payload (captured blob + fresh push token)
ODM_INFO = ("AD8Dr_Gk4-uXpcUOu0gdLXIQk36DoO0jPXBmDfsLzYmHSW-pm3Kq2SUL2hVarv8RLbBQGwqB01"
            "agkJzLebQ")

LINK = ("https://app.adjust.com/67sl63t?campaign=campaign2&adgroup=Aff1_AQ_06_CRTADS_{sub2}"
        "&click_id={click_id}&idfa={sub3}&ip_address={sub6}"
        "&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
        "%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D{click_id}"
        "%26advertising_id%3Dcrustalads%26p_sub1%3Dadjust%26offer_id%3Dncycrymmp"
        "&event_callback_fveg9l=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
        "%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D{click_id}"
        "%26goal%3Dfveg9l%26advertising_id%3Dcrustalads%26p_sub1%3Dadjust%26offer_id%3Dncycrymmp")
CLICK_WAIT = 60        # seconds between click and session (the capture's shape)
DO_CLICK = True
ASA_TOKEN = "OJFoJanEPOna3i5lMK6pUjblEbnrAzx2DK5gErgL6jIiTH83OVAXtgJ0oZWRhloaKq+QhMBmOpy2IsaIEZmWaK769dIEAByXVgAAAVADAAAAywAAAICUPra7gDXzo5HZwSNvTGbPKHRVpPkeenLg4MV1M15nvWb8mVmZL4YKNlnDPLVOT4fFjg6xLithuVkpOXzGV3ItUk1LGwSYehqpSgOo0s2Z4ueudxw1t6BgwUKR+aaExEEiqT1JrrRHb3icR4no2IvTr5UUNBsl64R0NGyDiNH/1AAAAB/YJPS17/G1zC0XSzZ8eNw4WqycZbuQo/nn52lZEwv8AAAAnwEJSiTMGrB9Y6AShR52LHxLjXvrOwAAAIYGCaS34tvIjPBeXoJtXJjGitpqxg4DgEUdT1TfqTUM53xkBHRROya3rypsEYgJCpFY8RkHbCzyX0tT13eRBHcvMjjW+MoIfSmbs7Wnb80IMXZfL5t6NcPSBHOKrkC+3te+vuVQGuSXWYRZr2kBbmrX6QNsNlAKePbiEWL2Ti0OSSzYmdO/G/gABBEsTAQA="         # optional AdServices token (source=apple_ads sdk_click)
# manual override for experiments, e.g.  ATT_STATUS=3 ASA_TOKEN=xyz python run_install.py
ATT_STATUS = os.environ.get("ATT_STATUS", ATT_STATUS)
ASA_TOKEN = os.environ.get("ASA_TOKEN", ASA_TOKEN)
RANDOM_ASA_TOKEN = os.environ.get("RANDOM_ASA_TOKEN", "")   # generate a junk token to probe
# ========================================================================

now = datetime.utcnow() - timedelta(hours=3)

HOST = ("https://consent.adjust.com" if ATT_STATUS == "3" else "https://analytics.adjust.com")


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0300" % (dt.microsecond // 1000)


def hexid(n):
    return base64.b16encode(os.urandom(n)).decode("ascii")


def signed(method, path, params, kind):
    t = int(time.time()) + 1
    while time.time() < t:
        time.sleep(0.02)
    p = dict(params)
    p["created_at"] = p["sent_at"] = fmt(datetime.utcfromtimestamp(t - 3 * 3600))
    auth = sg.sign_request(p, kind, c=CAMPAIGN, second=t)
    h = {"User-Agent": UA, "Client-Sdk": CAMPAIGN["adjust"]["sdk"],
         "Authorization": "auth"}
    if method == "POST":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return S.post(HOST + path, data=p, headers=h, timeout=30)
    return S.get(HOST + path + "?" + urlencode(p), headers=h, timeout=30)


def main():
    att = ATT_STATUS
    idfa = str(uuid.uuid4()).upper()        # fresh device_id, doubles as click_id
    click_id = idfa
    idfv = str(uuid.uuid4()).upper()
    dedupe = str(uuid.uuid4())
    insider = hexid(16)
    installed = fmt(now - timedelta(minutes=1))
    started = fmt(now - timedelta(minutes=1))
    skan = fmt(now - timedelta(seconds=10))
    print("idfa/device_id:", idfa)
    print("idfv:", idfv)

    if LINK and DO_CLICK:
        ip = (S.get("https://api.ipify.org", timeout=15).text or "").strip() or "1.1.1.1"
        click_link = (LINK.replace("{sub2}", SUB2).replace("{click_id}", click_id)
                          .replace("{sub3}", idfa).replace("{sub6}", ip))
        print("click ip:", ip)
        r = S.get(click_link,
                  headers={"User-Agent": UA}, timeout=30, allow_redirects=True)
        print("[click]", r.status_code, "| final:", str(r.url)[:110])
        time.sleep(CLICK_WAIT)

    base = {"bundle_id": BUNDLE_ID, "app_token": CAMPAIGN["adjust"]["app_token"],
            "app_version": APP_VERSION, "app_version_short": APP_VERSION_SHORT,
            "device_name": CAMPAIGN["device_name"], "device_type": "iPhone",
            "os_name": "ios", "os_version": CAMPAIGN["os_version"],
            "os_build": OS_BUILD,
            "environment": "production", "idfv": idfv,
            "att_status": att,
            "country": COUNTRY, "mcc": MCC, "mnc": MNC, "currency": CURRENCY,
            "tracking_enabled": "1" if att == "3" else "0",
            "primary_dedupe_token": dedupe,
            "needs_response_details": "1", "attribution_deeplink": "1",
            "ff_odm_enabled": "1",
            "installed_at": installed, "started_at": started,
            "skadn_registered_at": skan,
            "last_skan_update": ('{"coarse_value":"low","lock_window":false,'
                                 '"timestamp":"%s","source":"sdk",'
                                 '"conversion_value":0}' % skan),
            "partner_params": json.dumps({"insider_id": insider},
                                         separators=(",", ":")),
            "send_in_background_enabled": "0"}
    if att == "3":        # ATT authorized: idfa rides along, host = consent.*
        base["idfa"] = idfa

    print("\n[1] /session (signed, solved claims) ...")
    r = signed("POST", "/session",
               dict(base, session_count="1", foreground="1", enqueue_size="0",
                    offline_mode_enabled="0", retry_count="0"), "session")
    print("[session]", r.status_code, "|", r.text[:200])
    adid = r.json().get("adid") if r.status_code == 200 and r.text.startswith("{") else None
    print("    adid:", adid)
    time.sleep(8)

    if ASA_TOKEN or RANDOM_ASA_TOKEN:
        tok = ASA_TOKEN or base64.b64encode(os.urandom(40)).decode("ascii").rstrip("=")
        print("\n[1b] /sdk_click (apple_ads + token%s) ..." %
              (", RANDOM" if RANDOM_ASA_TOKEN else ""))
        cp = dict(base, source="apple_ads", session_count="1",
                  subsession_count="1", session_length="0", time_spent="0",
                  attribution_token=tok,
                  click_time=fmt(datetime.utcnow() - timedelta(hours=1)))
        r = signed("POST", "/sdk_click", cp, "click")
        print("[sdk_click]", r.status_code, "|", r.text[:180])
        time.sleep(5)
    else:
        print("\n[2] /sdk_click (google_odm) ...")
        cp = dict(base, source="google_odm", session_count="1",
                  subsession_count="1", session_length="0", time_spent="0",
                  background="0", offline_mode_enabled="0",
                  odm_info=ODM_INFO, push_token=hexid(32))
        r = signed("POST", "/sdk_click", cp, "click")
        print("[sdk_click]", r.status_code, "|", r.text[:180])
        time.sleep(5)

    print("\n[3] /attribution (signed) ...")
    ap = dict(base, initiated_by="sdk")
    r = signed("GET", "/attribution", ap, "attribution")
    print("[attribution]", r.status_code, r.json())
    try:
        a = r.json().get("attribution", {})
        tk, name = a.get("tracker_token", ""), a.get("tracker_name", "")
        eng = a.get("engagement_time", "")
        print("    tracker:", tk, "|", name, "| engagement:", eng,
              "| reattr:", a.get("is_reattributed"))
        if "No User Consent" in name:
            print("\nVERDICT: NON-ORGANIC — 'No User Consent' state reached")
        elif name == "Organic":
            print("\nVERDICT: Organic (consented naming; unattributed)")
        else:
            print("\nVERDICT: BOOKED —", tk, "/", name)
    except Exception:
        print("    body:", r.text[:300])

    json.dump({"idfa": idfa, "idfv": idfv, "adid": adid, "resp": r.text[:500]},
              open(os.path.join(HERE, "run_install_result.json"), "w"), indent=1)


if __name__ == "__main__":
    main()