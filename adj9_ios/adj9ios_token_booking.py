"""Token-replay booking: fresh device + the capture's Oct-5 attribution_token
(same 1sd1lk6a link) + signed sdk_click (source=apple_ads) + signed attribution.
Target: booked under penti_install / 1sd1lk6a, EC2 postback fires."""
import time, base64, sys, os, json, uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode, unquote
from curl_cffi import requests as cr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj9ios_pure as sg
import adj9_claims_law as law

ADJ_V = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"
S = cr.Session(impersonate="safari17_0")
now = datetime.utcnow() - timedelta(hours=3)


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0300" % (dt.microsecond // 1000)


def signed(method, path, params, kind):
    t = int(time.time()) + 1
    while time.time() < t:
        time.sleep(0.02)
    p = dict(params)
    p["created_at"] = p["sent_at"] = fmt(datetime.utcfromtimestamp(t - 3 * 3600))
    claims = law.build_claims(p, kind, ADJ_V)[0].encode("latin1")
    blob = sg.sign_request(p, kind, second=t, nonce4=os.urandom(4),
                           device_name="iPhone12,1", adj_verification=ADJ_V)[0]
    auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), ADJ_V))
    h = {"User-Agent": "Penti/8 CFNetwork/3860.600.12 Darwin/25.5.0",
         "Client-Sdk": "ios5.8.0", "Authorization": auth}
    if method == "POST":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return S.post("https://consent.adjust.com" + path, data=p,
                      headers=h, timeout=30)
    return S.get("https://consent.adjust.com" + path + "?" + urlencode(p),
                 headers=h, timeout=30)


wire = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7_work\_penti_wire.json"))
TOKEN = unquote(wire[1]["params"]["attribution_token"])   # the Oct-5 penti token
CLICK_ID = "replay-" + str(uuid.uuid4())[:8]
idfa = str(uuid.uuid4()).upper()          # FRESH device presenting the capture's token
idfv = str(uuid.uuid4()).upper()
print("idfa (fresh):", idfa)
print("token head  :", TOKEN[:60])

# 1. the click (binding the same click_id/idfa shape as the capture)
link = ("https://app.adjust.com/1sd1lk6a?campaign=penti_install&adgroup=vkm_0926_36"
        "&creative=penti_generic&click_id=" + CLICK_ID + "&idfa=" + idfa)
r = S.get(link, headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 "
                         "like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                         "Version/16.6 Mobile/15E148 Safari/604.1"},
          timeout=30, allow_redirects=True)
print("[click]", r.status_code, flush=True)
time.sleep(60)

base = {"bundle_id": "com.penti.PentiApp", "app_token": "jut9tib0eeps",
        "app_version": "8", "app_version_short": "2.35.0",
        "device_name": "iPhone12,1", "device_type": "iPhone",
        "os_name": "ios", "os_version": "26.5", "environment": "production",
        "idfa": idfa, "idfv": idfv, "att_status": "3", "tracking_enabled": "1",
        "fb_anon_id": "XZ" + str(uuid.uuid4()).upper(),
        "primary_dedupe_token": str(uuid.uuid4()).upper(),
        "needs_response_details": "1", "attribution_deeplink": "1",
        "installed_at": fmt(now - timedelta(minutes=2)),
        "started_at": fmt(now - timedelta(minutes=2)),
        "session_count": "1", "foreground": "1",
        "send_in_background_enabled": "0", "enqueue_size": "0",
        "offline_mode_enabled": "0", "retry_count": "0"}

print("\n[1] /session (signed) ...", flush=True)
r = signed("POST", "/session", base, "session")
print("[session]", r.status_code, "|", r.text[:150], flush=True)
time.sleep(6)

print("\n[2] /sdk_click (signed, apple_ads + capture token) ...", flush=True)
cp = {k: v for k, v in base.items() if k not in ("session_count", "enqueue_size")}
cp["click_time"] = fmt(now - timedelta(hours=1))
cp["source"] = "apple_ads"
cp["attribution_token"] = TOKEN
r = signed("POST", "/sdk_click", cp, "click")
print("[sdk_click]", r.status_code, "|", r.text[:200], flush=True)
time.sleep(6)

print("\n[3] /attribution (signed) ...", flush=True)
ap = {k: v for k, v in base.items()
      if k not in ("session_count", "enqueue_size", "foreground",
                   "send_in_background_enabled", "offline_mode_enabled",
                   "retry_count")}
ap["initiated_by"] = "backend"
r = signed("GET", "/attribution", ap, "attribution")
print("[attribution]", r.status_code, flush=True)
try:
    a = r.json().get("attribution", {})
    tk, name = a.get("tracker_token", ""), a.get("tracker_name", "")
    print("    tracker:", tk, "|", name, "| engagement:", a.get("engagement_time"),
          "| reattr:", a.get("is_reattributed"), flush=True)
    if name == "Organic":
        print("\nVERDICT: Organic — the Oct-5 token no longer decodes")
    elif "No User Consent" in name:
        print("\nVERDICT: NON-ORGANIC STATE (unattr) — token decoded, no consent booking")
    else:
        print("\nVERDICT: *** BOOKED UNDER", tk, "/", name, "***")
except Exception:
    print("    body:", r.text[:300])