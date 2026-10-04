# send_minted5.py - THE decisive test: device-minted blob (real signer, OUR map)
# sent verbatim. If booked -> device-oracle = permanent signing solution.
import base64
import http.client
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sig_probe as sp
import device_funnel as df

OUT = os.path.join(HERE, "send_minted5_result.json")

a = json.load(open(r"C:\Users\Apps\AppData\Local\Temp\mo1.json", encoding="utf-16"))
b2 = json.load(open(r"C:\Users\Apps\AppData\Local\Temp\mo2.json", encoding="utf-16"))
val = {}
for k, v in a["mapPairs"]:
    val.setdefault(k, v)
gps, auid = val["gps_adid"], val["android_uuid"]
print("minted blob gps=%s auid=%s stamp=%s" % (gps, auid, a["stamp"]))

df.install_proxy("http://127.0.0.1:8888")
os.environ["ADJ_INSECURE"] = "1"


def send_auth(url, blob, auth_value):
    pr = urllib.parse.urlsplit(url)
    path = pr.path + ("?" + pr.query if pr.query else "")
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    conn.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth_value)
    conn.putheader("User-Agent", sp.fc.UA)
    conn.putheader("Host", pr.hostname)
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


q = {
    "gps_adid": gps, "android_uuid": auid,
    "gps_adid_src": val["gps_adid_src"], "gps_adid_attempt": val["gps_adid_attempt"],
    "api_level": val["api_level"], "app_version": val["app_version"],
    "app_token": val["app_token"], "os_name": val["os_name"],
    "os_version": val["os_version"], "device_name": val["device_name"],
    "device_type": val["device_type"], "environment": val["environment"],
    "package_name": val["package_name"], "created_at": val["created_at"],
    "sent_at": val["sent_at"], "installed_at": val["installed_at"],
    "updated_at": val["updated_at"], "session_count": val["session_count"],
    "tracking_enabled": val["tracking_enabled"], "initiated_by": "backend",
    "needs_response_details": val["needs_response_details"],
    "attribution_deeplink": val["attribution_deeplink"],
    "offline_mode_enabled": val["offline_mode_enabled"],
    "device_manufacturer": val["device_manufacturer"],
    "hardware_name": val["hardware_name"], "os_build": val["os_build"],
    "language": val["language"], "cpu_type": val["cpu_type"],
    "display_width": val["display_width"], "display_height": val["display_height"],
    "screen_size": val["screen_size"], "screen_format": val["screen_format"],
    "screen_density": val["screen_density"], "connectivity_type": val["connectivity_type"],
    "ui_mode": val["ui_mode"], "foreground": val["foreground"],
    "initiating_package_name": val["initiating_package_name"],
    "store_name_from_system": val["store_name_from_system"],
}
url = "https://app.adjust.com/attribution?" + urllib.parse.urlencode(q)
runs = []
for label, src in (("M1 minted blob verbatim", a), ("M2 minted blob verbatim", b2)):
    blob = base64.b64decode(src["blobB64"])
    auth = src["auth"]
    try:
        s, body = send_auth(url, blob, auth)
        v = sp.verdict(s, body)
    except Exception as e:
        s, v = "ERR", "%s: %s" % (type(e).__name__, e)
    print("%-28s -> %s %s" % (label, s, v), flush=True)
    runs.append({"label": label, "http": s, "verdict": v})
    time.sleep(2)
json.dump({"gps": gps, "auid": auid, "url": url, "runs": runs},
          open(OUT, "w"), indent=1)
print("saved", OUT)
