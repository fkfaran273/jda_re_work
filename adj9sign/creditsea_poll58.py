"""creditsea_poll58.py — poll /attribution for the device's adid (stored
non-organic 2439ti22) using OUR 5.8.0-law signature.

Returns the stored Tarsan1 attribution  -> our signature is VERIFIABLE.
Returns Organic                         -> still unverifiable.
"""
import sys, os, json, time, uuid
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "adj9", "rev", "creditsea"))

import run_creditsea as RC          # brings sg.DESC9 + the 5.8.0 claims patch
from signer_simple import auth_header
import signer_simple as sg
import http.client                  # noqa: E402  (used for the poll below)

GAID = "b9f64a28-7fd6-4cfd-a85a-2c272234b6e4"   # from the device Ads settings (the screenshot)
AUID = "1a018cc1-a8ff-46a7-a962-dd216570b28e"      # the SDK android_uuid (ActivityState)

gaid0, params, chrome_ua, dalvik_ua, stamp = RC.load_device("device_g64.json")
params["gps_adid"] = GAID
params["android_uuid"] = AUID

# the attribution request: the law keys the device's own poll carried
ap = {
    "app_token": RC.APP_TOKEN, "gps_adid": GAID, "android_uuid": AUID,
    "activity_kind": "attribution", "initiated_by": "sdk",
    "needs_response_details": "1", "environment": "production",
    "api_level": "31", "app_version": RC.CRED_VERSION,
    "created_at": stamp(time.time(), 77),
    "device_name": "moto g42", "device_type": "phone",
    "gps_adid_src": "service", "os_name": "android", "os_version": "12",
    "package_name": RC.CRED_PACKAGE, "tracking_enabled": "1",
    "country": "IN",
    # the law keys the server rebuilds from the WIRE body (the device's map
    # carries all of these — the claims match only if the wire does too):
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "client_sdk": "flutter5.8.0@android5.8.0",
    "headers_id": "10", "adj_signing_id": "1500000",
    "native_version": "5.0.0", "algorithm": "adj9",
}
auth = auth_header(sg.sign_request(ap, "attribution")[0])

q = urllib.parse.urlencode(ap)
conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
conn.putrequest("GET", "/attribution?" + q, skip_host=1, skip_accept_encoding=1)
conn.putheader("Client-SDK", RC.CLIENT_SDK)
conn.putheader("Authorization", auth)
conn.putheader("User-Agent", dalvik_ua)
conn.putheader("Host", "app.adjust.com")
conn.endheaders()
resp = conn.getresponse()
body = resp.read().decode("utf-8", "replace")
conn.close()
print("POLL:", resp.status, body[:420])
try:
    att = json.loads(body).get("attribution", {})
    print("VERDICT:", att.get("network"), att.get("tracker_token"),
          "| adid:", json.loads(body).get("adid", "?")[:16])
except Exception:
    pass
