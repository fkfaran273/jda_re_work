"""creditsea_poll_true_gaid.py — poll /attribution for the REAL converting
GAID (b9f64a28…, from the device's Ads settings) with OUR minted signature.

If the response carries the stored non-organic attribution (2439ti22 /
Tarsan1::Clickgency_03) -> our creditsea signature is VERIFIABLE and the
funnel problem is the flow (adjust_no_sdkclick=1).
If Organic -> our blob is unverifiable -> constants (D8 / claims 5.8.0).
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_creditsea as RC                     # noqa: E402
from signer_simple import auth_header          # noqa: E402
import signer_simple as sg                     # noqa: E402

GAID = "b9f64a28-7fd6-4cfd-a85a-2c272234b6e4"     # device Ads settings
AUID = "e66c7928-c85e-4882-8682-52992321dc73"     # ActivityState uuid

gaid0, params, chrome_ua, dalvik_ua, stamp = RC.load_device("device_g64.json")
params["gps_adid"] = GAID
params["android_uuid"] = AUID

ap = {"app_token": RC.APP_TOKEN, "gps_adid": GAID,
      "android_uuid": AUID,
      "activity_kind": "attribution", "initiated_by": "sdk",
      "needs_response_details": "1", "environment": "production",
      "api_level": params["api_level"], "app_version": params["app_version"],
      "created_at": stamp(time.time(), 77),
      "device_name": params["device_name"], "device_type": params["device_type"],
      "gps_adid_src": params["gps_adid_src"], "os_name": "android",
      "os_version": params["os_version"], "package_name": params["package_name"],
      "tracking_enabled": "1"}
code, body = RC.send("/attribution", ap, "attribution", dalvik_ua, method="GET")
print("TRUE-GAID POLL:", code, body[:500], flush=True)
try:
    att = json.loads(body).get("attribution", {})
    print("VERDICT:", att.get("network"), att.get("tracker_token"),
          "reattr=", att.get("is_reattributed"))
except Exception:
    pass
