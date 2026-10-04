"""creditsea_probe.py — is the signature gate active on creditsea endpoints?

1. send /session with a 1-bit-FLIPPED blob  -> if 400/error: gate is ACTIVE
                                              if 200: endpoint doesn't check
2. re-poll /attribution with a fresh signing -> async join?
"""
import json
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_creditsea as RC            # noqa: E402  (brings sg + constants)
import signer_simple as sg            # noqa: E402
from signer_simple import auth_header  # noqa: E402

gaid, params, chrome_ua, dalvik_ua, stamp = RC.load_device("device_g64.json")
t_click = time.time()

session = dict(params)
session.update({"session_count": "1", "session_length": "0",
                "time_spent": "0", "subsession_count": "1",
                "created_at": stamp(t_click + 7, 61),
                "sent_at": stamp(t_click + 7, 68)})

# --- 1. flipped-bit session ----------------------------------------------
blob, sec, info = sg.sign_request(session, "session")
print("[P] signed session sec=%d st=%s" % (sec, info["status"]), flush=True)
bad = bytearray(blob)
bad[-1] ^= 0x01
bad = bytes(bad)

import http.client
body = urllib.parse.urlencode(session).encode()
conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
conn.putrequest("POST", "/session", skip_host=1, skip_accept_encoding=1)
conn.putheader("Client-SDK", RC.CLIENT_SDK)
conn.putheader("Authorization", auth_header(bad))
conn.putheader("Content-Type", "application/x-www-form-urlencoded")
conn.putheader("User-Agent", dalvik_ua)
conn.putheader("Host", "app.adjust.com")
conn.putheader("Content-Length", str(len(body)))
conn.endheaders(body)
resp = conn.getresponse()
print("[P] FLIPPED-BIT /session -> %d %s"
      % (resp.status, resp.read()[:160]), flush=True)
conn.close()

# --- 2. clean re-send (control) -------------------------------------------
time.sleep(3)
auth = auth_header(blob)
conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
conn.putrequest("POST", "/session", skip_host=1, skip_accept_encoding=1)
conn.putheader("Client-SDK", RC.CLIENT_SDK)
conn.putheader("Authorization", auth)
conn.putheader("Content-Type", "application/x-www-form-urlencoded")
conn.putheader("User-Agent", dalvik_ua)
conn.putheader("Host", "app.adjust.com")
conn.putheader("Content-Length", str(len(body)))
conn.endheaders(body)
resp = conn.getresponse()
print("[P] CLEAN /session -> %d %s"
      % (resp.status, resp.read()[:160]), flush=True)
conn.close()

# --- 3. attribution re-poll ------------------------------------------------
time.sleep(5)
ap = {"app_token": RC.APP_TOKEN, "gps_adid": gaid,
      "android_uuid": session["android_uuid"],
      "activity_kind": "attribution", "initiated_by": "sdk",
      "needs_response_details": "1", "environment": "production",
      "api_level": params["api_level"], "app_version": params["app_version"],
      "created_at": stamp(time.time(), 77),
      "device_name": params["device_name"],
      "device_type": params["device_type"],
      "gps_adid_src": params["gps_adid_src"], "os_name": "android",
      "os_version": params["os_version"],
      "package_name": params["package_name"], "tracking_enabled": "1"}
code, out = RC.send("/attribution", ap, "attribution", dalvik_ua,
                    method="GET")
