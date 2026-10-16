# -*- coding: utf-8 -*-
"""replay_hunchdating.py -- the attribution replay rule on the hunch-dating
iOS capture (hunchdatingiosauto_newapp_1appril2026 (2).saz, extracted to
saz_hunchdating/).  Same G / O / ARM shape as replay_lululemon.py.

G    genuine verbatim (carved query + captured Authorization)
O    ours, same map, fresh second + nonce
ARM  our signed /session -> wait ask_in -> our signed /attribution
"""
import json
import os
import re
import sys
import time
import urllib.parse

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg  # noqa: E402

RAW = os.path.join(HERE, "saz_hunchdating", "raw")
HOST = "https://analytics.adjust.com"
SDK = "flutter5.5.0@ios5.5.0"
HID, NV = "8", "3.62.0"


def read(n):
    return open(os.path.join(RAW, "%02d_c.txt" % n), encoding="utf-8",
                errors="replace", newline="").read()


def resp(n):
    t = open(os.path.join(HERE, "saz_hunchdating", "raw",
                          "%02d_s.txt" % n), encoding="utf-8",
             errors="replace", newline="").read()
    parts = t.split("\r\n\r\n", 1)
    return parts[1].strip() if len(parts) > 1 else t.strip()


def carve(n):
    """-> (query, auth, params) for a GET row."""
    t = read(n)
    line0 = t.split("\r\n", 1)[0]
    q = line0.split(" ", 2)[1].split("?", 1)[1].rsplit(" ", 1)[0]
    head = t.split("\r\n\r\n", 1)[0]
    auth = [l.split(": ", 1)[1] for l in head.split("\r\n")
            if l.startswith("Authorization")][0]
    return q, auth, dict(urllib.parse.parse_qsl(q, keep_blank_values=True))


LOGGED_ATTR = 37
REASK_ATTR = 44
SESS, CLICK = 20, 21

q, auth, params = carve(LOGGED_ATTR)
old_resp = resp(LOGGED_ATTR)
old_resp2 = resp(REASK_ATTR)
print("== logged (sid row %d):" % LOGGED_ATTR)
print("   ", old_resp[:260])
print("== re-ask  (sid row %d):" % REASK_ATTR)
print("   ", old_resp2[:260])
print("   adid:", params.get("bundle_id"), "| second window from sent_at:",
      params.get("sent_at"))

UA = [l for l in read(LOGGED_ATTR).split("\r\n\r\n", 1)[0].split("\r\n")
      if l.startswith("User-Agent")][0].split(": ", 1)[1]
print("   UA:", UA[:90], "| app_token:", params.get("app_token"))


def hdrs(auth=None):
    h = {"User-Agent": UA, "Client-Sdk": SDK, "Accept": "*/*"}
    if auth:
        h["Authorization"] = auth
    return h


out = {}

# ---- G ------------------------------------------------------------------
st, body = requests.get(HOST + "/attribution", params=None, headers=hdrs(auth),
                        timeout=30).text, None
r = requests.get(HOST + "/attribution?" + q, headers=hdrs(auth), timeout=30)
out["G"] = {"http": r.status_code, "json": r.json()}
print("== G genuine verbatim ->", r.status_code, r.text[:170], flush=True)

# ---- O ------------------------------------------------------------------
now = time.time()
p2 = dict(params)
import datetime as _dt
tz = _dt.timezone(_dt.timedelta(hours=3))
p2["created_at"] = _dt.datetime.fromtimestamp(now, tz).strftime(
    "%Y-%m-%dT%H:%M:%S.") + "%03dZ+0300" % int(now % 1 * 1000)
p2["sent_at"] = _dt.datetime.fromtimestamp(now + 0.02, tz).strftime(
    "%Y-%m-%dT%H:%M:%S.") + "%03dZ+0300" % int(now % 1 * 1000)
auth_o = sg.sign_request(p2, "attribution", second=int(now),
                         client_sdk=SDK,
                         headers_id=HID, native_version=NV)[0]
qo = urllib.parse.urlencode(p2, quote_via=urllib.parse.quote)
r2 = requests.get(HOST + "/attribution?" + qo, headers=hdrs(auth_o),
                  timeout=30)
out["O"] = {"http": r2.status_code, "json": r2.json()}
print("== O ours fresh sig ->", r2.status_code, r2.text[:170], flush=True)

# ---- ARM ----------------------------------------------------------------
sp = None
# build the session map from the capture's own session row body
st_t = read(SESS)
sbody = st_t.split("\r\n\r\n", 1)[1].strip()
sm = dict(urllib.parse.parse_qsl(sbody, keep_blank_values=True))
sauth = [l.split(": ", 1)[1] for l in st_t.split("\r\n\r\n", 1)[0].split("\r\n")
         if l.startswith("Authorization")][0]
sm2 = dict(sm)
sm2["created_at"] = p2["created_at"]
sm2["sent_at"] = p2["sent_at"]
auth_s = sg.sign_request(sm2, "session", second=int(now), client_sdk=SDK,
                         headers_id=HID, native_version=NV)[0]
rs = requests.post(HOST + "/session", data=sm2, headers=hdrs(auth_s),
                   timeout=30)
out["ARM_session"] = {"http": rs.status_code, "json": rs.json()}
print("== ARM session ->", rs.status_code, rs.text[:170], flush=True)
try:
    ai = rs.json().get("ask_in")
except Exception:
    ai = None
if ai:
    time.sleep(max(2.0, ai / 1000.0 + 1.0))
r3 = requests.get(HOST + "/attribution?" + qo, headers=hdrs(auth_o),
                  timeout=30)
out["ARM"] = {"http": r3.status_code, "json": r3.json()}
print("== ARM attribution ->", r3.status_code, r3.text[:170], flush=True)

json.dump(out, open(os.path.join(HERE, "replay_hunchdating_result.json"), "w"),
          indent=1)
print()
print("G status", out["G"]["http"], "| O status", out["O"]["http"],
      "| ARM", out["ARM"]["http"])
print("G attr:", json.dumps(out["G"]["json"].get("attribution"))[:200])
print("O attr:", json.dumps(out["O"]["json"].get("attribution"))[:200])
same = (out["G"]["http"] == out["O"]["http"]
        and out["G"]["json"].get("attribution")
        == out["O"]["json"].get("attribution"))
print("O == G:", same)
