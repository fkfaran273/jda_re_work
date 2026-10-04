"""attempt3_phase_b.py — session-first install funnel after CTIT wait.

Run >= ~3 min after attempt3_phase_a.py. Order per SAZ ground truth:
first /session, then /sdk_click (28 ms apart in reality), then
attribution polls. Params: fresh installed_at, correct
initiating_package_name, reftag minted by OUR click.
"""
import json
import time

import attrib_test
from attrib_test import send, log, log_lines

S = json.load(open("attempt3_state.json"))

attrib_test.IDENT["gps_adid"] = S["gps_adid"]
attrib_test.IDENT["android_uuid"] = S["android_uuid"]
attrib_test.IDENT["installed_at"] = S["installed_at"]
attrib_test.IDENT["updated_at"] = S["updated_at"]


def base():
    p = dict(attrib_test.IDENT)
    p.update(attrib_test.COMMON)
    p.pop("initiatingPackage_name", None)          # camelCase typo
    p["initiating_package_name"] = "com.android.vending"
    return p


REF = ("adjust_reftag=%s&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
       "&utm_content=vkm_0926_36&utm_term=penti_generic" % S["reftag"])

log("gps_adid  : %s" % S["gps_adid"])
log("reftag    : %s (click %s)" % (S["reftag"], S["click_time"]))
log("installed_at (claimed): %s" % S["installed_at"])

log("== 1: /session (first session, session-first order) ==")
s = base()
s.update({"session_count": "1", "foreground": "1"})
send("POST", "/session", s)

log("== 2: /sdk_click (immediately after, SAZ order) ==")
c = base()
c.update({
    "source": "install_referrer", "referrer": REF,
    "referrer_api": "google", "google_play_instant": "0",
    "install_version": "3.13.9",
    "click_time": S["click_time"],
    "click_time_server": S["click_time_server"],
    "install_begin_time": S["install_begin_time"],
    "install_begin_time_server": S["install_begin_time_server"],
    "session_count": "1", "subsession_count": "1",
    "session_length": "0", "time_spent": "0",
})
send("POST", "/sdk_click", c)
time.sleep(6)

att = dict(attrib_test.IDENT)
att.update({k: v for k, v in attrib_test.COMMON.items()
            if k in ("gps_adid_attempt", "gps_adid_src", "foreground",
                     "needs_response_details", "attribution_deeplink",
                     "tracking_enabled", "ui_mode", "offline_mode_enabled")})
att["initiated_by"] = "backend"

for i, wait in enumerate([0, 30, 60], 1):
    if wait:
        time.sleep(wait)
    log("== 3.%d: /attribution poll %d ==" % (i, i))
    send("GET", "/attribution", att)

open("attempt3.log", "w").write("\n".join(log_lines))
print("saved attempt3.log", flush=True)
