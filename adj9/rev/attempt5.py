"""attempt5.py — click the network link EXACTLY as provided, substituting
ONLY {sub3} -> our fresh adid (keep {click_id} literal). Then run the full
session-first /sdk_click /attribution funnel with that same identity.

A non-rooted device install on THIS link reflects non-organic, so the
matching works here; replicate the exact click our earlier attempts didn't.
"""
import datetime
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import attrib_test
from attrib_test import COMMON, NoRedirect, log, log_lines, send, ts_now

# The EXACT link the user provided. Only {sub3} is replaced.
LINK = ("https://app.adjust.com/1sd1lk6a"
        "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
        "&click_id={click_id}"
        "&idfa={sub3}"
        "&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1"
        ".compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
        "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
        "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
        "&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1"
        ".compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
        "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
        "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")


def iso(now, off=0.0, ms="000"):
    return (now + datetime.timedelta(seconds=off)).strftime(
        "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


def do_click(url):
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "Mozilla/5.0 (Linux; Android 12; moto g42) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 "
                      "Mobile Safari/537.36"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(req, timeout=30)
        code, loc = r.status, r.headers.get("Location")
    except urllib.error.HTTPError as e:
        code, loc = e.code, e.headers.get("Location")
    except Exception as e:
        log("  click FAIL %s" % e)
        return None
    log("  click -> %d loc=%s" % (code, (loc or "")[:150]))
    if loc:
        m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc)
        if m:
            return m.group(1)
    return None


def main():
    adid = str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    attrib_test.IDENT["gps_adid"] = adid
    attrib_test.IDENT["android_uuid"] = auuid
    log("gps_adid     : %s" % adid)
    log("android_uuid : %s" % auuid)

    url = LINK.replace("{sub3}", adid)          # ONLY {sub3}; click_id stays
    log("== click (idfa=<adid>) ==")
    log("  %s" % url[:150])
    reftag = do_click(url)
    log("  reftag=%s" % reftag)
    t_click = time.time()
    now = datetime.datetime.now(datetime.timezone.utc)
    click_ts = iso(now, 0, "100")
    click_srv = iso(now, 1, "100")
    inst_begin = iso(now, 95, "200")
    inst_begin_srv = iso(now, 96, "200")
    installed = iso(now, 175, "400")
    attrib_test.IDENT["installed_at"] = installed
    attrib_test.IDENT["updated_at"] = installed
    if not reftag:
        log("!! no reftag — abort")
        return
    time.sleep(3)

    # SAZ order: /session first, then /sdk_click
    log("== 1: /session (first session) ==")
    s = dict(attrib_test.IDENT)
    s.update(COMMON)
    s["initiating_package_name"] = "com.android.vending"
    s.update({"session_count": "1", "foreground": "1"})
    send("POST", "/session", s)

    log("== 2: /sdk_click (referral) ==")
    ref = ("adjust_reftag=%s&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
           "&utm_content=vkm_0926_36&utm_term=penti_generic" % reftag)
    c = dict(attrib_test.IDENT)
    c.update(COMMON)
    c["initiating_package_name"] = "com.android.vending"
    c.update({
        "source": "install_referrer", "referrer": ref,
        "referrer_api": "google", "google_play_instant": "0",
        "install_version": "3.13.9",
        "click_time": click_ts, "click_time_server": click_srv,
        "install_begin_time": inst_begin,
        "install_begin_time_server": inst_begin_srv,
        "session_count": "1", "subsession_count": "1",
        "session_length": "0", "time_spent": "0",
    })
    send("POST", "/sdk_click", c)
    time.sleep(6)

    att = dict(attrib_test.IDENT)
    att.update({k: v for k, v in COMMON.items()
                if k in ("gps_adid_attempt", "gps_adid_src", "foreground",
                         "needs_response_details", "attribution_deeplink",
                         "tracking_enabled", "ui_mode",
                         "offline_mode_enabled")})
    att["initiated_by"] = "backend"
    for i, wait in enumerate([0, 30, 60, 90], 1):
        if wait:
            time.sleep(wait)
        log("== 3.%d: /attribution poll %d ==" % (i, i))
        send("GET", "/attribution", att)

    json.dump({"adid": adid, "reftag": reftag, "click_ts": click_ts},
              open("attempt5_state.json", "w"), indent=1)
    open("attempt5.log", "w").write("\n".join(log_lines))
    print("saved attempt5.log", flush=True)


if __name__ == "__main__":
    main()
