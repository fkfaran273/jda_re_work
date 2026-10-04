"""new_install2.py — faithful fresh-install funnel, attempt 2.

Fixes vs attempt 1:
  * sdk_click referrer uses the reftag MINTED BY OUR OWN CLICK (parsed
    from the tracker's 302 Location), not the possibly-expired original.
  * click_time/install_begin_time = the ACTUAL stage-0 click wall time.
  * attribution polled patiently (4 polls over ~2.5 min; server said
    ask_in=2000 last time).

Funnel = exactly what a real install does:
  ad click -> Play Store redirect carrying adjust_reftag -> install ->
  SDK reads Play referrer -> sdk_click -> session -> attribution.
"""
import datetime
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import attrib_test
from attrib_test import COMMON, NoRedirect, log, log_lines, send

EC2 = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")


def dt_at(sec, ms="000"):
    return (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=sec)).strftime(
                "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


def tracker_click(gps_adid):
    click_id = "%032x" % random.getrandbits(128)
    url = ("https://app.adjust.com/1sd1lk6a"
           "?gps_adid=" + gps_adid +
           "&campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
           "&click_id=" + click_id +
           "&install_callback=" + EC2 + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
           "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
           "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
           "&event_callback_bfi71x=" + EC2 + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
           "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
           "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(req, timeout=30)
        code, loc = r.status, r.headers.get("Location")
    except urllib.error.HTTPError as e:
        code, loc = e.code, e.headers.get("Location")
    except Exception as e:
        log("  click FAIL %s" % e)
        return None
    log("  click -> %d" % code)
    reftag = None
    if loc:
        log("  loc: %s" % loc[:140])
        m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc)
        if m:
            reftag = m.group(1)
    return reftag


def main():
    new_adid = str(uuid.uuid4())
    new_uuid = str(uuid.uuid4())
    attrib_test.IDENT["gps_adid"] = new_adid
    attrib_test.IDENT["android_uuid"] = new_uuid
    log("NEW gps_adid     : %s" % new_adid)
    log("NEW android_uuid : %s" % new_uuid)

    log("== stage 0: tracker click ==")
    t_click = time.time()
    reftag = tracker_click(new_adid)
    log("  reftag from redirect: %s" % reftag)
    if not reftag:
        log("  !! no reftag — aborting")
        return
    time.sleep(3)

    log("== stage 1: /sdk_click (fresh reftag referrer) ==")
    ref = ("adjust_reftag=%s&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
           "&utm_content=vkm_0926_36&utm_term=penti_generic" % reftag)
    c = dict(attrib_test.IDENT)
    c.update(COMMON)
    c.update({
        "source": "install_referrer", "referrer": ref,
        "referrer_api": "google", "google_play_instant": "0",
        "install_version": "3.13.9",
        "click_time": dt_at(-(time.time() - t_click), "100"),
        "install_begin_time": dt_at(-(time.time() - t_click) + 2, "200"),
        "click_time_server": dt_at(-(time.time() - t_click) + 1, "100"),
        "install_begin_time_server": dt_at(-(time.time() - t_click) + 3,
                                           "200"),
        "session_count": "1", "subsession_count": "1",
        "session_length": "0", "time_spent": "0",
    })
    send("POST", "/sdk_click", c)
    time.sleep(3)

    log("== stage 2: /session (first session) ==")
    s = dict(attrib_test.IDENT)
    s.update(COMMON)
    s.update({"session_count": "1", "foreground": "1"})
    send("POST", "/session", s)
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
        log("== stage 3.%d: /attribution poll %d ==" % (i, i))
        send("GET", "/attribution", att)

    open("C:/Users/Apps/Downloads/com.penti.app/adj9/rev/new_install2.log",
         "w").write("\n".join(log_lines))
    print("saved new_install2.log", flush=True)


if __name__ == "__main__":
    main()
