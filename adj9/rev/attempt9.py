"""attempt9.py — click via curl_cffi Chrome TLS impersonation (the piece
the funnel cannot control: click-side bot scoring), then the same
Dalvik-header signed funnel as attempt 8. If organic persists through
this too, the gate is something beyond transport/sig/params."""
import datetime
import re
import time
import uuid
from urllib.parse import urlencode

import attrib_test
from attempt8 import dalvik_send, iso, CB
from attrib_test import COMMON, log, log_lines
from curl_cffi import requests as creq


def click_chrome(adid):
    url = ("https://app.adjust.com/1sd1lk6a"
           "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
           "&click_id={click_id}&idfa=" + adid +
           "&install_callback=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
           "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
           "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
           "&event_callback_bfi71x=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
           "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
           "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")
    s = creq.Session(impersonate="chrome")
    r = s.get(url, allow_redirects=False, timeout=30)
    loc = r.headers.get("location") or ""
    log("  click -> %d %s" % (r.status_code, loc[:130]))
    m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc)
    return m.group(1) if m else None


def main():
    adid = str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    attrib_test.IDENT["gps_adid"] = adid
    attrib_test.IDENT["android_uuid"] = auuid
    log("gps_adid/android_uuid: %s / %s" % (adid[:13], auuid[:13]))

    now = datetime.datetime.now(datetime.timezone.utc)
    reftag = click_chrome(adid)
    log("click reftag=%s" % reftag)
    assert reftag
    click_ts = iso(now, 0, "100")
    attrib_test.IDENT["installed_at"] = iso(now, 190, "400")
    attrib_test.IDENT["updated_at"] = iso(now, 190, "400")

    log("== CTIT wait 250 s ==")
    time.sleep(250)

    log("== 1: /session (Chrome click + Dalvik headers) ==")
    s = dict(attrib_test.IDENT)
    s.update(COMMON)
    s["initiating_package_name"] = "com.android.vending"
    s.update({"session_count": "1", "foreground": "1"})
    dalvik_send("POST", "/session", s)
    time.sleep(1)

    log("== 2: /sdk_click ==")
    ref = ("adjust_reftag=%s&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
           "&utm_content=vkm_0926_36&utm_term=penti_generic" % reftag)
    c = dict(attrib_test.IDENT)
    c.update(COMMON)
    c["initiating_package_name"] = "com.android.vending"
    c.update({
        "source": "install_referrer", "referrer": ref,
        "referrer_api": "google", "google_play_instant": "0",
        "install_version": "3.13.9",
        "click_time": click_ts, "click_time_server": click_ts,
        "install_begin_time": iso(now, 120, "200"),
        "install_begin_time_server": iso(now, 120, "200"),
        "session_count": "1", "subsession_count": "1",
        "session_length": "0", "time_spent": "0",
    })
    dalvik_send("POST", "/sdk_click", c)
    time.sleep(6)

    att = dict(attrib_test.IDENT)
    att.update({k: v for k, v in COMMON.items()
                if k in ("gps_adid_attempt", "gps_adid_src", "foreground",
                         "needs_response_details", "attribution_deeplink",
                         "tracking_enabled", "ui_mode",
                         "offline_mode_enabled")})
    att["initiated_by"] = "backend"
    for i, wait in enumerate([0, 30, 60], 1):
        if wait:
            time.sleep(wait)
        log("== 3.%d: /attribution poll %d ==" % (i, i))
        dalvik_send("GET", "/attribution", att)

    open("attempt9.log", "w").write("\n".join(log_lines))
    print("saved attempt9.log", flush=True)


if __name__ == "__main__":
    main()
