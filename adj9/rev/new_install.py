"""new_install.py — simulate a FRESH INSTALL for a brand-new advertising id.

New identity: fresh gps_adid + fresh android_uuid (only id-type fields
change — that is what install matching keys on). Sequence mirrors a real
first install:
  0. GET the real tracker (1sd1lk6a) with the new adid  -> click recorded
  1. POST /sdk_click  (Play install-referrer shape, campaign reftag)
  2. POST /session    (session_count=1, fresh installed_at)
  3. GET  /attribution polled 3x
Expected: first session of a new adid -> attributed to tracker 1sd1lk6a
(non-organic) and the install postback fires to the offer's callback.

The signer's embedded claims are patched to the new identity so the
signature matches the request params (attrib_test.sign reads the
module-level IDENT at call time).
"""
import datetime
import random
import time
import urllib.error
import urllib.request
import uuid

import attrib_test
from attrib_test import (COMMON, NoRedirect, log, log_lines, send,
                         ts_now)

NEW_GPS_ADID = str(uuid.uuid4())
NEW_UUID = str(uuid.uuid4())
CLICK_ID = "%032x" % random.getrandbits(128)

REFSTR = ("adjust_reftag=cTZk0zc2x78Ko&utm_source=VKM+Digital+Yeni"
          "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")

EC2 = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
CLICK = ("https://app.adjust.com/1sd1lk6a"
         "?gps_adid=" + NEW_GPS_ADID +
         "&campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
         "&click_id=" + CLICK_ID +
         "&install_callback=" + EC2 + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
         "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
         "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
         "&event_callback_bfi71x=" + EC2 + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
         "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
         "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")


def dt_off(sec, ms):
    return (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=sec)).strftime(
                "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


def do_click():
    req = urllib.request.Request(CLICK, method="GET", headers={
        "User-Agent": "Mozilla/5.0 (Linux; Android 12; moto g42) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 "
                      "Mobile Safari/537.36"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(req, timeout=30)
        log("  -> %d loc=%s" % (r.status, r.headers.get("Location")))
        r.read(200)
    except urllib.error.HTTPError as e:
        log("  -> %d loc=%s body=%s" % (e.code, e.headers.get("Location"),
                                        e.read()[:200]))
    except Exception as e:
        log("  -> FAIL %s" % e)


def main():
    # patch the signer identity so claims == request params
    attrib_test.IDENT["gps_adid"] = NEW_GPS_ADID
    attrib_test.IDENT["android_uuid"] = NEW_UUID

    log("NEW gps_adid     : %s" % NEW_GPS_ADID)
    log("NEW android_uuid : %s" % NEW_UUID)
    log("click_id         : %s" % CLICK_ID)

    log("== stage 0: tracker click (new-adid bound) ==")
    log("  %s" % (CLICK[:120] + "…"))
    do_click()
    time.sleep(3)

    log("== stage 1: /sdk_click (install_referrer) ==")
    c = dict(attrib_test.IDENT)
    c.update(COMMON)
    c.update({
        "source": "install_referrer", "referrer": REFSTR,
        "referrer_api": "google", "google_play_instant": "0",
        "install_version": "3.13.9",
        "click_time": dt_off(-30, "100"),
        "install_begin_time": dt_off(-25, "200"),
        "click_time_server": dt_off(-29, "100"),
        "install_begin_time_server": dt_off(-24, "200"),
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
    time.sleep(5)

    att = dict(attrib_test.IDENT)
    att.update({k: v for k, v in COMMON.items()
                if k in ("gps_adid_attempt", "gps_adid_src", "foreground",
                         "needs_response_details", "attribution_deeplink",
                         "tracking_enabled", "ui_mode",
                         "offline_mode_enabled")})
    att["initiated_by"] = "backend"

    log("== stage 3: /attribution poll 1 ==")
    send("GET", "/attribution", att)

    log("== stage 4: /attribution poll 2 (+25 s) ==")
    time.sleep(25)
    send("GET", "/attribution", att)

    log("== stage 5: /attribution poll 3 (+40 s) ==")
    time.sleep(40)
    send("GET", "/attribution", att)

    open("C:/Users/Apps/Downloads/com.penti.app/adj9/rev/new_install.log",
         "w").write("\n".join(log_lines))
    print("saved new_install.log", flush=True)


if __name__ == "__main__":
    main()
