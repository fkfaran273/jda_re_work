"""click_attrib.py — real tracker click + signed attribution flow.

Uses the real tracker token 1sd1lk6a (user-provided): GET the click URL
with the moto gps_adid so Adjust records a click bound to our adid, then
the signed sdk_click / session / attribution sequence (attrib_test.send).
"""
import random
import time
import urllib.request

from attrib_test import (send, ts_now, IDENT, COMMON, REFSTR, ADID,
                         NoRedirect, log, log_lines)

CLICK = ("https://app.adjust.com/1sd1lk6a"
         "?gps_adid=" + ADID +
         "&campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
         "&click_id=" + "%032x" % random.getrandbits(128) +
         "&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1"
         ".compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D"
         "{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital"
         "%26offer_id%3Dpntvkmdup1mmp"
         "&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1"
         ".compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D"
         "{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3D"
         "vkmdigital%26offer_id%3Dpntvkmdup1mmp")


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
        return r.status
    except urllib.error.HTTPError as e:
        log("  -> %d loc=%s body=%s" % (e.code, e.headers.get("Location"),
                                        e.read()[:200]))
        return e.code
    except Exception as e:
        log("  -> FAIL %s" % e)
        return -1


def main():
    log("== stage 0: REAL tracker click (1sd1lk6a, adid-bound) ==")
    log("  url: %s" % CLICK[:130] + "…")
    do_click()
    time.sleep(3)

    log("== stage 1: /sdk_click (reftag) ==")
    click = dict(IDENT)
    click.update(COMMON)
    click.update({
        "source": "install_referrer", "referrer": REFSTR,
        "referrer_api": "google", "google_play_instant": "0",
        "install_version": "3.13.9",
        "click_time": ts_now("100"), "install_begin_time": ts_now("200"),
        "session_count": "3", "subsession_count": "1",
        "session_length": "0", "time_spent": "0",
    })
    send("POST", "/sdk_click", click)
    time.sleep(3)

    log("== stage 2: /session ==")
    sess = dict(IDENT)
    sess.update(COMMON)
    sess.update({"session_count": "3", "foreground": "1"})
    send("POST", "/session", sess)
    time.sleep(5)

    log("== stage 3: /attribution poll 1 ==")
    att = dict(IDENT)
    att.update({k: v for k, v in COMMON.items()
                if k in ("gps_adid_attempt", "gps_adid_src", "foreground",
                         "needs_response_details", "attribution_deeplink",
                         "tracking_enabled", "ui_mode", "offline_mode_enabled")})
    att["initiated_by"] = "backend"
    send("GET", "/attribution", att)

    log("== stage 4: /attribution poll 2 (+25 s) ==")
    time.sleep(25)
    send("GET", "/attribution", att)

    open("C:/Users/Apps/Downloads/com.penti.app/adj9/rev/click_attrib.log",
         "w").write("\n".join(log_lines))
    print("saved click_attrib.log", flush=True)


if __name__ == "__main__":
    main()
