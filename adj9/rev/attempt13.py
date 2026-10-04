"""attempt13.py — the click that was originally asked for: gps_adid =
the REAL realme adid (ba56f461…) injected at click time (server-side
substitution is exactly what the ad network does), minting a NEW reftag
bound to that adid; then the signed funnel with that reftag. The device
record already exists (attempt 12 stage 0: adid 6f06b494…), so this
tests RE-ATTRIBUTION-by-adid — the one path attempts 1-12 never had:
a click whose device identity equals a genuine installed device."""
import json
import random
import re
import string
import time
import urllib.error
import urllib.request

import adj9_forge as F
from attempt12 import (ADID, AUID, PROF, UA, SKEW, COUPLED, rand_push)
from curl_cffi import requests as creq

CB = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"


def click_bound():
    url = ("https://app.adjust.com/1sd1lk6a"
           "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
           "&click_id={click_id}&idfa=" + ADID + "&gps_adid=" + ADID +
           "&install_callback=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
           "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
           "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
           "&event_callback_bfi71x=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
           "click_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust"
           "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")
    s = creq.Session(impersonate="chrome131_android")
    r = s.get(url, allow_redirects=False, timeout=30)
    loc = r.headers.get("location") or ""
    m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc)
    print("click -> %d reftag=%s" % (r.status_code, m.group(1) if m else None),
          flush=True)
    return m.group(1) if m else None


def call(label, endpoint, path, prof, method="POST"):
    sec = int(time.time()) + SKEW
    ov = {k: prof[k] for k in COUPLED if k in prof}
    ov["created_at"] = prof["created_at"]
    st, blob, h = F.make_signature(sec, ov)
    p = F.wire_params(endpoint, prof)
    p.update({k: v for k, v in prof.items() if k not in p})
    code, body = F.call(endpoint, path, p, blob, UA, method)
    print("%-10s mint=%s -> %d %s" % (label, st, code, body[:260]), flush=True)
    return code, body


def main():
    reftag = click_bound()
    assert reftag
    now = time.time()
    p0 = dict(PROF, push_token=rand_push())

    def mk(ep_extra=None, ms=666):
        sec = int(time.time()) + SKEW
        d = dict(p0)
        d["created_at"] = F.iso_plus0200(sec - 1, ms)
        d["sent_at"] = F.iso_plus0200(sec - 1, ms + 30)
        d["installed_at"] = d["updated_at"] = F.iso_plus0200(now - 3600, 774)
        d.update(ep_extra or {})
        return d

    print("== 1: /session (real device record, new session) ==")
    call("session", "session", "/session", mk({
        "session_count": "2", "foreground": "1"}))
    time.sleep(2)

    print("== 2: /sdk_click (reftag BOUND to this adid at click) ==")
    ref = ("adjust_reftag=%s&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
           "&utm_content=vkm_0926_36&utm_term=penti_generic" % reftag)
    call("sdk_click", "sdk_click", "/sdk_click", mk({
        "source": "install_referrer", "referrer": ref,
        "referrer_api": "google", "google_play_instant": "0",
        "click_time": F.iso_plus0200(now, 100),
        "click_time_server": F.iso_plus0200(now + 1, 100),
        "install_begin_time": F.iso_plus0200(now - 3540, 200),
        "install_begin_time_server": F.iso_plus0200(now - 3539, 200),
        "session_count": "2", "subsession_count": "1",
        "session_length": "0", "time_spent": "0"}))
    time.sleep(10)

    body_last = ""
    for i in range(1, 5):
        c, b = call("attr-%d" % i, "session", "/attribution", mk({
            "initiated_by": "backend", "session_count": "2"}), method="GET")
        body_last = b
        if '"Organic"' not in b and c == 200:
            break
        time.sleep(60 * i)

    ok = '"Organic"' not in body_last
    print("\nVERDICT:", "NON-ORGANIC" if ok else "Organic")
    json.dump({"reftag": reftag, "verdict": "NON-ORGANIC" if ok else "Organic",
               "last": body_last[:600]},
              open("attempt13_result.json", "w"), indent=1)


if __name__ == "__main__":
    main()
