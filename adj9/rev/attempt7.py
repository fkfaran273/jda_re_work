"""attempt7.py — click (idfa=adid + gps_adid, real click_id) + funnel with
the CAPTURED REAL #0 (tiled pointer record) + real H — the only input
class never tried on a crafted request. If position-parse gating was the
organic cause, this is the run that flips it.

Order: click -> CTIT wait (~4 min inside this run) -> /session ->
/sdk_click (fresh reftag from our own click) -> /attribution x4.
"""
import datetime
import json
import random
import re
import time
import urllib.error
import urllib.request
import uuid

import attrib_test
from attrib_test import COMMON, NoRedirect, log, log_lines, send

# use the REAL captured #0: fin_descs already provides it via D["descs"];
# just DON'T override by[0] the way sign_fresh/attrib_test do.
_orig_sign = attrib_test.sign


def sign_real0(created):
    import struct
    from collections import defaultdict
    from fin_vm2 import FinEx
    parts = [attrib_test.IDENT["adj_verification"].encode(),
             attrib_test.IDENT["android_uuid"].encode(),
             attrib_test.IDENT["api_level"].encode(),
             attrib_test.IDENT["app_token"].encode(),
             attrib_test.IDENT["app_version"].encode(),
             created.encode(),
             attrib_test.IDENT["device_name"].encode(),
             attrib_test.IDENT["device_type"].encode(),
             attrib_test.IDENT["environment"].encode(),
             attrib_test.IDENT["gps_adid"].encode()]
    raw = b"".join(parts)
    fetch = raw + b"\0" * ((-len(raw)) % 4)
    L10 = len(fetch) // 4
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
          for d in attrib_test.D["descs"]}
    # by[0] stays the REAL captured #0; H stays real (attrib_test.H)
    by[10] = (L10, fetch)
    by[7] = (1, struct.pack(">I", L10 << 2))
    descs = [(by[i][0], 0, by[i][1])
             for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]]
    sec = int(time.time())
    ex = FinEx(sec, descs)
    status = ex.run(max_steps=20_000_000)
    sinks = defaultdict(dict)
    for (sva, n, v) in ex.emit_trace:
        sinks[sva][n] = v
    am = sinks.get(0x5500000000, {})
    blob = b"".join(struct.pack(">I", am.get(i, 0)) for i in range(48))
    from vm_final import Random3
    r = Random3(sec)
    draws = [r.next() & 0xFFFFFFFF for _ in range(8)]
    hdr_ok = (struct.unpack(">4I", blob[:16]) ==
              tuple(draws[2 * i] ^ draws[2 * i + 1] for i in range(4)))
    return blob, status, hdr_ok


attrib_test.sign = sign_real0   # patch into send()'s signer

CB = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")


def iso(now, off=0.0, ms="000"):
    return (now + datetime.timedelta(seconds=off)).strftime(
        "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


def click(adid, cid):
    url = ("https://app.adjust.com/1sd1lk6a"
           "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
           "&click_id=" + cid + "&idfa=" + adid + "&gps_adid=" + adid +
           "&install_callback=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
           "click_id%3D" + cid + "%26p_sub1%3Dadjust%26advertising_id%3D"
           "vkmdigital%26offer_id%3Dpntvkmdup1mmp"
           "&event_callback_bfi71x=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fevents%3F"
           "click_id%3D" + cid + "%26goal%3Dbfi71x%26p_sub1%3Dadjust"
           "%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": UA})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(req, timeout=30)
        loc = r.headers.get("Location")
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location")
    m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc or "")
    return m.group(1) if m else None, loc


def main():
    adid = str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    cid = "%032x" % random.getrandbits(128)
    attrib_test.IDENT["gps_adid"] = adid
    attrib_test.IDENT["android_uuid"] = auuid
    log("gps_adid/android_uuid: %s / %s" % (adid, auuid))
    log("== click (idfa+gps_adid+real click_id) ==")
    now = datetime.datetime.now(datetime.timezone.utc)
    reftag, loc = click(adid, cid)
    log("  reftag=%s loc=%s" % (reftag, (loc or "")[:110]))
    assert reftag
    attrib_test.IDENT["installed_at"] = iso(now, 180, "400")
    attrib_test.IDENT["updated_at"] = iso(now, 180, "400")

    log("== CTIT wait 240 s ==")
    time.sleep(240)

    log("== 1: /session (REAL #0 signed) ==")
    s = dict(attrib_test.IDENT)
    s.update(COMMON)
    s["initiating_package_name"] = "com.android.vending"
    s.update({"session_count": "1", "foreground": "1"})
    send("POST", "/session", s)

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
        "click_time": iso(now, 0, "100"), "click_time_server": iso(now, 1, "100"),
        "install_begin_time": iso(now, 120, "200"),
        "install_begin_time_server": iso(now, 121, "200"),
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

    open("attempt7.log", "w").write("\n".join(log_lines))
    print("saved attempt7.log", flush=True)


if __name__ == "__main__":
    main()
