"""attempt11.py v2 — PRIOR-INSTALL device test (the one difference we
could never manufacture with fresh adids).

Device: SAZ capture's real OnePlus DN2101 (gps_adid 1a89cb29-…,
android_uuid 117d0470-…, installed_at 2026-09-08T14:00:02.774Z+0530,
one session then 6 days inactive). Claims built +0530 consistently.
Click the re-engagement tracker for THAT adid, then session ->
sdk_click (reftag referrer, format per user's example) -> poll
attribution. If re-engagement semantics need prior install + inactivity,
this is the configuration that must flip to non-organic /
is_reattributed=true."""
import datetime
import json
import re
import struct
import time
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict

import attrib_test
from attrib_test import log, log_lines
from fin_vm2 import FinEx
from curl_cffi import requests as creq
from vm_final import Random3

ADID = "1a89cb29-3590-418c-ae2b-122bbd93e38f"
AUID = str(uuid.uuid4())   # fresh SDK uuid; real GAID is the match key,
                           # reusing the captured android_uuid could dedup
INST = "2026-09-08T14:00:02.774Z+0530"
IDENT = {
    "gps_adid": ADID, "android_uuid": AUID, "app_token": "jut9tib0eeps",
    "api_level": "30", "app_version": "3.12.1", "device_name": "DN2101",
    "device_manufacturer": "OnePlus", "device_type": "phone",
    "environment": "production", "hardware_name": "DN2101_11_A.20",
    "os_build": "RP1A.200720.011", "os_name": "android", "os_version": "11",
    "package_name": "com.penti.app", "installed_at": INST, "updated_at": INST,
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
}
UA = ("Dalvik/2.1.0 (Linux; U; Android 11; DN2101 Build/RP1A.200720.011)")
CB = "http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com"
D = json.load(open(attrib_test.__file__.replace("attrib_test.py",
                                                "fin_descs.json")))
S0 = 0x5500000000


def now530(off=0.0, ms=0):
    dt = datetime.datetime.now(datetime.timezone.utc) + \
        datetime.timedelta(hours=5, minutes=30, seconds=off)
    return "%s.%03dZ+0530" % (dt.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def sign(created):
    parts = [IDENT["adj_verification"].encode(), IDENT["android_uuid"].encode(),
             IDENT["api_level"].encode(), IDENT["app_token"].encode(),
             IDENT["app_version"].encode(), created.encode(),
             IDENT["device_name"].encode(), IDENT["device_type"].encode(),
             IDENT["environment"].encode(), IDENT["gps_adid"].encode()]
    raw = b"".join(parts)
    fetch = raw + b"\0" * ((-len(raw)) % 4)
    L10 = len(fetch) // 4
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
          for d in D["descs"]}
    d0 = bytearray(144)
    d0[140:144] = struct.pack(">I", uuid.uuid4().int & 0xFFFFFFFF)
    by[0] = (36, bytes(d0))
    by[10] = (L10, fetch)
    by[7] = (1, struct.pack(">I", L10 << 2))
    descs = [(by[i][0], 0, by[i][1])
             for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]]
    sec = int(time.time())
    ex = FinEx(sec, descs)
    status = ex.run(max_steps=20_000_000)
    out = {}
    for (s, n, v) in ex.emit_trace:
        out[(s, n)] = v
    blob = b"".join(struct.pack(">I", out.get((S0, k), 0)) for k in range(48))
    R = Random3(sec)
    d = [R.next() for _ in range(8)]
    law = b"".join(struct.pack(">I", d[2 * i] ^ d[2 * i + 1])
                   for i in range(4))
    log("  sig %s law=%s" % (status, blob[:16] == law))
    return blob


def call(method, path, params):
    created = now530(0, int(time.time() * 1000) % 1000)
    sent = now530(0.02, (int(time.time() * 1000) + 20) % 1000)
    blob = sign(created)
    p = dict(params)
    p["created_at"] = created
    p["sent_at"] = sent
    auth = ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="%s"'
            % (__import__("base64").b64encode(blob).decode(),
               IDENT["adj_verification"]))
    s = creq.Session(impersonate="chrome131_android")
    s.headers.update({"Authorization": auth, "Client-SDK": "android5.7.0",
                      "User-Agent": UA})
    url = "https://app.adjust.com" + path
    if method == "POST":
        r = s.post(url, data=urllib.parse.urlencode(p), timeout=30)
    else:
        r = s.get(url + "?" + urllib.parse.urlencode(p), timeout=30)
    log("  -> %d %s" % (r.status_code, r.text[:300]))
    return r.status_code, r.text


def common(**kw):
    p = dict(IDENT)
    p.update({k: v for k, v in IDENT.items() if k != "adj_verification"})
    p.update({"gps_adid_attempt": "1", "gps_adid_src": "service",
              "foreground": "1", "connectivity_type": "1", "mcc": "405",
              "mnc": "872", "language": "tr", "ui_mode": "1",
              "tracking_enabled": "1", "needs_response_details": "1",
              "attribution_deeplink": "1", "offline_mode_enabled": "0",
              "cpu_type": "arm64-v8a", "display_width": "1080",
              "display_height": "2293", "screen_size": "normal",
              "screen_format": "long", "screen_density": "high",
              "store_name_from_system": "com.android.vending",
              "initiating_package_name": "com.android.vending"})
    p.update(kw)
    return p


def main():
    log("== device: %s (prior install %s, inactive since 09-08) ==" %
        (ADID[:13], INST))
    url = ("https://app.adjust.com/1sd1lk6a"
           "?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
           "&click_id={click_id}&idfa=" + ADID + "&gps_adid=" + ADID +
           "&install_callback=" + CB + "%2Fapi%2Ftrack%2Fv1%2Fpostback%3F"
           "click_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3D"
           "vkmdigital%26offer_id%3Dpntvkmdup1mmp")
    cs = creq.Session(impersonate="chrome131_android")
    r = cs.get(url, allow_redirects=False, timeout=30)
    loc = r.headers.get("location") or ""
    m = re.search(r"adjust_reftag%3D([A-Za-z0-9]+)", loc)
    reftag = m.group(1) if m else None
    log("click %d reftag=%s" % (r.status_code, reftag))
    assert reftag, "no reftag"
    click_ts = now530(0, 100)
    time.sleep(10)

    log("== 1: /session (session_count=2, 6 days after 1st) ==")
    call("POST", "/session", common(session_count="2", retry_count="0",
                                    last_error="0", first_error="0",
                                    enqueue_size="0", wait_time="0.0",
                                    wait_total="0.0"))
    time.sleep(2)

    log("== 2: /sdk_click (re-engagement reftag) ==")
    ref = ("adjust_reftag=%s&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
           "&utm_content=vkm_0926_36&utm_term=penti_generic" % reftag)
    call("POST", "/sdk_click", common(
        source="install_referrer", referrer=ref, reftag=reftag,
        click_label=reftag, referrer_api="google", google_play_instant="0",
        install_version="3.12.1", click_time=click_ts,
        click_time_server=click_ts, install_begin_time=INST,
        install_begin_time_server=INST, session_count="2",
        subsession_count="1", session_length="510000", time_spent="510000"))
    time.sleep(8)

    for i, wait in enumerate([0, 30, 60, 120], 1):
        if wait:
            time.sleep(wait)
        log("== 3.%d: /attribution ==" % i)
        call("GET", "/attribution", common(initiated_by="backend"))

    open("attempt11.log", "w").write("\n".join(log_lines))
    print("saved attempt11.log", flush=True)


if __name__ == "__main__":
    main()
