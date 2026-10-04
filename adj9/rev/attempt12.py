"""attempt12.py — THE test: real non-rooted device (realme RMX5051,
adid ba56f461-9b35-4416-9612-d1bcad094b29, Turkey/Turk Telekom, tz
+0200) + the reftag ITS browser click minted (c0Sztz9FqfLzn). No
synthesized click this time: a genuine click exists server-side bound
to a genuine GAID; we complete the install-side (session -> sdk_click
with the real referrer -> sdk_info -> attribution) with forged-perfect
adj9 signatures: random 32B H, zeroed #0, coupled claims.

Stage 0 polls attribution FIRST: it tells us whether the real app on
that phone already sent its own sessions (state of the device before
our calls)."""
import json
import random
import string
import time
import uuid as U

import adj9_forge as F

ADID = "ba56f461-9b35-4416-9612-d1bcad094b29"
AUID = str(U.uuid4())
REFERRER = ("adjust_reftag=c0Sztz9FqfLzn&utm_source=VKM+Digital+Yeni"
            "&utm_campaign=AH&utm_content=vkm_0926_36"
            "&utm_term=penti_generic")
UA = ("Dalvik/2.1.0 (Linux; U; Android 15; RMX5051 Build/UKQ1.231108.001)")
SKEW = 55
PUSH_TPL = F.M["wire_templates"]["sdk_info"]["push_token"]


def rand_push():
    a = string.ascii_letters + string.digits + "-_"
    return ("emsp" + "".join(random.choices(a, k=22)) + ":APA91b"
            + "".join(random.choices(a, k=len(PUSH_TPL) - 34)))


PROF = {
    "gps_adid": ADID, "android_uuid": AUID, "app_token": "jut9tib0eeps",
    "api_level": "35", "app_version": "3.13.9", "install_version": "3.13.9",
    "device_name": "RE6079L1", "device_manufacturer": "realme",
    "device_type": "phone", "environment": "production",
    "hardware_name": "qcom", "os_build": "UKQ1.231108.001",
    "os_name": "android", "os_version": "15",
    "package_name": "com.penti.app",
    "store_name_from_system": "com.android.vending",
    "initiating_package_name": "com.android.vending",
    "language": "tr", "mcc": "286", "mnc": "03",
    "cpu_type": "arm64-v8a", "display_width": "1272",
    "display_height": "2604", "screen_size": "normal",
    "screen_format": "long", "screen_density": "xxxhdpi",
    "push_token": rand_push(),
}
COUPLED = ("gps_adid", "android_uuid", "api_level", "app_version",
           "device_name", "device_type", "environment", "installed_at",
           "updated_at", "os_version", "app_token")

def stamp(prof, sec):
    p = dict(prof)
    p["created_at"] = F.iso_plus0200(sec - 1, int(time.time()*1000) % 900 + 60)
    p["sent_at"] = F.iso_plus0200(sec - 1, int(time.time()*1000) % 900 + 80)
    return p


def signed_call(label, endpoint, path, prof, method="POST"):
    sec = int(time.time()) + SKEW
    overrides = {k: prof[k] for k in COUPLED if k in prof}
    overrides["created_at"] = prof["created_at"]
    if prof.get("installed_at"):
        overrides["installed_at"] = overrides["updated_at"] = prof["installed_at"]
    status, blob, h = F.make_signature(sec, overrides)
    p = F.wire_params(endpoint, prof)
    p.update({k: v for k, v in prof.items() if k not in p})
    code, body = F.call(endpoint, path, p, blob, UA, method)
    print("%-11s mint=%s law=OK -> %d %s" % (label, status, code, body[:260]),
          flush=True)
    return code, body, blob


def main():
    now = time.time()
    inst = F.iso_plus0200(now - 3600, 774)         # app updated ~1h ago
    res = {"gps": ADID, "auid": AUID, "referrer": REFERRER,
           "push": PROF["push_token"], "installed_at": inst}

    base = stamp(dict(PROF, installed_at=inst, updated_at=inst),
                 int(now) + SKEW)
    base.update({"session_count": "1", "foreground": "1",
                 "wait_time": "0.0", "wait_total": "0.0",
                 "retry_count": "0", "last_error": "0", "first_error": "0",
                 "enqueue_size": "0", "connectivity_type": "1",
                 "ui_mode": "1", "tracking_enabled": "1",
                 "offline_mode_enabled": "0", "needs_response_details": "1",
                 "attribution_deeplink": "1", "gps_adid_attempt": "1",
                 "gps_adid_src": "service", "initiated_by": "backend"})
    print("== stage 0: attribution READ (device state before us) ==")
    c, b, _ = signed_call("attr-read", "attribution", "/attribution",
                          base, method="GET")
    res["attr_before"] = [c, b[:400]]

    print("== 1: /session ==")
    s = dict(base)
    c, b, _ = signed_call("session", "session", "/session", s)
    res["session"] = [c, b[:300]]
    time.sleep(2)

    print("== 2: /sdk_click (REAL reftag from the phone's click) ==")
    clk = dict(base)
    click_epoch = now - 120
    clk.update({
        "source": "install_referrer", "referrer": REFERRER,
        "referrer_api": "google", "google_play_instant": "0",
        "click_time": F.iso_plus0200(click_epoch, 0),
        "click_time_server": F.iso_plus0200(click_epoch + 1, 0),
        "install_begin_time": F.iso_plus0200(now - 3540, 0),
        "install_begin_time_server": F.iso_plus0200(now - 3539, 0),
        "subsession_count": "1", "session_length": "0", "time_spent": "0",
        "session_count": "1",
    })
    c, b, _ = signed_call("sdk_click", "sdk_click", "/sdk_click", clk)
    res["sdk_click"] = [c, b[:300]]
    time.sleep(4)

    print("== 3: /sdk_info (fresh random push token) ==")
    si = dict(base)
    c, b, _ = signed_call("sdk_info", "sdk_info", "/sdk_info", si)
    res["sdk_info"] = [c, b[:200]]
    time.sleep(20)

    for i in range(1, 4):
        print("== 4.%d: /attribution poll ==" % i)
        c, b, _ = signed_call("attr-%d" % i, "attribution", "/attribution",
                              base, method="GET")
        res["attr_%d" % i] = [c, b[:500]]
        if "AdsyM" in b or "VKM" in b or "tracker_token\":\"1sd1lk6a" in b \
                or "\"Organic\"" not in b:
            break
        time.sleep(60 * i)

    verdict = ("NON-ORGANIC!" if '"Organic"' not in res["attr_3"][1]
               and res["attr_3"][0] == 200 else "Organic")
    for k in ("attr_3", "attr_2", "attr_1", "attr_before"):
        if '"Organic"' not in res[k][1] and "attribution" in res[k][1]:
            verdict = "NON-ORGANIC (%s)" % k
            break
    res["verdict"] = verdict
    print("\nVERDICT:", verdict)
    json.dump(res, open("nonorganic_result3.json", "w"), indent=1)


if __name__ == "__main__":
    main()
