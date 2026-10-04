"""attrib_test.py — full attribution flow with crafted adj9 signatures.

Stages (real-SDK order, params modeled on the SAZ capture):
  0. CLICK the tracker with the device's gps_adid (records the click
     server-side, bound to the adid) — reftag cTZk0zc2x78Ko
  1. POST /sdk_click   (referrer flavor, reftag in referrer string)
  2. POST /session
  3. GET  /attribution  (initiated_by=backend), polled twice

Identity = the proven moto g42 package (android_uuid 415606ad…,
gps_adid f476b3d4-e0b1-4707-bc43-6153d17f7f8c) that already earned
crafted 200s. Signing = the slice-81 recipe (zero #0 + random dword35,
replayed sess_H, session-flavor claims, fresh timestamps).
"""
import base64
import datetime
import json
import random
import struct
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict

sys.path.insert(0, ".")
from fin_vm2 import FinEx

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
D = json.load(open(HERE + "/fin_descs.json"))
H = bytes.fromhex(json.load(open(
    "C:/Users/Apps/Downloads/com.penti.app/adj9/device/triples_tail7.json"))["sess_H"])

ADID = "f476b3d4-e0b1-4707-bc43-6153d17f7f8c"
REFSTR = ("adjust_reftag=cTZk0zc2x78Ko&utm_source=VKM+Digital+Yeni"
          "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")

IDENT = {
    "app_token": "jut9tib0eeps",
    "android_uuid": "415606ad-7002-479b-b691-305aace409ba",
    "api_level": "31",
    "app_version": "3.13.9",
    "device_name": "moto g42",
    "device_type": "phone",
    "environment": "production",
    "gps_adid": ADID,
    "hardware_name": "S2SE32.28-28-4",
    "os_build": "S2SE32.28-28-4",
    "os_name": "android",
    "os_version": "12",
    "package_name": "com.penti.app",
    "installed_at": "2026-09-08T12:20:49.782Z+0200",
    "updated_at": "2026-09-10T07:26:18.015Z+0200",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
}
COMMON = {
    "gps_adid_attempt": "1", "gps_adid_src": "service",
    "foreground": "1", "connectivity_type": "1",
    "needs_response_details": "1", "attribution_deeplink": "1",
    "tracking_enabled": "1", "ui_mode": "1",
    "offline_mode_enabled": "0", "retry_count": "0",
    "last_error": "0", "first_error": "0",
    "enqueue_size": "0", "wait_time": "0.0", "wait_total": "0.0",
    "language": "tr", "screen_size": "normal", "screen_format": "long",
    "screen_density": "high", "cpu_type": "arm64-v8a",
    "display_width": "720", "display_height": "1600",
    "store_name_from_system": "com.android.vending",
    "initiatingPackage_name": "com.android.vending",
}

log_lines = []
def log(s):
    print(s, flush=True)
    log_lines.append(s)


def ts_now(ms="000"):
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S." + ms + "Z+0200")


def sign(created):
    """One crafted 192-B blob for this created_at (slice-81 recipe)."""
    parts = [IDENT["adj_verification"].encode(), IDENT["android_uuid"].encode(),
             IDENT["api_level"].encode(), IDENT["app_token"].encode(),
             IDENT["app_version"].encode(), created.encode(),
             IDENT["device_name"].encode(), IDENT["device_type"].encode(),
             IDENT["environment"].encode(), IDENT["gps_adid"].encode()]
    raw = b"".join(parts)
    fetch = raw + b"\0" * ((-len(raw)) % 4)
    L10 = len(fetch) // 4
    d0 = bytearray(144)
    d0[140:144] = struct.pack(">I", random.getrandbits(32))
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
          for d in D["descs"]}
    by[0] = (36, bytes(d0))
    by[4] = (8, H)
    by[10] = (L10, fetch)
    by[7] = (1, struct.pack(">I", L10 << 2))
    descs = [(by[i][0], 0, by[i][1]) for i in [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]]
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


def send(method, path, params):
    created, sent = ts_now(), ts_now("060")
    blob, status, hdr_ok = sign(created)
    log("  sig: %s hdr_law=%s blob=%s…" % (status, hdr_ok, blob.hex()[:24]))
    sig_b64 = base64.b64encode(blob).decode()
    auth = ('signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig_b64)
    p = dict(params)
    p["created_at"] = created
    p["sent_at"] = sent
    if method == "GET":
        url = "https://app.adjust.com%s?%s" % (path, urllib.parse.urlencode(p))
        req = urllib.request.Request(url, method="GET")
    else:
        req = urllib.request.Request("https://app.adjust.com" + path,
                                     data=urllib.parse.urlencode(p).encode(),
                                     method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Authorization", auth)
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; "
                                 "moto g42 Build/S2SE32.28-28-4)")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()[:400]
            log("  -> %d %s" % (r.status, body.decode("utf-8", "replace")))
            return r.status, body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read()[:400]
        log("  -> %d %s" % (e.code, body.decode("utf-8", "replace")))
        return e.code, body.decode("utf-8", "replace")
    except Exception as e:
        log("  -> FAIL %s" % e)
        return -1, str(e)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def stage0_click():
    q = urllib.parse.urlencode({"gps_adid": ADID})
    url = ("https://app.adjust.com/cTZk0zc2x78Ko?" + q + "&" +
           "utm_source=VKM%2BDigital%2BYeni&utm_campaign=AH"
           "&utm_content=vkm_0926_36&utm_term=penti_generic")
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent":
                                          "Mozilla/5.0 (Linux; Android 12; "
                                          "moto g42) AppleWebKit/537.36"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(req, timeout=30)
        log("  -> %d loc=%s body=%s" % (r.status, r.headers.get("Location"),
                                        r.read()[:120]))
        return r.status
    except urllib.error.HTTPError as e:
        log("  -> %d loc=%s body=%s" % (e.code, e.headers.get("Location"),
                                        e.read()[:200]))
        return e.code
    except Exception as e:
        log("  -> FAIL %s" % e)
        return -1


def main():
    log("== stage 0: tracker click (adid-bound) ==")
    stage0_click()

    log("== stage 1: /sdk_click (reftag referrer) ==")
    click = dict(IDENT)
    click.update(COMMON)
    click.update({
        "source": "install_referrer", "referrer": REFSTR,
        "referrer_api": "google", "google_play_instant": "0",
        "install_version": "3.13.9",
        "click_time": ts_now("100"), "install_begin_time": ts_now("200"),
        "session_count": "2", "subsession_count": "1",
        "session_length": "0", "time_spent": "0",
    })
    send("POST", "/sdk_click", click)
    time.sleep(3)

    log("== stage 2: /session ==")
    sess = dict(IDENT)
    sess.update(COMMON)
    sess.update({"session_count": "2", "foreground": "1"})
    send("POST", "/session", sess)
    time.sleep(3)

    log("== stage 3: /attribution (poll 1) ==")
    att = dict(IDENT)
    att.update({k: v for k, v in COMMON.items()
                if k in ("gps_adid_attempt", "gps_adid_src", "foreground",
                         "needs_response_details", "attribution_deeplink",
                         "tracking_enabled", "ui_mode", "offline_mode_enabled")})
    att["initiated_by"] = "backend"
    send("GET", "/attribution", att)

    log("== stage 4: /attribution (poll 2, +20 s) ==")
    time.sleep(20)
    send("GET", "/attribution", att)

    open(HERE + "/attrib_result.log", "w").write("\n".join(log_lines))
    print("saved attrib_result.log", flush=True)


if __name__ == "__main__":
    main()
