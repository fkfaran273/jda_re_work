"""replay_yamistar.py — the user's cross-check: replay the BOOKED yamistar
capture (com.grad.def, network Mobavenue) through OUR signature maker.

Same-to-same: every field value copied from the captured session/click/
attribution bodies (device story RMX2161 / Android 15 / API 35 / country US,
properties derived from that story), with ONLY the per-install identity
(gaid, android_uuid, external_device_id, google_app_set_id) and the
timestamps made fresh, plus a fresh click from the same mobpine offer.
If attribution books non-organic -> our signature making is valid.
"""
import base64
import calendar
import datetime
import json
import os
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, ".")
GAID = str(uuid.uuid4())
AUUID = str(uuid.uuid4())
EXTID = os.urandom(8).hex()
GAPPSET = str(uuid.uuid4())
AGENT = "w77le91flo6o902n18"
LINK = ("http://clicks.mobpine.com/api/track/v1/click?aff_id=3"
        "&offer_id=23480213&sub1=" + GAID + "&sub2=" + AGENT +
        "&sub3=" + GAID)

cap = json.load(open("cap/yamistar_capture.json"))
sess_cap = [r for r in cap if r["kind"] == "session"][0]["params"]
click_cap = [r for r in cap if r["kind"] == "click"][0]["params"]
attr_cap = [r for r in cap if r["kind"] == "attribution"][0]["params"]

# ---- device story from the capture (realme RMX2161, Android 15) ------------
DEV = {
    "sdk": sess_cap["api_level"],
    "os_version": sess_cap["os_version"],
    "build": sess_cap["os_build"],
    "display": sess_cap["hardware_name"],
    "model": sess_cap["device_name"],
    "manufacturer": sess_cap["device_manufacturer"],
    "brand": "realme",
    "name": "RMX2161",
    "device": "RMX2161",
    "fingerprint": ("realme/RMX2161/RMX2161:15/" + sess_cap["os_build"] +
                    "/user/release-keys"),
    "locale": {"country": sess_cap.get("country", "US"),
               "language": sess_cap.get("language", "en")},
    "timezone": "+0530",
    "network": "WiFi",
    "cpu_abi": sess_cap.get("cpu_type", "arm64-v8a"),
    "resolution": "%sx%s" % (sess_cap.get("display_width", "1080"),
                             sess_cap.get("display_height", "2400")),
    "display_metrics": {"density_dpi": "xxhdpi",
                        "screen_layout_name": sess_cap.get("screen_size",
                                                           "normal"),
                        "screen_layout_format": sess_cap.get("screen_format",
                                                             "long")},
    "User-Agent": ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
                   % (sess_cap["os_version"], sess_cap["device_name"],
                      sess_cap["os_build"])),
}

sys.argv = [sys.argv[0]]
import run_install as R
import adj8_pure as S

# properties DERIVED from the story (the native fingerprints the environment;
# on a real device these come from the same build the map values came from)
BS = bytes
props = {
    BS(b"ro.product.name"): BS(DEV["name"].encode()),
    BS(b"ro.product.model"): BS(DEV["model"].encode()),
    BS(b"ro.product.manufacturer"): BS(DEV["manufacturer"].encode()),
    BS(b"ro.product.device"): BS(DEV["device"].encode()),
    BS(b"ro.product.cpu.abilist"): BS(b"arm64-v8a,armeabi-v7a,armeabi"),
    BS(b"ro.product.brand"): BS(DEV["brand"].encode()),
    BS(b"ro.hardware"): BS(DEV["device"].encode()),
    BS(b"ro.build.version.sdk"): BS(DEV["sdk"].encode()),
    BS(b"ro.build.version.release"): BS(DEV["os_version"].encode()),
    BS(b"ro.build.user"): BS(b"dpi"),
    BS(b"ro.build.type"): BS(b"user"),
    BS(b"ro.build.host"): BS(b"dpi"),
    BS(b"ro.build.fingerprint"): BS(DEV["fingerprint"].encode()),
    BS(b"ro.build.display.id"): BS(DEV["build"].encode()),
    BS(b"ro.bootloader"): BS(b"unknown"),
}
S.DEVICE_PROPS.clear()
S.DEVICE_PROPS.update(props)

REAL = ("/data/app/~~VNWurfK3vN5kr6qQae49BQ==/"
        "com.grad.def-SIu3qkp-9Ulvb5P8tBF8dQ==/base.apk")
apk = open("apks/graddef_base.apk", "rb").read()
_orig_sign = R.sign
def sign(fields, kind, second):
    blob, auth = S.mint_adj8(kind, fields, unix_sec=second,
                             apk_path=REAL, apk_bytes=apk)
    return auth, blob
R.sign = sign
R.DEVICE = DEV
R.INSTALL_AFTER = 48

TS_FMT = "%Y-%m-%dT%H:%M:%S." + "%03d" + "Z+0530"


def stamp(ts, ms):
    dt = datetime.datetime.utcfromtimestamp(ts + 330 * 60)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + ("%03d" % ms) + "Z+0530"


def refresh(params, sec, click_sec, reftag=None):
    """Captured values, fresh identity + timestamps."""
    out = {}
    skip = {"gps_adid", "android_uuid", "external_device_id",
            "google_app_set_id", "created_at", "sent_at", "installed_at",
            "updated_at", "click_time", "click_time_server",
            "install_begin_time", "install_begin_time_server", "referrer"}
    for k, v in params.items():
        if k not in skip:
            out[k] = v
    out["gps_adid"] = GAID
    out["android_uuid"] = AUUID
    out["external_device_id"] = EXTID
    out["google_app_set_id"] = GAPPSET
    out["created_at"] = stamp(sec, 928)
    out["sent_at"] = stamp(sec, 942)
    if "installed_at" in out or "installed_at" in params:
        installed = stamp(click_sec + 48, 774)
        out["installed_at"] = installed
        out["updated_at"] = installed
    if reftag is not None:
        out["referrer"] = reftag
        out["click_time"] = stamp(click_sec, 0)
        out["click_time_server"] = stamp(click_sec - 2, 0)
        out["install_begin_time"] = stamp(click_sec + 8, 0)
        out["install_begin_time_server"] = stamp(click_sec + 6, 0)
    return out


import http.client
def call(method, path, fields, auth):
    body = urllib.parse.urlencode(fields).encode() if method == "POST" else None
    target = path if method == "POST" else path + "?" + urllib.parse.urlencode(
        fields)
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest(method, target, skip_host=1, skip_accept_encoding=1)
        c.putheader("Client-SDK", "android5.6.1")
        c.putheader("Authorization", auth)
        c.putheader("User-Agent", DEV["User-Agent"])
        c.putheader("Host", "app.adjust.com")
        if body is not None:
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("Content-Length", str(len(body)))
        c.putheader("Accept-Encoding", "gzip")
        c.endheaders(body)
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            import gzip
            raw = gzip.decompress(raw)
        return r.status, raw.decode("utf-8", "replace")
    finally:
        c.close()


print("device story:", DEV["User-Agent"], flush=True)
print("fresh gaid:", GAID, flush=True)

reftag, _ = R._one_visit(LINK)
print("reftag:", reftag, flush=True)
if not reftag:
    raise SystemExit("no reftag")
click_sec = int(time.time())

time.sleep(64)
sec = R.signing_second()
fields = refresh(sess_cap, sec, click_sec)
print("session fields:", len(fields), flush=True)
auth, blob = sign(fields, "session", sec)
print("session %d B" % len(blob), flush=True)
st, body = call("POST", "/session", fields, auth)
adid = json.loads(body).get("adid", "")
print("session ->", st, "adid", adid, flush=True)

time.sleep(12)
sec = R.signing_second()
fields = refresh(click_cap, sec, click_sec, reftag=reftag)
print("click fields:", len(fields), flush=True)
auth, blob = sign(fields, "click", sec)
print("click %d B" % len(blob), flush=True)
st, body = call("POST", "/sdk_click", fields, auth)
print("sdk_click ->", st, body[:120], flush=True)

verdict = {}
for delay in (5, 15, 30, 45, 60, 90, 120):
    time.sleep(delay)
    sec = R.signing_second()
    f = refresh(attr_cap, sec, click_sec)
    auth, _ = sign(f, "attribution", sec)
    st, body = call("GET", "/attribution", f, auth)
    v = (json.loads(body).get("attribution") or {})
    verdict = v
    print("poll +%ds -> %s / %s / eng=%s"
          % (delay, v.get("network"), v.get("tracker_token"),
             v.get("engagement_time")), flush=True)
    if v.get("network") and v["network"] != "Organic":
        print("*** NON-ORGANIC — SIGNATURE VALID ***",
              json.dumps(v)[:300], flush=True)
        break

json.dump({"gaid": GAID, "android_uuid": AUUID, "adid": adid,
           "reftag": reftag, "verdict": verdict, "test": "yamistar-replay"},
          open("last_run.json", "w"), indent=1)
print("DONE verdict:", verdict.get("network"), flush=True)
