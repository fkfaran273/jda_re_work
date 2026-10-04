"""run_graddef.py — live funnel for com.grad.def with the backend's device.

Device: Samsung SM-S928U (Android 16, API 36, IN) — the AutoLabs blob.
GAID pinned to the click's sub1/sub3 (device-matched click via mobpine).
Story: hardware_name = os_build (per both genuine captures), properties
served = the Samsung's.
"""
import json
import os
import sys
import time
import uuid

sys.path.insert(0, ".")
GAID = "a6f6194e-1197-4633-b226-a7e02a9610c8"
LINK = ("http://clicks.mobpine.com/api/track/v1/click?aff_id=3"
        "&offer_id=23480213&sub1=a6f6194e-1197-4633-b226-a7e02a9610c8"
        "&sub2=w77le91flo6o902n18&sub3=a6f6194e-1197-4633-b226-a7e02a9610c8")

sys.argv = [sys.argv[0], "graddef"]
import run_install as R
import device_data as D

# Samsung properties for the native's environment fingerprint
BS = bytes
S = R.S
S.DEVICE_PROPS.clear()
S.DEVICE_PROPS.update({
    BS(b"ro.product.name"): BS(b"e3qsqw"),
    BS(b"ro.product.model"): BS(b"SM-S928U"),
    BS(b"ro.product.manufacturer"): BS(b"samsung"),
    BS(b"ro.product.device"): BS(b"e3q"),
    BS(b"ro.product.cpu.abilist"): BS(b"arm64-v8a,armeabi-v7a,armeabi"),
    BS(b"ro.product.brand"): BS(b"samsung"),
    BS(b"ro.hardware"): BS(b"pineapple"),
    BS(b"ro.build.version.sdk"): BS(b"36"),
    BS(b"ro.build.version.release"): BS(b"16"),
    BS(b"ro.build.user"): BS(b"dpi"),
    BS(b"ro.build.type"): BS(b"user"),
    BS(b"ro.build.host"): BS(b"dpi"),
    BS(b"ro.build.fingerprint"): BS(b"samsung/e3qsqw/e3q:16/BP2A.250605.031.A3/"
                                    b"S928USQU4CYI9:user/release-keys"),
    BS(b"ro.build.display.id"): BS(b"BP2A.250605.031.A3"),
    BS(b"ro.bootloader"): BS(b"S928USQU4CYI9"),
})
# the APK must be graddef's, not be's
REAL = ("/data/app/~~VNWurfK3vN5kr6qQae49BQ==/"
        "com.grad.def-SIu3qkp-9Ulvb5P8tBF8dQ==/base.apk")
apk = open("apks/graddef_base.apk", "rb").read()
_orig_sign = R.sign
def sign(fields, kind, second):
    import inspect
    kwargs = {}
    try:
        if "apk_bytes" in inspect.getfullargspec(S.mint_adj8).args:
            kwargs = {"apk_path": REAL, "apk_bytes": apk}
    except Exception:
        pass
    blob, auth = S.mint_adj8(kind, fields, unix_sec=second, **kwargs)
    return auth, blob
R.sign = sign

R.INSTALL_AFTER = 48
auuid = str(uuid.uuid4())
print("device:", D.device_headers(), flush=True)
print("gaid:", GAID, flush=True)

reftag, _ = R._one_visit(LINK)
print("reftag:", reftag, flush=True)
if not reftag:
    raise SystemExit("no reftag")
click_sec = int(time.time())

time.sleep(64)
sec = R.signing_second()
fields = R.build_session_request(GAID, auuid, R.DEVICE, R.campaign_data, sec,
                                 click_sec=click_sec)
auth, blob = sign(fields, "session", sec)
print("session %d B" % len(blob), flush=True)
st, body = R.call("POST", "/session", fields, auth)
adid = json.loads(body).get("adid", "")
print("session ->", st, "adid", adid, flush=True)

time.sleep(12)
sec = R.signing_second()
fields = R.build_click_request(GAID, auuid, R.DEVICE, R.campaign_data, sec,
                               reftag, click_sec=click_sec)
auth, blob = sign(fields, "click", sec)
print("click %d B" % len(blob), flush=True)
st, body = R.call("POST", "/sdk_click", fields, auth)
print("sdk_click ->", st, body[:120], flush=True)

verdict = {}
for delay in (5, 15, 30, 45, 60, 90):
    time.sleep(delay)
    sec = R.signing_second()
    f = R.build_attribution_request(GAID, auuid, R.DEVICE, R.campaign_data, sec)
    auth, _ = sign(f, "attribution", sec)
    st, body = R.call("GET", "/attribution", f, auth)
    v = (json.loads(body).get("attribution") or {})
    verdict = v
    print("poll +%ds -> %s / %s / eng=%s"
          % (delay, v.get("network"), v.get("tracker_token"),
             v.get("engagement_time")), flush=True)
    if v.get("network") and v["network"] != "Organic":
        print("*** NON-ORGANIC ***", json.dumps(v)[:300], flush=True)
        break

json.dump({"gaid": GAID, "android_uuid": auuid, "adid": adid,
           "reftag": reftag, "click_second": click_sec, "verdict": verdict,
           "campaign": "graddef"}, open("last_run.json", "w"), indent=1)
print("DONE verdict:", verdict.get("network"), flush=True)
