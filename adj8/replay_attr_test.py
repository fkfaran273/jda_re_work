"""replay_attr_test.py — replay the BOOKED captures' attribution GETs with OUR
signature maker (same params, same signing second).  The device's attribution
is already non-organic server-side; if our signed request returns it, the
signature making is valid.
"""
import base64
import calendar
import datetime
import json
import re
import sys
import urllib.parse
import http.client
import gzip

sys.path.insert(0, ".")
import adj8_pure as S

BS = bytes
UA = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)")


def created_sec(created):
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z([+-]\d{4})",
                 created)
    dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f")
    off = m.group(2)
    minutes = (1 if off[0] == "+" else -1) * (int(off[1:3]) * 60 + int(off[3:5]))
    return calendar.timegm(dt.timetuple()) - minutes * 60


def send(params, auth, client_sdk, ua):
    target = "/attribution?" + urllib.parse.urlencode(
        params, quote_via=urllib.parse.quote)
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest("GET", target, skip_host=1, skip_accept_encoding=1)
        c.putheader("Client-SDK", client_sdk)
        c.putheader("Authorization", auth)
        c.putheader("User-Agent", ua)
        c.putheader("Host", "app.adjust.com")
        c.putheader("Accept-Encoding", "gzip")
        c.endheaders()
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return r.status, raw.decode("utf-8", "replace")
    finally:
        c.close()


def run_case(name, params, client_sdk, ua, apk_path, apk_bytes, props=None):
    if props is not None:
        S.DEVICE_PROPS.clear()
        S.DEVICE_PROPS.update(props)
    sec = created_sec(params["created_at"])
    print("== %s == signing second %d" % (name, sec))
    blob, auth, meta = S.mint_adj8("attribution", dict(params), unix_sec=sec,
                                   return_meta=True, apk_path=apk_path,
                                   apk_bytes=apk_bytes)
    print("   mint %d B tag_ok=%s" % (len(blob), meta["tag_ok"]))
    st, body = send(params, auth, client_sdk, ua)
    print("   -> %d %s" % (st, body[:320]))
    ok = ("Organic" not in body) and '"network"' in body
    print("   VERDICT:", "NON-ORGANIC RETURNED — SIGNATURE VALID"
          if ok else "not booked / rejected")
    return ok


apk_be = open("apks/base.apk", "rb").read()
MOTO_PROPS = dict(S.DEVICE_PROPS)

# ---- case 1: be (xyz.be.customer, booked Dinos_Dynamic_Partner) -----------
be_params = json.load(open("cap/be_attr_params.json"))
ok1 = run_case("be (moto g42 story)", be_params, "android5.7.0",
               UA % ("12", "moto g42", "S2SE32.28-28-4"),
               "/data/app/~~cgSd5YKkLX7RXvJWtSA_6Q==/"
               "xyz.be.customer-zt-y8mq-uV_paqBcpeNXcg==/base.apk",
               apk_be, props=MOTO_PROPS)

# ---- case 2: yamistar (com.grad.def, booked Mobavenue) ---------------------
yami = json.load(open("cap/yami_attr.json"))
RMX_PROPS = {
    BS(b"ro.product.name"): BS(b"RMX2161"),
    BS(b"ro.product.model"): BS(b"RMX2161"),
    BS(b"ro.product.manufacturer"): BS(b"realme"),
    BS(b"ro.product.device"): BS(b"RMX2161"),
    BS(b"ro.product.cpu.abilist"): BS(b"arm64-v8a,armeabi-v7a,armeabi"),
    BS(b"ro.product.brand"): BS(b"realme"),
    BS(b"ro.hardware"): BS(b"RMX2161"),
    BS(b"ro.build.version.sdk"): BS(b"35"),
    BS(b"ro.build.version.release"): BS(b"15"),
    BS(b"ro.build.user"): BS(b"dpi"),
    BS(b"ro.build.type"): BS(b"user"),
    BS(b"ro.build.host"): BS(b"dpi"),
    BS(b"ro.build.fingerprint"): BS(b"realme/RMX2161/RMX2161:15/"
                                    b"BP1A.250405.007.D1:user/release-keys"),
    BS(b"ro.build.display.id"): BS(b"BP1A.250405.007.D1"),
    BS(b"ro.bootloader"): BS(b"unknown"),
}
apk_gd = open("apks/graddef_base.apk", "rb").read()
ok2 = run_case("yamistar (RMX2161 story)", yami["params"], "android5.6.1",
               yami["ua"], "/data/app/~~VNWurfK3vN5kr6qQae49BQ==/"
               "com.grad.def-SIu3qkp-9Ulvb5P8tBF8dQ==/base.apk",
               apk_gd, props=RMX_PROPS)

print("\nFINAL:", {"be": ok1, "yamistar": ok2})
