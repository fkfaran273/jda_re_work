"""run_hunch.py -- fresh hunch install funnel (copy; originals untouched).

Device truth: hunchdate_new.saz rows 29/30/32 (genuine booking 2026-10-08
12:28 IST, adid 2304ef18, verdict Spyke Media/1zwaj8ym FIRST poll, no event).
Blobs re-mint WHOLE byte-exact for session+attribution with
  cert aa92a18790f85d4e9b5199c7792c55f2fb0f61e1 (fresh Play APK, DER-verified)
  client_sdk flutter5.5.0@android5.5.0, 1300000/adj7/8/3.62.0, same 98-key pool
Click: user's DIRECT adjust link (no mobpine middle hop), raw-tap faithful:
  no gps_adid appended, macros sent literally (genuine utm_content shows
  literal {affiliate_id}, creative dropped server-side).
Flow: click 12:25:15 -> server -1 -> begin +6/+5 -> installed +18.589 ->
  session +203.295 -> sdk_click +0.038 pipelined -> attr +3.258 -> PAID.
  NO /event (device sends none).
Timeline longs: CTIT 203 s wall clock.
"""
import gzip
import http.client
import json
import os
import re
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

os.environ["HTTP_PROXY"] = "http://127.0.0.1:8888"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8888"

from adj7_pure import mint_adj7
from run_fiddler import _connect, BROWSER_HEADERS

CAMPAIGN = {
    "package_name": "social.hunch.app",
    "app_version": "3.2.33",
    "app_token": "vf3lochhmgw0",
    "client_sdk": "flutter5.5.0@android5.5.0",
    "cert_sha1": "aa92a18790f85d4e9b5199c7792c55f2fb0f61e1",
    "adj_signing_id": "1300000",
    "algorithm": "adj7",
    "headers_id": "8",
    "native_version": "3.62.0",
}
PACKAGE_NAME = CAMPAIGN["package_name"]
APP_TOKEN = CAMPAIGN["app_token"]
APP_VERSION = CAMPAIGN["app_version"]
CLIENT_SDK = CAMPAIGN["client_sdk"]

DEVICE = {
    "api_level": "31", "os_version": "12",
    "device_name": "moto g42", "device_manufacturer": "motorola",
    "hardware_name": "S2SE32.28-28-4", "os_build": "S2SE32.28-28-4",
    "language": "en", "country": "IN",
    "display_width": "1080", "display_height": "2237",
    "screen_density": "high", "screen_size": "normal", "screen_format": "long",
    "cpu_type": "arm64-v8a", "connectivity_type": "1",
    "device_type": "phone", "environment": "production",
    "timezone": "+0530",
}
P = DEVICE
APP_UA = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
          % (DEVICE["os_version"], DEVICE["device_name"], DEVICE["os_build"]))

# user's direct click link MINUS creative: genuine referrer has no utm_term,
# so the device's click carried campaign+adgroup only (creative=[app_name}
# injects utm_term=%5Bapp_name%7D which the genuine row never had)
LINK = ("https://app.adjust.com/1yzhva5b?campaign=SOHYPE_ADH"
        "&adgroup={affiliate_id}")
DRY_RUN = "--dry-run" in sys.argv

INSTALL_AFTER = 18           # installed = click+18.589 s (ms .589)
SESSION_AT = 203             # session created = click+203.295 s
MS = {"session_c": 295, "session_s": 559, "click_c": 597, "click_s": 715,
      "installed": 589, "attr_c": 817, "attr_s": 834}
MINT_SKEW = 0
PROXY = os.environ.get("FUNNEL_PROXY", "http://127.0.0.1:8888")
if not PROXY:
    PROXY = ""


def signing_second():
    return int(time.time()) + MINT_SKEW


def _stamp(ts, ms):
    off = int(DEVICE["timezone"][1:3]) * 3600 + int(DEVICE["timezone"][3:5]) * 60
    dt = datetime.fromtimestamp(ts + off, timezone.utc)
    return (dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms) + "Z"
            + DEVICE["timezone"])


def log(*parts):
    print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"),
                       " ".join(str(p) for p in parts)))
    sys.stdout.flush()


def _reftag_in(s):
    if "referrer=" not in s:
        return None
    ref = urllib.parse.unquote(s.split("referrer=", 1)[1])
    ref = ref.split(";S.browser_fallback_url")[0]
    ref = re.sub(r"&ip_address=%7B[^&]*%7D", "", ref)
    return re.sub(r"&ip_address=\{[^&]*\}", "", ref)


def _click_get(url):
    scheme, rest = url.split("://", 1)
    host, _, path = rest.partition("/")
    port = 443 if scheme == "https" else 80
    import run_fiddler as _RF
    if os.environ.get("FUNNEL_BLIND") == "1" and scheme == "https":
        import socket as _skt
        pp = _RF._proxy_addr()
        raw = _skt.create_connection(pp, timeout=30)
        raw.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                     % (host, port, host, port)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += raw.recv(4096)
        c = http.client.HTTPConnection(host, port, timeout=30)
        c.sock = raw
        c.putrequest("GET", "/" + path, skip_host=1,
                     skip_accept_encoding=1)
    else:
        c, via = _RF._connect(scheme, host, port, timeout=30)
        path = url if via == "proxy" else "/" + path
        c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    for hk, hv in BROWSER_HEADERS.items():
        if hk in ("Connection", "Host"):
            continue
        c.putheader(hk, hv)
    c.putheader("Connection", "close")
    c.putheader("Host", host)
    c.endheaders()
    r = c.getresponse()
    raw = r.read()
    if raw[:2] == bytes((0x1f, 0x8b)):
        raw = gzip.decompress(raw)
    c.close()
    return r.status, dict(r.getheaders()), raw.decode("utf-8", "replace")


def open_direct_link(gaid):
    """Fire the direct adjust link as Chrome; the 302 Location carries
    market://...referrer=adjust_reftag%3D... ; return (reftag, click_epoch).
    click_epoch is captured AT FIRE TIME so click_time never postdates the
    real click (the old now-1-after-return stamped it seconds late)."""
    clog = open(os.path.join(HERE, "click_chain_hunch.log"), "a")
    clog.write("=== %s gaid=%s url=%s\n"
               % (datetime.now().isoformat(), gaid, LINK))
    try:
        fired = time.time()
        status, hdrs, _ = _click_get(LINK)
        loc = hdrs.get("Location") or hdrs.get("location") or ""
        clog.write("direct -> %s loc=%s\n" % (status, loc[:300]))
        print("click    direct -> %s" % status)
        ref = _reftag_in(loc)
        if ref:
            clog.write("result ref=%s fired=%s\n" % (ref, fired))
            return ref, fired
        # follow one redirect if the first hop didn't carry the referrer
        if loc.startswith("http"):
            st2, hd2, _ = _click_get(loc)
            loc2 = hd2.get("Location") or hd2.get("location") or ""
            clog.write("hop2 -> %s loc=%s\n" % (st2, loc2[:300]))
            ref = _reftag_in(loc2)
            if ref:
                clog.write("result ref=%s fired=%s\n" % (ref, fired))
                return ref, fired
        return None, fired
    finally:
        clog.close()


def build_session(gaid, android_uuid, sec, click_sec):
    installed = _stamp(click_sec + INSTALL_AFTER, MS["installed"])
    return {
        "store_name_from_system": "com.android.vending",
        "gps_adid_attempt": "1", "country": P["country"],
        "api_level": P["api_level"], "hardware_name": P["hardware_name"],
        "app_version": APP_VERSION, "app_token": APP_TOKEN,
        "installed_at": installed, "created_at": _stamp(sec, MS["session_c"]),
        "wait_total": "0.0", "device_type": P["device_type"],
        "language": P["language"], "gps_adid": gaid, "foreground": "1",
        "connectivity_type": P["connectivity_type"],
        "ff_first_session_delay": "1",
        "device_manufacturer": P["device_manufacturer"],
        "display_width": P["display_width"], "device_name": P["device_name"],
        "needs_response_details": "1", "os_build": P["os_build"],
        "updated_at": installed, "cpu_type": P["cpu_type"],
        "retry_count": "0", "screen_size": P["screen_size"],
        "screen_format": P["screen_format"], "last_error": "0",
        "gps_adid_src": "service", "wait_time": "0.0",
        "os_version": P["os_version"], "first_error": "0",
        "android_uuid": android_uuid, "sent_at": _stamp(sec, MS["session_s"]),
        "offline_mode_enabled": "0", "environment": P["environment"],
        "screen_density": P["screen_density"], "attribution_deeplink": "1",
        "session_count": "1", "display_height": P["display_height"],
        "package_name": PACKAGE_NAME,
        "initiating_package_name": "com.android.vending",
        "os_name": "android", "ui_mode": "1",
        "enqueue_size": "0", "tracking_enabled": "1",
    }


def build_click(gaid, android_uuid, sec, referrer, click_sec):
    installed = _stamp(click_sec + INSTALL_AFTER, MS["installed"])
    begin = click_sec + 6
    begin_server = click_sec + 5
    return {
        "country": P["country"], "api_level": P["api_level"],
        "hardware_name": P["hardware_name"], "app_version": APP_VERSION,
        "partner_params": PARTNER_PARAMS,
        "app_token": APP_TOKEN, "installed_at": installed,
        "device_type": P["device_type"], "language": P["language"],
        "gps_adid": gaid, "source": "install_referrer", "foreground": "1",
        "connectivity_type": P["connectivity_type"], "os_build": P["os_build"],
        "click_time": _stamp(click_sec, 0),
        "cpu_type": P["cpu_type"],
        "install_version": APP_VERSION,
        "screen_size": P["screen_size"], "gps_adid_src": "service",
        "subsession_count": "1", "sent_at": _stamp(sec, MS["click_s"]),
        "offline_mode_enabled": "0", "screen_density": P["screen_density"],
        "session_count": "1", "ui_mode": "1", "gps_adid_attempt": "1",
        "session_length": "0", "created_at": _stamp(sec, MS["click_c"]),
        "referrer_api": "google",
        "ff_first_session_delay": "1",
        "device_manufacturer": P["device_manufacturer"],
        "display_width": P["display_width"], "time_spent": "0",
        "device_name": P["device_name"], "needs_response_details": "1",
        "updated_at": installed, "screen_format": P["screen_format"],
        "click_time_server": _stamp(click_sec - 1, 0),
        "os_version": P["os_version"], "google_play_instant": "0",
        "install_begin_time_server": _stamp(begin_server, 0),
        "android_uuid": android_uuid, "referrer": referrer,
        "environment": P["environment"], "attribution_deeplink": "1",
        "install_begin_time": _stamp(begin, 0),
        "display_height": P["display_height"], "package_name": PACKAGE_NAME,
        "os_name": "android", "tracking_enabled": "1",
    }


def build_attr(gaid, android_uuid, sec):
    return {
        "gps_adid_attempt": "1",
        "api_level": P["api_level"], "app_version": APP_VERSION,
        "app_token": APP_TOKEN,
        "created_at": _stamp(sec, MS["attr_c"]),
        "device_type": P["device_type"],
        "gps_adid": gaid, "foreground": "1",
        "ff_first_session_delay": "1",
        "device_name": P["device_name"], "needs_response_details": "1",
        "gps_adid_src": "service", "initiated_by": "backend",
        "os_version": P["os_version"], "android_uuid": android_uuid,
        "sent_at": _stamp(sec, MS["attr_s"]), "offline_mode_enabled": "0",
        "environment": P["environment"], "attribution_deeplink": "1",
        "package_name": PACKAGE_NAME, "os_name": "android", "ui_mode": "1",
        "tracking_enabled": "1",
    }


PARTNER_PARAMS = json.dumps(
    {"mixpanel_uuid": "$device:" + os.environ.get(
        "FUNNEL_MIXPANEL", str(uuid.uuid4()))},
    separators=(",", ":"))


def sign(fields, kind, sec):
    return mint_adj7(kind, fields, unix_sec=sec, include_block2=True,
                     campaign=CAMPAIGN)


def call(method, path, fields, auth):
    body = urllib.parse.urlencode(fields).encode() if method == "POST" else None
    target = (path if method == "POST" else path + "?" +
              urllib.parse.urlencode(fields, quote_via=urllib.parse.quote))
    import run_fiddler as _RF
    import socket as _skt
    if os.environ.get("FUNNEL_BLIND") == "1":
        # blind Conscrypt relay: CONNECT then plaintext (relay owns TLS)
        pp = _RF._proxy_addr()
        raw = _skt.create_connection(pp, timeout=30)
        raw.sendall(("CONNECT app.adjust.com:443 HTTP/1.1\r\n"
                     "Host: app.adjust.com:443\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += raw.recv(4096)
        if b" 200 " not in buf.split(b"\r\n", 1)[0]:
            raise RuntimeError("relay CONNECT failed: %r" % buf[:60])
        c = http.client.HTTPConnection("app.adjust.com", 443, timeout=30)
        c.sock = raw
    else:
        c, _ = _RF._connect("https", "app.adjust.com", 443, timeout=30)
    try:
        c.putrequest(method, target, skip_host=1, skip_accept_encoding=1)
        c.putheader("Client-SDK", CLIENT_SDK)
        c.putheader("Authorization", auth)
        if body is not None:
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
        c.putheader("User-Agent", APP_UA)
        c.putheader("Host", "app.adjust.com")
        c.putheader("Connection", "Keep-Alive")
        c.putheader("Accept-Encoding", "gzip")
        if body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == bytes((0x1f, 0x8b)):
            raw = gzip.decompress(raw)
        return r.status, raw.decode("utf-8", "replace")
    finally:
        c.close()


def main():
    gaid = os.environ.get("FUNNEL_GAID") or str(uuid.uuid4())
    android_uuid = str(uuid.uuid4())
    started = time.time()
    log("=" * 78)
    log("HUNCH INSTALL FUNNEL  app=%s  gaid=%s" % (PACKAGE_NAME, gaid))
    log("click: %s" % LINK)
    log("=" * 78)
    referrer = "utm_source=(not set)&utm_medium=(not set)"
    click_second = None
    if not DRY_RUN:
        got = (os.environ.get("FUNNEL_REFTAG")
               or open_direct_link(gaid))
        if isinstance(got, tuple):
            reftag, fired = got
        else:
            reftag, fired = got, None
        if not reftag:
            print("no reftag from direct link -- aborting")
            return 1
        referrer = reftag
        print("click    reftag %s  [t=+%.0fs]"
              % (referrer, time.time() - started))
        # click_time must be the moment the click actually fired, never
        # after it (engagement_time < click_time is an impossible story).
        # FUNNEL_CLICK_EPOCH carries a real device-tap time (epoch float).
        if fired:
            click_second = int(fired)
        elif os.environ.get("FUNNEL_CLICK_EPOCH"):
            click_second = int(float(os.environ["FUNNEL_CLICK_EPOCH"]))
        else:
            click_second = int(time.time()) - 1
    if click_second is None:
        click_second = int(time.time()) - 1
    last_run = {"mode": "dry-run" if DRY_RUN else "live",
                "app": PACKAGE_NAME, "gaid": gaid,
                "android_uuid": android_uuid,
                "reftag": referrer if not DRY_RUN else None,
                "click_second": click_second}
    with open(os.path.join(HERE, "last_run_hunch.json"), "w") as f:
        json.dump(last_run, f, indent=1)

    if not DRY_RUN:
        wait = click_second + SESSION_AT - time.time()
        if wait > 0:
            print("installing... (CTIT wall clock, %.0fs to the session)" % wait)
            time.sleep(wait)

    sec = signing_second()
    sf = build_session(gaid, android_uuid, sec, click_second)
    auth = sign(sf, "session", sec)
    print("signing  /session ...  %d fields  [t=+%.0fs]"
          % (len(sf), time.time() - started))
    if DRY_RUN:
        print("         signed -- not sending")
        return 0
    status, body = call("POST", "/session", sf, auth)
    payload = json.loads(body)
    log("session -> HTTP %d adid %s ask_in=%s"
        % (status, payload.get("adid"), payload.get("ask_in")))
    last_run["adid"] = payload.get("adid")
    last_run["session_ask_in"] = payload.get("ask_in")
    with open(os.path.join(HERE, "last_run_hunch.json"), "w") as f:
        json.dump(last_run, f, indent=1)

    time.sleep(0.3)
    sec2 = signing_second()
    cf = build_click(gaid, android_uuid, sec2, referrer, click_second)
    status2, body2 = call("POST", "/sdk_click", cf,
                          sign(cf, "click", sec2))
    log("sdk_click -> HTTP %d  %s" % (status2, body2[:120]))

    verdict = {}
    for i in range(6):
        time.sleep(3.2 if i == 0 else 1.5)
        sec3 = signing_second()
        af = build_attr(gaid, android_uuid, sec3)
        _st, b3 = call("GET", "/attribution", af,
                       sign(af, "attribution", sec3))
        p3 = json.loads(b3)
        verdict = p3.get("attribution") or {}
        ask_in = p3.get("ask_in")
        print("poll %-2d -> %-9s / %-9s ask_in=%s  [t=+%.0fs]"
              % (i + 1, verdict.get("network"), verdict.get("tracker_token"),
                 ask_in, time.time() - started))
        if verdict.get("network") and verdict["network"] != "Organic":
            break
        if isinstance(ask_in, (int, float)) and ask_in > 0:
            time.sleep(ask_in / 1000.0)
            continue
        if verdict.get("network") == "Organic" and not ask_in:
            if i >= 2:
                break
    log("FINAL ATTRIBUTION: %s" % json.dumps(verdict))
    last_run["attribution"] = verdict
    with open(os.path.join(HERE, "last_run_hunch.json"), "w") as f:
        json.dump(last_run, f, indent=1)
    if verdict.get("network", "Organic") != "Organic":
        print("*** NON-ORGANIC ***   %.0fs total" % (time.time() - started))
        for field in ("network", "tracker_token", "tracker_name", "campaign",
                      "adgroup", "engagement_time", "adid"):
            print("  %-16s %s" % (field, verdict.get(field)))
    else:
        print("*** Organic / not joined ***   %.0fs total"
              % (time.time() - started))
    return 0


if __name__ == "__main__":
    print("campaign  %s / %s (adj7, signing id %s, headers %s, native %s)"
          % (PACKAGE_NAME, APP_TOKEN, CAMPAIGN["adj_signing_id"],
             CAMPAIGN["headers_id"], CAMPAIGN["native_version"]))
    print("device    %s %s (Android %s, api %s)"
          % (P["device_manufacturer"], P["device_name"], P["os_version"],
             P["api_level"]))
    print("signer    adj7_pure (pure Python, cert %s...)" % CAMPAIGN["cert_sha1"][:12])
    raise SystemExit(main())
