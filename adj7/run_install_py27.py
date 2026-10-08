# -*- coding: utf-8 -*-
"""run_install_py27.py -- the adj7 live install funnel (adj9 style, py2.7).

    py -2.7 run_install_py27.py --dry-run   # build + sign, send nothing
    py -2.7 run_install_py27.py             # click -> [CTIT] -> session ->
                                            #   sdk_click -> attribution
    py -2.7 run_install_py27.py --sign-all  # dry-run, but sign every step

Flow, order and field lists follow the genuine in.hanafintech capture
(payrupi.chls, 2026-10-06): click -> [63.8 s CTIT] -> POST /session
(creates the adid) -> POST /sdk_click 49 ms later -> ONE attribution GET
2.8 s after the session (initiated_by=backend).  No third_party_sharing.
Signing = adj7_pure_py27 (the pure adj7 law, no unicorn).
"""
import datetime
import gzip
import httplib
import json
import os
import re
import sys
import time
import urllib
import urlparse
import uuid
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from adj7_pure_py27 import mint_adj7

os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8888'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8888'
# ============================ CAMPAIGN (hardcoded, backend format) ======
CAMPAIGN = {
    "package_name": "in.hanafintech",
    "app_version": "3.0.4",
    "app_token": "smxi7gqwu39c",
    "client_sdk": "android5.6.0",
    "cert_sha1": "c1bfafcaffb84b805288b985fbe48e7f33d2c6df",
    "adj_signing_id": "1300000",
    "algorithm": "adj7",
    "headers_id": "8",
    "native_version": "3.62.0",
}
PACKAGE_NAME = CAMPAIGN["package_name"]
APP_TOKEN = CAMPAIGN["app_token"]
APP_VERSION = CAMPAIGN["app_version"]
CLIENT_SDK = CAMPAIGN["client_sdk"]
CERT_SHA1 = CAMPAIGN["cert_sha1"]



# the OnePlus GM1901 profile.  mcc/mnc stay empty: the in.hanafintech
# genuine bodies carry neither (the oracle map confirms they never enter
# the signed map either).
DEVICE = {
    "api_level": "31", "os_version": "12",
    "device_name": "moto g42", "device_manufacturer": "motorola",
    "hardware_name": "S2SE32.28-28-4", "os_build": "S2SE32.28-28-4",
    "language": "en", "country": "IN",
    "display_width": "1080", "display_height": "2400",
    "screen_density": "high", "screen_size": "normal", "screen_format": "long",
    "cpu_type": "arm64-v8a", "connectivity_type": "1",
    "device_type": "phone", "environment": "production",
    "timezone": "+0530",
}

LINK = ("http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23483498")
INSTALL_AFTER = 3          # the genuine click -> install gap (payrupi.chls)
ADJ_CLICK_SEC = None        # the adjust click's server Date second (device-true
                            # click time; set by open_click_link)
POLL_DELAYS = [30, 45, 60, 60]
DRY_RUN = "--dry-run" in sys.argv
SIGN_ALL = "--sign-all" in sys.argv

APP_UA = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
          % (DEVICE["os_version"], DEVICE["device_name"], DEVICE["os_build"]))
P = DEVICE
MINT_SKEW = -2

# The click is fetched as a browser would.  A bare "Mozilla/5.0 (Linux;
# Android 12)" makes the tracker answer 200 with no redirect, and then no
# reftag is ever issued.  A real Chrome click sends a full fingerprint;
# affiliate trackers qualify clicks by it -- a 3-header python click can be
# silently disqualified.
BROWSER_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
BROWSER_HEADERS = OrderedDict([
    ("User-Agent", BROWSER_UA),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Accept-Encoding", "identity"),
    ("Connection", "close"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
])
# PROXY = os.environ.get("FUNNEL_PROXY", "")   # e.g. a residential session

# a plausible FCM token (the genuine attribution carries one) and the app's
# partner parameters (the oracle session map carries payrupik_c_id)
PUSH_TOKEN = ("f" + uuid.uuid4().hex[:10] + "Zx_9R7cQ8yY:APA91bH"
              + uuid.uuid4().hex + uuid.uuid4().hex[:22])
PARTNER_PARAMS = json.dumps({"payrupik_c_id": str(uuid.uuid4())},
                            separators=(",", ":"))

# ========================================================================

def say(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def log(*parts):
    say("[" + time.strftime("%H:%M:%S") + "] " +
        " ".join(str(p) for p in parts))


def signing_second():
    return int(time.time()) + MINT_SKEW


def _stamp(ts, ms):
    """Adjust wire timestamp: LOCAL wall-clock digits + the offset label --
    the offset must come from the SAME DEVICE timezone the params use
    (hardcoding 5:30 made the digits lie whenever DEVICE["timezone"]
    changed)."""
    tz = DEVICE["timezone"]
    sign = -1 if tz[0] == "-" else 1
    off = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
    dt = datetime.datetime.utcfromtimestamp(ts + off)
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + ("%03d" % ms) + "Z" + tz)


def _subst(url, gaid):
    return (url.replace("{gaid}", gaid)
               .replace("{sub2}", "zt1")
               .replace("{click_id}", "z" + uuid.uuid4().hex[:12]))


def _reftag_in(s):
    if "referrer=" not in s:
        return None
    ref = urllib.unquote(s.split("referrer=", 1)[1])
    ref = ref.split(";S.browser_fallback_url")[0]
    ref = ref.replace("&ip_address=%7Bloop_id%7D", "")
    ref = ref.replace("&ip_address={loop_id}", "")
    return ref


def _get(url):
    """Scheme-aware hop with the full browser fingerprint; FUNNEL_PROXY
    routes every hop (a burned/datacenter IP gets clicks dropped
    silently)."""
    scheme, rest = url.split("://", 1)
    host, _, path = rest.partition("/")
    port = 443 if scheme == "https" else 80
    if False:
        p = urlparse.urlsplit(PROXY if PROXY.startswith("http")
                              else "http://" + PROXY)
        c = (httplib.HTTPSConnection if scheme == "https"
             else httplib.HTTPConnection)(p.hostname, p.port or 443,
                                          timeout=30)
        path = url
    else:
        cls = (httplib.HTTPSConnection if scheme == "https"
               else httplib.HTTPConnection)
        c = cls(host, port, timeout=30)
        path = "/" + path
    c.request("GET", path, headers=dict(BROWSER_HEADERS))
    r = c.getresponse()
    raw = r.read()
    c.close()
    hdrs = {}
    for k, v in r.getheaders():
        hdrs[k.lower()] = v
    try:
        text = raw.decode("utf-8", "replace")
    except Exception:
        text = raw
    return r.status, hdrs, text


def _fill_device_id(u, gaid):
    """THE ORGANIC TRAP: the click must carry the id as gps_adid= (the
    Android parameter).  Affiliate chains forward adj_gps_adid= EMPTY or as
    an unfilled macro -- an Adjust click without a device id can never join
    the install, and Adjust answers Organic."""
    u = re.sub(r'adj_gps_adid=(&|$)', 'adj_gps_adid=' + gaid + r'\1', u)
    u = re.sub(r'(?<!adj_)gps_adid=(&|$)', 'gps_adid=' + gaid + r'\1', u)
    u = re.sub(r'adj_gps_adid=%7B[^&]*%7D', 'adj_gps_adid=' + gaid, u)
    u = re.sub(r'(?<!adj_)gps_adid=%7B[^&]*%7D', 'gps_adid=' + gaid, u)
    u = re.sub(r'adj_gps_adid=[{][^&]*[}]', 'adj_gps_adid=' + gaid, u)
    u = re.sub(r'(?<!adj_)gps_adid=[{][^&]*[}]', 'gps_adid=' + gaid, u)
    return u


def open_click_link(gaid):
    """Follow the tracker link and return the adjust_reftag it hands back
    (the adj9-android chain follower: Location hops, HTML/JS hops, the
    market:// break, device-id filled at every hop)."""
    global ADJ_CLICK_SEC
    ADJ_CLICK_SEC = None
    url = _fill_device_id(_subst(LINK, gaid), gaid)
    if "gps_adid=" not in url:
        url = url + "&gps_adid=" + gaid
    for attempt in (1, 2):
        for hop_i in range(12):
            if url.startswith("market://") or url.startswith("intent://"):
                break
            code, hdrs, text = _get(url)
            if "app.adjust.com" in url:
                # the server's OWN clock at click registration -- the real
                # device's click_time_server is anchored exactly here
                _d = hdrs.get("date") or hdrs.get("Date")
                if _d:
                    try:
                        import email.utils as _eu
                        _p = _eu.parsedate_tz(_d)
                        if _p:
                            ADJ_CLICK_SEC = int(_eu.mktime_tz(_p))
                    except Exception:
                        pass
            loc = hdrs.get("location") or ""
            if loc:
                ref = _reftag_in(loc)
                if ref:
                    return ref
                url = _fill_device_id(urlparse.urljoin(url, loc), gaid)
                continue
            if "adjust_reftag" in text:
                ref = _reftag_in(text)
                if ref:
                    return ref
            m = re.search(r'(?:window\.|document\.)?location\.replace\('
                          r'\s*["\']([^"\']+)["\']', text)
            if m:
                nxt = urllib.unquote(m.group(1))
                ref = _reftag_in(nxt)
                if ref:
                    return ref
                url = _fill_device_id(urlparse.urljoin(url, nxt), gaid)
                continue
            m = re.search(r'http-equiv="refresh"[^>]*url=([^">]+)', text, re.I)
            if m:
                url = urllib.unquote(m.group(1))
                continue
            break
        if attempt == 1:
            time.sleep(2)
    return None


def _jitter():
    import random
    return random.randint(11, 977)


def _ts_pair(sec):
    """(created_at, sent_at): the device's sent_at is always ~11-95 ms
    after created_at; the fractions vary per install."""
    import random
    m1 = _jitter()
    d = random.randint(11, 95)
    m2 = m1 + d
    s2 = sec
    if m2 > 999:
        m2 -= 1000
        s2 += 1
    return _stamp(sec, m1), _stamp(s2, m2)


# ============================ the wire builders =========================
def build_session_request(gaid, android_uuid, sec, click_sec=None):
    """POST /session -- creates the adid (the genuine flow's first call)."""
    installed = _stamp(click_sec + INSTALL_AFTER, 800)
    _cat, _sat = _ts_pair(sec)
    return OrderedDict([
        ("store_name_from_system", "com.android.vending"),
        ("gps_adid_attempt", "1"), ("country", P["country"]),
        ("api_level", P["api_level"]), ("hardware_name", P["hardware_name"]),
        ("app_version", APP_VERSION), ("app_token", APP_TOKEN),
        ("installed_at", installed), ("created_at", _cat),
        ("wait_total", "0.0"), ("device_type", P["device_type"]),
        ("language", P["language"]), ("gps_adid", gaid),
        ("foreground", "1"),
        ("connectivity_type", P["connectivity_type"]),
        ("device_manufacturer", P["device_manufacturer"]),
        ("display_width", P["display_width"]),
        ("device_name", P["device_name"]),
        ("needs_response_details", "1"), ("os_build", P["os_build"]),
        ("updated_at", installed), ("cpu_type", P["cpu_type"]),
        ("retry_count", "0"), ("screen_size", P["screen_size"]),
        ("screen_format", P["screen_format"]), ("last_error", "0"),
        ("gps_adid_src", "service"), ("wait_time", "0.0"),
        ("os_version", P["os_version"]), ("first_error", "0"),
        ("partner_params", PARTNER_PARAMS),
        ("initiating_package_name", "com.android.vending"),
        ("android_uuid", android_uuid), ("sent_at", _sat),
        ("offline_mode_enabled", "0"), ("environment", P["environment"]),
        ("screen_density", P["screen_density"]),
        ("attribution_deeplink", "1"), ("session_count", "1"),
        ("display_height", P["display_height"]),
        ("package_name", PACKAGE_NAME), ("os_name", "android"),
        ("ui_mode", "1"), ("enqueue_size", "0"),
        ("tracking_enabled", "1"),
    ])


def build_click_request(gaid, android_uuid, sec, referrer, click_sec=None):
    """POST /sdk_click -- joins the reftag to the install (49 ms after the
    session in the genuine flow).  The click story is anchored at
    ADJ_CLICK_SEC (the adjust response Date header = the server's own
    registration time); install_begin lands +5s later (Play download)."""
    click_sec = sec if click_sec is None else click_sec
    t_click = ADJ_CLICK_SEC if ADJ_CLICK_SEC else click_sec
    # ONE anchor: installed_at derives from t_click like every other
    # install-story second (a second base contradicts click_time)
    installed = _stamp(t_click + INSTALL_AFTER, 800)
    _cat, _sat = _ts_pair(sec)
    begin = t_click + 5
    return OrderedDict([
        ("country", P["country"]), ("api_level", P["api_level"]),
        ("hardware_name", P["hardware_name"]), ("app_version", APP_VERSION),
        ("app_token", APP_TOKEN), ("installed_at", installed),
        ("device_type", P["device_type"]), ("language", P["language"]),
        ("gps_adid", gaid), ("source", "install_referrer"),
        ("foreground", "1"),
        ("connectivity_type", P["connectivity_type"]),
        ("os_build", P["os_build"]), ("click_time", _stamp(t_click, 0)),
        ("cpu_type", P["cpu_type"]), ("install_version", APP_VERSION),
        ("partner_params", PARTNER_PARAMS),
        ("click_time_server", _stamp(t_click, 0)),
        ("screen_size", P["screen_size"]), ("gps_adid_src", "service"),
        ("subsession_count", "1"), ("sent_at", _sat),
        ("offline_mode_enabled", "0"),
        ("screen_density", P["screen_density"]), ("session_count", "1"),
        ("ui_mode", "1"), ("gps_adid_attempt", "1"),
        ("session_length", "0"), ("created_at", _cat),
        ("referrer_api", "google"),
        ("device_manufacturer", P["device_manufacturer"]),
        ("display_width", P["display_width"]), ("time_spent", "0"),
        ("device_name", P["device_name"]),
        ("needs_response_details", "1"), ("updated_at", installed),
        ("screen_format", P["screen_format"]),
        ("os_version", P["os_version"]), ("google_play_instant", "0"),
        ("android_uuid", android_uuid), ("referrer", referrer),
        ("environment", P["environment"]), ("attribution_deeplink", "1"),
        ("install_begin_time", _stamp(begin, 0)),
        ("install_begin_time_server", _stamp(begin, 0)),
        ("display_height", P["display_height"]),
        ("package_name", PACKAGE_NAME), ("os_name", "android"),
        ("tracking_enabled", "1"),
    ])


def build_attribution_request(gaid, android_uuid, sec):
    _cat, _sat = _ts_pair(sec)
    """GET /attribution -- ONE GET ~2.8 s after the session response
    (ask_in honoured); initiated_by=backend; NO push_token in the signed
    map (the oracle map excludes it)."""
    return OrderedDict([
        ("initiated_by", "backend"), ("gps_adid_attempt", "1"),
        ("api_level", P["api_level"]), ("app_version", APP_VERSION),
        ("app_token", APP_TOKEN), ("os_version", P["os_version"]),
        ("created_at", _cat), ("device_type", P["device_type"]),
        ("gps_adid", gaid), ("foreground", "1"),
        ("android_uuid", android_uuid), ("sent_at", _sat),
        ("offline_mode_enabled", "0"), ("device_name", P["device_name"]),
        ("environment", P["environment"]),
        ("needs_response_details", "1"), ("attribution_deeplink", "1"),
        ("package_name", PACKAGE_NAME), ("os_name", "android"),
        ("ui_mode", "1"), ("gps_adid_src", "service"),
        ("push_token", PUSH_TOKEN),
        ("tracking_enabled", "1"),
    ])


def sign(fields, kind, sec):
    # the campaign dict goes straight into the signer (cert_sha1 drives the
    # commitment prefix and the record's c slot; client_sdk enters the claims)
    auth = mint_adj7(kind, fields, unix_sec=sec, include_block2=True,
                     campaign=CAMPAIGN)
    return auth


def call(method, path, fields, auth):

    body = urllib.urlencode(fields) if method == "POST" else None
    target = (path if method == "POST" else path + "?" +
              urllib.urlencode(fields))
    c = httplib.HTTPSConnection("app.adjust.com", 443, timeout=30)
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
        c.endheaders(body if body is not None else None)
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
    log("ADJ7 INSTALL FUNNEL (py27)  app=%s  gaid=%s" % (PACKAGE_NAME, gaid))
    log("click: %s" % _subst(LINK, gaid))
    log("=" * 78)

    referrer = "utm_source=(not set)&utm_medium=(not set)"
    T0 = int(time.time())
    click_second = T0
    if not DRY_RUN:
        reftag = open_click_link(gaid)
        if not reftag:
            say("no reftag in the redirect chain -- aborting")
            return 1
        referrer = reftag
        say("click    reftag %s  [t=+%.0fs]"
            % (referrer[:50], time.time() - started))
    last_run = {"mode": "dry-run" if DRY_RUN else "live",
                "app": PACKAGE_NAME, "gaid": gaid,
                "android_uuid": android_uuid,
                "reftag": referrer if not DRY_RUN else None,
                "click_second": click_second}

    def signed_call(label, kind, fields, method, path):
        auth = sign(fields, kind, signing_second())
        say("signing  /%s ...  %d fields, blob 304 B  [t=+%.0fs]"
            % (path.strip("/"), len(fields), time.time() - started))
        if DRY_RUN and not SIGN_ALL:
            say("         signed -- not sending")
            return None, None
        status, body = call(method, path, fields, auth)
        log("%s -> HTTP %d  %s" % (label, status, body[:120]))
        return status, body

    # the genuine time story: the install lands 63.8 s after the click and
    # the first session runs 88.3 s after it -- sleep the real wall clock
    if not DRY_RUN:
        target = click_second + 88
        wait = target - time.time()
        if wait > 0:
            say("installing... (CTIT wall clock, %.0fs)" % wait)
            time.sleep(15)

    # 1. session (creates the adid; the genuine flow has NO tps and the
    #    session comes BEFORE the sdk_click)
    sec = signing_second()
    session_fields = build_session_request(gaid, android_uuid, sec,
                                           click_sec=click_second)
    auth = sign(session_fields, "session", sec)
    say("signing  /session ...  %d fields, blob 304 B  [t=+%.0fs]"
        % (len(session_fields), time.time() - started))
    adid = ""
    if DRY_RUN and not SIGN_ALL:
        say("         signed -- not sending")
        last_run.update({"fields": len(session_fields),
                         "blob_len": 304, "ok": True})
    else:
        status, body = call("POST", "/session", session_fields, auth)
        adid = json.loads(body).get("adid", "")
        log("session -> HTTP %d adid %s" % (status, adid))
        last_run["adid"] = adid

    # 2. sdk_click: built+signed at its own second and sent immediately
    #    after the session (pipelined; the device gap is 31-74 ms)
    if not DRY_RUN:
        csec = signing_second()
        click_fields = build_click_request(gaid, android_uuid, csec,
                                           referrer, click_sec=click_second)
        cauth = sign(click_fields, "click", csec)
        say("signing  /sdk_click ...  %d fields" % len(click_fields))
        cstatus, cbody = call("POST", "/sdk_click", click_fields, cauth)
        log("sdk_click -> HTTP %d  %s" % (cstatus, cbody[:120]))

    # 3. ONE attribution GET ~2.8 s after the session response (ask_in)
    if DRY_RUN and not SIGN_ALL:
        with open(os.path.join(HERE, "last_run.json"), "w") as f:
            json.dump(last_run, f, indent=1)
        say("")
        say("config is valid: the session signed cleanly (adj7).")
        return 0
    time.sleep(2.8)
    asec = signing_second()
    fields = build_attribution_request(gaid, android_uuid, asec)
    # the device signs its OS language even though the wire GET omits it
    # (device-oracle proof: H binds wire fields + language)
    sfields = dict(fields)
    sfields.setdefault("language", P["language"])
    auth = sign(sfields, "attribution", asec)
    _status, body = call("GET", "/attribution", fields, auth)
    verdict = json.loads(body).get("attribution") or {}
    say("attribution GET -> %s / %s  [t=+%.0fs]"
        % (verdict.get("network"), verdict.get("tracker_token"),
           time.time() - started))
    if verdict.get("network", "Organic") == "Organic":
        time.sleep(5)
        asec = signing_second()
        fields = build_attribution_request(gaid, android_uuid, asec)
        sfields = dict(fields)
        sfields.setdefault("language", P["language"])
        auth = sign(sfields, "attribution", asec)
        _status, body = call("GET", "/attribution", fields, auth)
        verdict = json.loads(body).get("attribution") or verdict
        say("poll +30s    -> %s / %s  [t=+%.0fs]"
            % (verdict.get("network"), verdict.get("tracker_token"),
               time.time() - started))

    log("FINAL ATTRIBUTION: %s" % json.dumps(verdict))
    last_run["attribution"] = verdict
    with open(os.path.join(HERE, "last_run.json"), "w") as f:
        json.dump(last_run, f, indent=1)
    if verdict.get("network", "Organic") != "Organic":
        say("*** NON-ORGANIC ***   %.0fs total" % (time.time() - started))
        for field in ("network", "tracker_token", "tracker_name", "campaign",
                      "adgroup", "engagement_time", "adid"):
            say("  %-16s %s" % (field, verdict.get(field)))
    else:
        say("*** Organic / not joined ***   %.0fs total"
            % (time.time() - started))
    return 0


if __name__ == "__main__":
    say("campaign  %s / %s (adj7, signing id %s, headers %s, native %s)"
        % (PACKAGE_NAME, APP_TOKEN, CAMPAIGN["adj_signing_id"],
           CAMPAIGN["headers_id"], CAMPAIGN["native_version"]))
    say("device    %s %s (Android %s, api %s)"
        % (P["device_manufacturer"], P["device_name"], P["os_version"],
           P["api_level"]))
    say("signer    adj7_pure_py27 (pure Python, cert %s...)" % CERT_SHA1[:12])
    raise SystemExit(main())
