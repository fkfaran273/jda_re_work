
"""run_install.py -- the adj7 live install funnel (adj9 style, py3).

    python run_install.py --dry-run     # build + sign, send nothing
    python run_install.py               # click -> [CTIT] -> session ->
                                        #   sdk_click -> attribution
    python run_install.py --sign-all    # dry-run, but sign every step

Flow, order and field lists follow the genuine in.hanafintech capture
(payrupi.chls, 2026-10-06): click -> [63.8 s CTIT] -> POST /session
(creates the adid; 43 fields) -> POST /sdk_click 49 ms later (44 fields)
-> ONE attribution GET 2.8 s after the session (19 params,
initiated_by=backend).  No third_party_sharing.  Signing = adj7_pure.
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

from adj7_pure import mint_adj7

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
    "display_width": "1080", "display_height": "2237",
    "screen_density": "high", "screen_size": "normal", "screen_format": "long",
    "cpu_type": "arm64-v8a", "connectivity_type": "1",
    "device_type": "phone", "environment": "production",
    "timezone": "+0530",
}

LINK = ("http://clicks.mobpine.com/api/track/v1/click"
        "?aff_id=3&offer_id=23483498&sub3={gaid}")
INSTALL_AFTER = 63          # the genuine click -> install gap (burger.saz)
INSTALL_AFTER = 14          # the PROVEN adj9 booking story: installed_at =
                            # click+14, session at click+30 (GAP)
ADJ_CLICK_SEC = None        # the adjust click's server Date second (set by
                            # open_click_link; the device-true click time)
CIT = 88                    # click->install CTIT (FUNNEL_CIT overrides)

def _jitter():
    """per-request millisecond fraction -- the device's vary every time."""
    import random
    return random.randint(11, 977)


def _ts_pair(sec):
    """(created_at, sent_at) for one request: the device's sent_at is always
    ~11-95 ms AFTER created_at (independent jitters produced inverted,
    physically impossible pairs)."""
    import random
    m1 = _jitter()
    d = random.randint(11, 95)
    m2 = m1 + d
    s2 = sec
    if m2 > 999:
        m2 -= 1000
        s2 += 1
    return _stamp(sec, m1), _stamp(s2, m2)
POLL_DELAYS = [30, 45, 60, 60]
DRY_RUN = "--dry-run" in sys.argv
SIGN_ALL = "--sign-all" in sys.argv

CLICK_UA = ("Mozilla/5.0 (Linux; Android 10; GM1901) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36")
PUSH_TOKEN = ("f" + uuid.uuid4().hex[:10] + "Zx_9R7cQ8yY:APA91bH"
              + uuid.uuid4().hex + uuid.uuid4().hex[:22])
PARTNER_PARAMS = json.dumps({"payrupik_c_id": str(uuid.uuid4())},
                            separators=(",", ":"))
# per-app wire extras the builders add (all campaign-driven):
#   partner_params: the app's own payload (hanafintech session+click,
#     hunch click only); ff_first_session_delay: the Flutter SDK's
#     wire-only field (never claimed -- not in the pool).
PP_SESSION = CAMPAIGN.get("partner_params_session", PARTNER_PARAMS)
PP_CLICK = CAMPAIGN.get("partner_params_click", PARTNER_PARAMS)
FF_DELAY = CAMPAIGN.get("ff_first_session_delay")

# The click is fetched as a browser would.  A bare "Mozilla/5.0 (Linux;
# Android 12)" makes the tracker answer 200 with no redirect, and then no
# reftag is ever issued.  A real Chrome click sends a full fingerprint;
# affiliate trackers qualify clicks by it -- a 3-header python click can be
# silently disqualified.
BROWSER_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
BROWSER_HEADERS = {
    "User-Agent": BROWSER_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}
PROXY = os.environ.get("FUNNEL_PROXY", "")   # e.g. a residential session

def _proxied(scheme, host):
    if not PROXY:
        return None
    p = urllib.parse.urlsplit(PROXY if PROXY.startswith("http")
                              else "http://" + PROXY)
    return {"http": p, "https": p}

APP_UA = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
          % (DEVICE["os_version"], DEVICE["device_name"], DEVICE["os_build"]))
P = DEVICE
MINT_SKEW = -2

# ========================================================================

def signing_second():
    return int(time.time()) + MINT_SKEW


def _stamp(ts, ms):
    """Local wall-clock digits + the offset label — the genuine device
    stamps created_at/sent_at in LOCAL time (+0530), not UTC digits."""
    sign = 1 if DEVICE["timezone"][0] != "-" else -1
    off = (sign * (int(DEVICE["timezone"][1:3]) * 3600
                   + int(DEVICE["timezone"][3:5]) * 60))
    dt = datetime.fromtimestamp(ts + off, timezone.utc)
    return (dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms) + "Z"
            + DEVICE["timezone"])


def log(*parts):
    print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"),
                       " ".join(str(p) for p in parts)))
    sys.stdout.flush()


def _subst(url, gaid):
    return (url.replace("{gaid}", gaid).replace("{idfa}", gaid)
               .replace("{sub2}", "zt1")
               .replace("{click_id}", "z" + uuid.uuid4().hex[:12]))


def _reftag_in(s):
    if "referrer=" not in s:
        return None
    ref = urllib.parse.unquote(s.split("referrer=", 1)[1])
    ref = ref.split(";S.browser_fallback_url")[0]
    return re.sub(r"&ip_address=%7B[^&]*%7D", "", ref)


def _get(url):
    """Fetch the click as a REAL Chrome browser would: curl_cffi with the
    real Chrome TLS fingerprint and HTTP/2."""
    from curl_cffi import requests as _cr
    r = _cr.get(url, headers=BROWSER_HEADERS, timeout=30,
                impersonate="chrome131_android", allow_redirects=False)
    return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text


def _fill_device_id(u, gaid):
    """THE ORGANIC TRAP: the click must carry the id as gps_adid= (the
    Android parameter).  Affiliate chains forward adj_gps_adid= EMPTY or as
    an unfilled macro -- an Adjust click without a device id can never join
    the install, and Adjust answers Organic."""
    u = re.sub(r'adj_gps_adid=(&|$)', 'adj_gps_adid=' + gaid + r'', u)
    u = re.sub(r'(?<!adj_)gps_adid=(&|$)', 'gps_adid=' + gaid + r'', u)
    u = re.sub(r'adj_gps_adid=%7B[^&]*%7D', 'adj_gps_adid=' + gaid, u)
    u = re.sub(r'(?<!adj_)gps_adid=%7B[^&]*%7D', 'gps_adid=' + gaid, u)
    u = re.sub(r'adj_gps_adid=[{][^&]*[}]', 'adj_gps_adid=' + gaid, u)
    u = re.sub(r'(?<!adj_)gps_adid=[{][^&]*[}]', 'gps_adid=' + gaid, u)
    return u


def open_click_link(gaid):
    """Visit the tracker link (twice; some chains redirect on a repeat hit)
    and return the adjust_reftag."""
    global ADJ_CLICK_SEC
    ADJ_CLICK_SEC = None
    pre = os.environ.get("FUNNEL_REFTAG")
    if pre:
        # the click already fired (browser_click.py, real Chrome): the
        # reftag + the server's Date second come from there
        cs = os.environ.get("FUNNEL_CLICK_SEC")
        ADJ_CLICK_SEC = int(cs) if cs else None
        return pre
    url = os.environ.get("FUNNEL_CLICK_URL") or _subst(LINK, gaid)
    url = url.replace("{gaid}", gaid)
    if not NO_GPS_APPEND:
        url = _fill_device_id(url, gaid)
        if "gps_adid=" not in url:
            url += "&gps_adid=" + gaid
    for attempt in (1, 2):
        for hop in range(12):
            if not (url.startswith("http://") or url.startswith("https://")):
                # market:// / intent:// Play hops: the reftag rides in the
                # referrer= parameter of the URL itself
                ref = _reftag_in(url)
                if ref:
                    return ref
                break
            try:
                status, hdrs, text = _get(url)
            except Exception as exc:
                log("click hop error: %r" % (exc,))
                break
            if "app.adjust.com" in url:
                # the server's OWN clock at click registration -- the real
                # device's click_time_server is anchored exactly here (via
                # the Play referrer).  Claiming an earlier time is a lie the
                # server can check.
                _d = hdrs.get("date") or hdrs.get("Date")
                if _d:
                    try:
                        import email.utils as _eu
                        ADJ_CLICK_SEC = int(_eu.parsedate_to_datetime(_d).timestamp())
                    except Exception:
                        ADJ_CLICK_SEC = None
            loc = hdrs.get("Location") or hdrs.get("location")
            if loc:
                # keep unfilled macros exactly as the device's chain receives
                # them (the device's own booking clicks carry ip_address=
                # {loop_id} and adjust ignores it) -- no rewriting
                loc = _fill_device_id(loc, gaid)
                if NO_GPS_APPEND:
                    # strip the device id entirely: the genuine phone click
                    # (raw browser) carries NO gps_adid -- probabilistic path
                    loc = re.sub(r"&adj_gps_adid=[^&]*", "", loc)
                    loc = re.sub(r"&gps_adid=[^&]*", "", loc)
                ref = _reftag_in(loc)
                if ref:
                    return ref
                url = loc
                continue
            if "adjust_reftag" in text:
                ref = _reftag_in(text)
                if ref:
                    return ref
            m = re.search(r"(?:window\.|document\.)?location\.replace\("
                          r"\s*[\"']([^\"']+)[\"']", text)
            if m:
                nxt = m.group(1)
                ref = _reftag_in(nxt)
                if ref:
                    return ref
                url = nxt
                continue
            break
        if attempt == 1:
            time.sleep(2)
    return None


# ============================ the wire builders =========================
def build_tps_request(gaid, android_uuid, sec):
    """POST /third_party_sharing -- capture sid 27 (28 fields)."""
    return {
        "gps_adid_attempt": "1", "api_level": P["api_level"],
        "app_version": APP_VERSION, "app_token": APP_TOKEN,
        "created_at": _stamp(sec, _jitter()), "wait_total": "0.0",
        "device_type": P["device_type"], "gps_adid": gaid,
        "foreground": "1", "device_name": P["device_name"],
        "needs_response_details": "1", "retry_count": "0",
        "last_error": "0", "gps_adid_src": "service", "wait_time": "0.0",
        "os_version": P["os_version"], "first_error": "0",
        "sharing": "enable", "android_uuid": android_uuid,
        "sent_at": _stamp(sec, 213), "offline_mode_enabled": "0",
        "environment": P["environment"], "attribution_deeplink": "1",
        "package_name": PACKAGE_NAME, "os_name": "android", "ui_mode": "1",
        "enqueue_size": "0", "tracking_enabled": "1",
    }


def build_click_request(gaid, android_uuid, sec, referrer, click_sec=None):
    """POST /sdk_click -- capture sid 28 (47 fields).  The click story is
    anchored at ADJ_CLICK_SEC (the adjust response Date header = the
    server's own registration time); the device's clock matches it within
    0-1s and install_begin lands +5-6s later (Play download start)."""
    global CIT
    click_sec = sec if click_sec is None else click_sec
    t_click = ADJ_CLICK_SEC if ADJ_CLICK_SEC else click_sec
    installed = _stamp(click_sec + int((CIT - 22) if CIT > 100 else INSTALL_AFTER), 800)
    _cat, _sat = _ts_pair(sec)
    begin = t_click + 5
    c = {
        "country": P["country"], "api_level": P["api_level"],
        "hardware_name": P["hardware_name"], "app_version": APP_VERSION,
        "app_token": APP_TOKEN, "installed_at": installed,
        "device_type": P["device_type"], "language": P["language"],
        "gps_adid": gaid, "source": "install_referrer", "foreground": "1",
        "connectivity_type": P["connectivity_type"], "os_build": P["os_build"],
        "click_time": _stamp(t_click, 0), "cpu_type": P["cpu_type"],
        "install_version": APP_VERSION,
        "screen_size": P["screen_size"], "gps_adid_src": "service",
        "subsession_count": "1", "sent_at": _sat,
        "offline_mode_enabled": "0", "screen_density": P["screen_density"],
        "session_count": "1", "ui_mode": "1", "gps_adid_attempt": "1",
        "session_length": "0", "created_at": _cat,
        "referrer_api": "google",
        "device_manufacturer": P["device_manufacturer"],
        "display_width": P["display_width"], "time_spent": "0",
        "device_name": P["device_name"], "needs_response_details": "1",
        "updated_at": installed, "screen_format": P["screen_format"],
        "click_time_server": _stamp(t_click, 0),
        "os_version": P["os_version"], "google_play_instant": "0",
        "install_begin_time_server": _stamp(begin, 0),
        "android_uuid": android_uuid, "referrer": referrer,
        "environment": P["environment"], "attribution_deeplink": "1",
        "install_begin_time": _stamp(begin, 0),
        "display_height": P["display_height"], "package_name": PACKAGE_NAME,
        "os_name": "android", "tracking_enabled": "1",
    }
    if FF_DELAY:
        c["ff_first_session_delay"] = FF_DELAY
    if PP_CLICK:
        c["partner_params"] = PP_CLICK
    return c


def build_session_request(gaid, android_uuid, sec, click_sec=None):
    """POST /session -- capture sid 90 (46 fields, queue_size "0")."""
    installed = _stamp(click_sec + int((CIT - 22) if CIT > 100 else INSTALL_AFTER), 800)
    _cat, _sat = _ts_pair(sec)
    s = {
        "store_name_from_system": "com.android.vending",
        "gps_adid_attempt": "1", "country": P["country"],
        "api_level": P["api_level"], "hardware_name": P["hardware_name"],
        "app_version": APP_VERSION, "app_token": APP_TOKEN,
        "installed_at": installed, "created_at": _cat,
        "wait_total": "0.0", "device_type": P["device_type"],
        "language": P["language"], "gps_adid": gaid, "foreground": "1",
        "connectivity_type": P["connectivity_type"],
        "device_manufacturer": P["device_manufacturer"],
        "display_width": P["display_width"], "device_name": P["device_name"],
        "needs_response_details": "1", "os_build": P["os_build"],
        "updated_at": installed, "cpu_type": P["cpu_type"],
        "retry_count": "0", "screen_size": P["screen_size"],
        "screen_format": P["screen_format"], "last_error": "0",
        "gps_adid_src": "service", "wait_time": "0.0",
        "os_version": P["os_version"], "first_error": "0",
        "android_uuid": android_uuid, "sent_at": _sat,
        "offline_mode_enabled": "0", "environment": P["environment"],
        "screen_density": P["screen_density"], "attribution_deeplink": "1",
        "session_count": "1", "display_height": P["display_height"],
        "package_name": PACKAGE_NAME,
        "initiating_package_name": "com.android.vending",
        "os_name": "android", "ui_mode": "1",
        "enqueue_size": "0", "tracking_enabled": "1",
    }
    if FF_DELAY:
        s["ff_first_session_delay"] = FF_DELAY
    if PP_SESSION:
        s["partner_params"] = PP_SESSION
    return s


def build_attribution_request(gaid, android_uuid, sec):
    """GET /attribution -- capture sid 96 (22 query params)."""
    _cat, _sat = _ts_pair(sec)
    a = {
        "initiated_by": os.environ.get("FUNNEL_ASK", "backend") + "", "gps_adid_attempt": "1",
        "api_level": P["api_level"], "app_version": APP_VERSION,
        "app_token": APP_TOKEN, "os_version": P["os_version"],
        "created_at": _cat, "device_type": P["device_type"],
        "gps_adid": gaid, "foreground": "1", "android_uuid": android_uuid,
        "sent_at": _sat, "offline_mode_enabled": "0",
        "device_name": P["device_name"], "environment": P["environment"],
        "needs_response_details": "1", "attribution_deeplink": "1",
        "package_name": PACKAGE_NAME, "os_name": "android", "ui_mode": "1",
        "gps_adid_src": "service",
        "tracking_enabled": "1",
    }
    if FF_DELAY:
        a["ff_first_session_delay"] = FF_DELAY
    return a


def sign(fields, kind, sec):
    """The campaign dict goes straight into the signer (cert_sha1 drives the
    commitment prefix and the record's c slot; client_sdk enters the
    claims) -- nothing wired through module globals."""
    return mint_adj7(kind, fields, unix_sec=sec, include_block2=True,
                     campaign=CAMPAIGN)


NO_GPS_APPEND = bool(os.environ.get("FUNNEL_NO_GPS"))
NO_SIG = bool(os.environ.get("FUNNEL_NO_SIG"))

PROXIES = None
if os.environ.get("FUNNEL_PROXY"):
    PROXIES = {"http": os.environ["FUNNEL_PROXY"], "https": os.environ["FUNNEL_PROXY"]}

_SESSION = None
def _sess():
    """One keep-alive session, plain requests -- EXACTLY the proven adj9
    funnel's transport (4 headers only; no browser-header injection)."""
    global _SESSION
    if _SESSION is None:
        import requests as _req
        _SESSION = _req.Session()
        _SESSION.headers.clear()
        _SESSION.headers["Accept-Encoding"] = "gzip"   # the device's OkHttp
        _SESSION.proxies.update(PROXIES or {})
    return _SESSION


def call(method, path, fields, auth):
    """The API transport: python-requests on one keep-alive session."""
    body = urllib.parse.urlencode(fields).encode() if method == "POST" else None
    url = "https://app.adjust.com" + path
    if method == "GET":
        url = url + "?" + urllib.parse.urlencode(fields)
        body = None
    headers = {
        "Client-SDK": CLIENT_SDK,
        "User-Agent": APP_UA,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if not NO_SIG:
        headers["Authorization"] = auth
    if body is None:
        del headers["Content-Type"]      # a GET carries no body
    r = _sess().request(method, url, data=body, headers=headers, timeout=30)
    return r.status_code, r.text


def main():
    gaid = os.environ.get("FUNNEL_GAID") or str(uuid.uuid4())
    android_uuid = str(uuid.uuid4())
    started = time.time()
    log("=" * 78)
    log("ADJ7 INSTALL FUNNEL  app=%s  gaid=%s" % (PACKAGE_NAME, gaid))
    log("click: %s" % _subst(LINK, gaid))
    log("=" * 78)

    referrer = "utm_source=(not set)&utm_medium=(not set)"
    T0 = int(time.time())
    click_second = T0
    if not DRY_RUN:
        reftag = open_click_link(gaid)
        if not reftag:
            print("no reftag in the redirect chain -- aborting")
            return 1
        referrer = reftag
        print("click    reftag %s  [t=+%.0fs]"
              % (referrer[:50], time.time() - started))
    last_run = {"mode": "dry-run" if DRY_RUN else "live",
                "app": PACKAGE_NAME, "gaid": gaid,
                "android_uuid": android_uuid,
                "reftag": referrer if not DRY_RUN else None,
                "click_second": click_second}

    def signed_call(label, kind, fields, method, path):
        auth = sign(fields, kind, signing_second())
        print("signing  /%s ...  %d fields, blob 304 B  [t=+%.0fs]"
              % (path.strip("/"), len(fields), time.time() - started))
        if DRY_RUN and not SIGN_ALL:
            print("         signed -- not sending")
            return None, None
        status, body = call(method, path, fields, auth)
        log("%s -> HTTP %d  %s" % (label, status, body[:120]))
        return status, body

    # the genuine time story: the install lands 63.8 s after the click and
    # the first session runs 88.3 s after it -- sleep the real wall clock so
    # created_at/installed_at agree with when the requests actually go out.
    # FUNNEL_CIT overrides the CTIT: the fresh device bookings used 204-433s
    # click->session; the <=93s device flows (and every funnel run at 88s)
    # answered Organic.
    CIT = int(os.environ.get("FUNNEL_CIT", "88"))
    if not DRY_RUN:
        target = click_second + CIT
        wait = target - time.time()
        if wait > 0:
            log("installing... (CTIT wall clock, %.0fs)" % wait)
            time.sleep(wait)

    # 1+2. session then sdk_click PIPELINED on the same keep-alive
    #    connection: the genuine SDK fires the click 31-74 ms after the
    #    session SEND (it does not wait for the response), so build and
    #    sign both first, then send back-to-back.  One signing second per
    #    request (created_at second == header second, as on the device).
    sec = signing_second()
    session_fields = build_session_request(gaid, android_uuid, sec,
                                           click_sec=click_second)
    auth = sign(session_fields, "session", sec)
    print("signing  /session ...  %d fields, blob 304 B  [t=+%.0fs]"
          % (len(session_fields), time.time() - started))
    adid = ""
    if DRY_RUN and not SIGN_ALL:
        print("         signed -- not sending")
        last_run.update({"fields": len(session_fields),
                         "blob_len": 304, "ok": True})
    else:
        status, body = call("POST", "/session", session_fields, auth)
        # the click is built at ITS own second and goes out immediately --
        # the 31-74 ms device gap, not response+~1 s
        csec = signing_second()
        click_fields = build_click_request(gaid, android_uuid, csec,
                                           referrer, click_sec=click_second)
        cauth = sign(click_fields, "click", csec)
        print("signing  /sdk_click ...  %d fields, blob 304 B  [t=+%.0fs]"
              % (len(click_fields), time.time() - started))
        cstatus, cbody = call("POST", "/sdk_click", click_fields, cauth)
        adid = json.loads(body).get("adid", "")
        log("session -> HTTP %d adid %s" % (status, adid))
        log("sdk_click -> HTTP %d  %s" % (cstatus, cbody[:120]))
        last_run["adid"] = adid

    # 3. ONE attribution GET ~2.8 s after the session response (ask_in)
    if DRY_RUN and not SIGN_ALL:
        with open(os.path.join(HERE, "last_run.json"), "w") as f:
            json.dump(last_run, f, indent=1)
        print()
        print("config is valid: the session signed cleanly (adj7).")
        return 0
    time.sleep(2.8)
    asec = signing_second()
    fields = build_attribution_request(gaid, android_uuid, asec)
    # the device signs its OS language even though the wire GET omits it
    # (device-oracle proof: H binds wire fields + language)
    sfields = dict(fields)
    if "@" not in CLIENT_SDK:      # native SDK signs language; Flutter does not
        sfields.setdefault("language", P["language"])
    auth = sign(sfields, "attribution", asec)
    _status, body = call("GET", "/attribution", fields, auth)
    verdict = json.loads(body).get("attribution") or {}
    print("attribution GET -> %s / %s  [t=+%.0fs]"
          % (verdict.get("network"), verdict.get("tracker_token"),
             time.time() - started))
    if verdict.get("network", "Organic") == "Organic":
        # attribution lags sometimes: one confirmation poll
        time.sleep(30)
        asec = signing_second()
        fields = build_attribution_request(gaid, android_uuid, asec)
        sfields = dict(fields)
        if "@" not in CLIENT_SDK:
            sfields.setdefault("language", P["language"])
        auth = sign(sfields, "attribution", asec)
        _status, body = call("GET", "/attribution", fields, auth)
        verdict = json.loads(body).get("attribution") or verdict
        print("poll +30s    -> %s / %s  [t=+%.0fs]"
              % (verdict.get("network"), verdict.get("tracker_token"),
                 time.time() - started))

    log("FINAL ATTRIBUTION: %s" % json.dumps(verdict))
    last_run["attribution"] = verdict
    with open(os.path.join(HERE, "last_run.json"), "w") as f:
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
    print("signer    adj7_pure (pure Python, cert %s...)" % CERT_SHA1[:12])
    raise SystemExit(main())
