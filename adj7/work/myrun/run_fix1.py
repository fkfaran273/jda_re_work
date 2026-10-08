
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
INSTALL_AFTER = 42          # golden payrupik_new: click 15:40:25 -> installed 15:41:06 (+41.6 s)
POLL_DELAYS = [30, 45, 60, 60]
DRY_RUN = "--dry-run" in sys.argv
SIGN_ALL = "--sign-all" in sys.argv

CLICK_UA = ("Mozilla/5.0 (Linux; Android 10; GM1901) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36")
PUSH_TOKEN = ("f" + uuid.uuid4().hex[:10] + "Zx_9R7cQ8yY:APA91bH"
              + uuid.uuid4().hex + uuid.uuid4().hex[:22])
PARTNER_PARAMS = json.dumps({"payrupik_c_id": str(uuid.uuid4())},
                            separators=(",", ":"))

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
    return (url.replace("{gaid}", gaid)
               .replace("{sub2}", "zt1")
               .replace("{click_id}", "z" + uuid.uuid4().hex[:12]))


def _reftag_in(s):
    if "referrer=" not in s:
        return None
    ref = urllib.parse.unquote(s.split("referrer=", 1)[1])
    ref = ref.split(";S.browser_fallback_url")[0]
    ref = re.sub(r"&ip_address=%7B[^&]*%7D", "", ref)
    return re.sub(r"&ip_address=\{[^&]*\}", "", ref)


def _get(url):
    """Scheme-aware hop with the full browser fingerprint; --proxy routes
    every hop (a burned/datacenter IP gets clicks dropped silently)."""
    scheme, rest = url.split("://", 1)
    host, _, path = rest.partition("/")
    port = 443 if scheme == "https" else 80
    if PROXY:
        p = urllib.parse.urlsplit(PROXY if PROXY.startswith("http")
                                  else "http://" + PROXY)
        c = (http.client.HTTPSConnection if scheme == "https"
             else http.client.HTTPConnection)(p.hostname, p.port or 443,
                                              timeout=30)
        path = url
    else:
        cls = (http.client.HTTPSConnection if scheme == "https"
               else http.client.HTTPConnection)
        c = cls(host, port, timeout=30)
        path = "/" + path
    c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    for k, v in BROWSER_HEADERS.items():
        c.putheader(k, v)
    c.putheader("Host", host)
    c.endheaders()
    r = c.getresponse()
    raw = r.read()
    if raw[:2] == bytes((0x1f, 0x8b)):
        raw = gzip.decompress(raw)
    c.close()
    return r.status, dict(r.getheaders()), raw.decode("utf-8", "replace")


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
    """Visit the tracker link (twice; some chains redirect on a repeat hit)
    and return the adjust_reftag."""
    url = _fill_device_id(_subst(LINK, gaid), gaid)
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
            loc = hdrs.get("Location") or hdrs.get("location")
            if loc:
                # mobpine's redirect carries an unfilled {loop_id} macro in
                # ip_address= -- strip it before it poisons the adjust click
                loc = loc.replace("&ip_address=%7Bloop_id%7D", "")
                loc = loc.replace("&ip_address={loop_id}", "")
                loc = _fill_device_id(loc, gaid)
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
        "created_at": _stamp(sec, 198), "wait_total": "0.0",
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
    """POST /sdk_click -- capture sid 28 (47 fields)."""
    click_sec = sec if click_sec is None else click_sec
    installed = _stamp(click_sec + INSTALL_AFTER, 800)
    begin = click_sec + 1
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
        "subsession_count": "1", "sent_at": _stamp(sec, 263),
        "offline_mode_enabled": "0", "screen_density": P["screen_density"],
        "session_count": "1", "ui_mode": "1", "gps_adid_attempt": "1",
        "session_length": "0", "created_at": _stamp(sec, 252),
        "referrer_api": "google",
        "device_manufacturer": P["device_manufacturer"],
        "display_width": P["display_width"], "time_spent": "0",
        "device_name": P["device_name"], "needs_response_details": "1",
        "updated_at": installed, "screen_format": P["screen_format"],
        "click_time_server": _stamp(click_sec, 0),
        "os_version": P["os_version"], "google_play_instant": "0",
        "install_begin_time_server": _stamp(begin, 0),
        "android_uuid": android_uuid, "referrer": referrer,
        "environment": P["environment"], "attribution_deeplink": "1",
        "install_begin_time": _stamp(begin, 0),
        "display_height": P["display_height"], "package_name": PACKAGE_NAME,
        "os_name": "android", "tracking_enabled": "1",
    }


def build_session_request(gaid, android_uuid, sec, click_sec=None):
    """POST /session -- capture sid 90 (46 fields, queue_size "0")."""
    installed = _stamp(click_sec + INSTALL_AFTER, 800)
    return {
        "store_name_from_system": "com.android.vending",
        "gps_adid_attempt": "1", "country": P["country"],
        "api_level": P["api_level"], "hardware_name": P["hardware_name"],
        "partner_params": PARTNER_PARAMS,
        "app_version": APP_VERSION, "app_token": APP_TOKEN,
        "installed_at": installed, "created_at": _stamp(sec, 198),
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
        "android_uuid": android_uuid, "sent_at": _stamp(sec, 523),
        "offline_mode_enabled": "0", "environment": P["environment"],
        "screen_density": P["screen_density"], "attribution_deeplink": "1",
        "session_count": "1", "display_height": P["display_height"],
        "package_name": PACKAGE_NAME,
        "initiating_package_name": "com.android.vending",
        "os_name": "android", "ui_mode": "1",
        "enqueue_size": "0", "tracking_enabled": "1",
    }


def build_attribution_request(gaid, android_uuid, sec):
    """GET /attribution -- capture sid 96 (22 query params)."""
    return {
        "initiated_by": "backend", "gps_adid_attempt": "1",
        "api_level": P["api_level"], "app_version": APP_VERSION,
        "app_token": APP_TOKEN, "os_version": P["os_version"],
        "created_at": _stamp(sec, 539), "device_type": P["device_type"],
        "gps_adid": gaid, "foreground": "1", "android_uuid": android_uuid,
        "sent_at": _stamp(sec, 569), "offline_mode_enabled": "0",
        "device_name": P["device_name"], "environment": P["environment"],
        "needs_response_details": "1", "attribution_deeplink": "1",
        "package_name": PACKAGE_NAME, "os_name": "android", "ui_mode": "1",
        "gps_adid_src": "service",
        "tracking_enabled": "1",
    }


def build_event_request(gaid, android_uuid, sec, click_sec=None):
    """POST /event -- fresh 2016(c) capture sid 45: event_token=y3sjx5,
    seq=1, event_count=1, 48 fields, no install_* echo here."""
    return {
        "country": P["country"], "api_level": P["api_level"],
        "hardware_name": P["hardware_name"],
        "partner_params": PARTNER_PARAMS,
        "app_version": APP_VERSION, "app_token": APP_TOKEN,
        "wait_total": "0.0", "device_type": P["device_type"],
        "language": P["language"], "gps_adid": gaid, "foreground": "1",
        "connectivity_type": P["connectivity_type"],
        "os_build": P["os_build"], "cpu_type": P["cpu_type"],
        "retry_count": "0", "screen_size": P["screen_size"],
        "gps_adid_src": "service", "subsession_count": "1",
        "wait_time": "0.0", "first_error": "0",
        "sent_at": _stamp(sec, 312),
        "offline_mode_enabled": "0", "screen_density": P["screen_density"],
        "session_count": "1", "ui_mode": "1", "enqueue_size": "0",
        "gps_adid_attempt": "1", "event_count": "1", "session_length": "5",
        "created_at": _stamp(sec, 280),
        "device_manufacturer": P["device_manufacturer"],
        "display_width": P["display_width"], "event_token": "y3sjx5",
        "time_spent": "5", "device_name": P["device_name"],
        "needs_response_details": "1", "screen_format": P["screen_format"],
        "last_error": "0", "seq": "1", "os_version": P["os_version"],
        "callback_params": json.dumps({"google_adid": gaid}, separators=(",", ":")),
        "android_uuid": android_uuid, "environment": P["environment"],
        "attribution_deeplink": "1", "display_height": P["display_height"],
        "package_name": PACKAGE_NAME, "os_name": "android",
        "tracking_enabled": "1",
    }


def sign(fields, kind, sec):
    """The campaign dict goes straight into the signer (cert_sha1 drives the
    commitment prefix and the record's c slot; client_sdk enters the
    claims) -- nothing wired through module globals."""
    return mint_adj7(kind, fields, unix_sec=sec, include_block2=True,
                     campaign=CAMPAIGN)


def call(method, path, fields, auth):
    body = urllib.parse.urlencode(fields).encode() if method == "POST" else None
    target = (path if method == "POST" else path + "?" +
              urllib.parse.urlencode(fields, quote_via=urllib.parse.quote))
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        # header order per the genuine capture: Client-SDK, Authorization,
        # Content-Type, User-Agent, Host, Connection, Accept-Encoding,
        # Content-Length last
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
    log("ADJ7 INSTALL FUNNEL  app=%s  gaid=%s" % (PACKAGE_NAME, gaid))
    log("click: %s" % _subst(LINK, gaid))
    log("=" * 78)

    referrer = "utm_source=(not set)&utm_medium=(not set)"
    if not DRY_RUN:
        reftag = open_click_link(gaid)
        if not reftag:
            print("no reftag in the redirect chain -- aborting")
            return 1
        referrer = reftag
        print("click    reftag %s  [t=+%.0fs]"
              % (referrer, time.time() - started))
    # BOOKING_DIFF ranking: the click_time stamp must NOT precede the
    # actual go-through of the Adjust click on the wire — taken after the
    # redirect chain produced the reftag.
    click_second = int(time.time()) - 1
    T0 = click_second
    last_run = {"mode": "dry-run" if DRY_RUN else "live",
                "app": PACKAGE_NAME, "gaid": gaid,
                "android_uuid": android_uuid,
                "reftag": referrer if not DRY_RUN else None,
                "click_second": click_second}

    def signed_call(label, kind, fields, method, path, sec=None):
        if sec is None:
            sec = signing_second()
        auth = sign(fields, kind, sec)
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
    # created_at/installed_at agree with when the requests actually go out
    if not DRY_RUN:
        target = click_second + 88
        wait = target - time.time()
        if wait > 0:
            print("installing... (CTIT wall clock, %.0fs)" % wait)
            time.sleep(wait)

    # 1. session (creates the adid; the genuine flow has NO tps and the
    #    session comes BEFORE the sdk_click)
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
        adid = json.loads(body).get("adid", "")
        log("session -> HTTP %d adid %s" % (status, adid))
        last_run["adid"] = adid

    # 2. sdk_click (49 ms after the session in the genuine flow)
    if not DRY_RUN:
        time.sleep(0.05)
    sec_ck = signing_second()
    signed_call("sdk_click", "click",
                build_click_request(gaid, android_uuid, sec_ck,
                                    referrer, click_sec=click_second),
                "POST", "/sdk_click", sec=sec_ck)

    # 3. ONE attribution GET ~2.8 s after the session response (ask_in)
    if DRY_RUN and not SIGN_ALL:
        with open(os.path.join(HERE, "last_run.json"), "w") as f:
            json.dump(last_run, f, indent=1)
        print()
        print("config is valid: the session signed cleanly (adj7).")
        return 0
    time.sleep(2.8)
    sec_at = signing_second()
    fields = build_attribution_request(gaid, android_uuid, sec_at)
    auth = sign(fields, "attribution", sec_at)
    _status, body = call("GET", "/attribution", fields, auth)
    verdict = json.loads(body).get("attribution") or {}
    print("attribution GET -> %s / %s  [t=+%.0fs]"
          % (verdict.get("network"), verdict.get("tracker_token"),
             time.time() - started))
    if verdict.get("network", "Organic") == "Organic":
        # attribution lags sometimes: one confirmation poll
        time.sleep(30)
        sec_at2 = signing_second()
        fields = build_attribution_request(gaid, android_uuid, sec_at2)
        auth = sign(fields, "attribution", sec_at2)
        _status, body = call("GET", "/attribution", fields, auth)
        verdict = json.loads(body).get("attribution") or verdict
        print("poll +30s    -> %s / %s  [t=+%.0fs]"
              % (verdict.get("network"), verdict.get("tracker_token"),
                 time.time() - started))

    log("FINAL ATTRIBUTION: %s" % json.dumps(verdict))
    last_run["attribution"] = verdict

    # 5. POST /event -- 1st-open event (event=token y3sjx5), auth kinds event
    if not DRY_RUN:
        time.sleep(2.1)
        sec_ev = signing_second()
        ev_fields = build_event_request(gaid, android_uuid, sec_ev,
                                        click_sec=click_second)
        auth = sign(ev_fields, "event", sec_ev)
        status, body = call("POST", "/event", ev_fields, auth)
        log("event       -> HTTP %d  %s" % (status, body[:120]))
        last_run["event_status"] = status

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
