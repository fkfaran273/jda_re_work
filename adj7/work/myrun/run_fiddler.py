
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
import socket
import ssl
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

# ===================== FIDDLER CAPTURE (user request) ==================
# Every hop (click chain + app.adjust.com) goes through the local Fiddler
# proxy so the whole funnel is visible in the capture window.
os.environ["HTTP_PROXY"] = "http://127.0.0.1:8888"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8888"

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
DRY_RUN = "--dry-run" in sys.argv
SIGN_ALL = "--sign-all" in sys.argv

CLICK_UA = ("Mozilla/5.0 (Linux; Android 10; GM1901) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36")
PUSH_TOKEN = ("f" + uuid.uuid4().hex[:10] + "Zx_9R7cQ8yY:APA91bH"
              + uuid.uuid4().hex + uuid.uuid4().hex[:22])
# ---- device data extracted from payruki_again_new.saz -------------------
# genuine booking 2026-10-07 13:05 IST, adid eed7cbfc..., verdict
# VL-Alliance/248wk8ym.  Profile matched our runner byte-for-byte
# (extract_device_saz.py: 0 diffs); the partner id is STABLE across both
# genuine captures (same value in payruki_again and payruki_again_new).
PARTNER_PARAMS = json.dumps(
    {"payrupik_c_id": os.environ.get(
        "FUNNEL_PARTNER", str(uuid.uuid4()))},
    separators=(",", ":"))
# timeline, offsets from click_time (this capture -- NOT payruki_again's):
#   click_time_server +0.000 (twin, no -1)  install_begin +2.000
#   begin_server +1.000 (= begin-1)         installed +8.574
#   session created +33.294                 sdk_click +0.287 after session sent
#   attr1 +36.406 (ask_in 2000) -> ORGANIC  attr2 +37.813 -> NON-ORGANIC
#   event +38.205
INSTALL_AFTER = 8            # installed_at = click+8.574 s (ms .574)
SESSION_AT = 33              # session created = click+33.294 s
POLL_DELAYS = [2.6]          # ask_in-driven; loop honours the returned ask_in
# ms fractions per request (genuine values)
MS = {"session_c": 294, "session_s": 431, "click_c": 718, "click_s": 839,
      "installed": 574, "attr_c": 406, "attr_s": 420, "event_c": 205,
      "event_s": 216}

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
PROXY = os.environ.get("FUNNEL_PROXY", "http://127.0.0.1:8888")
# "" disables the proxy entirely (direct connection)
if not PROXY:
    PROXY = ""


def _proxy_addr():
    if not PROXY:
        return None
    p = urllib.parse.urlsplit(PROXY if "://" in PROXY else "http://" + PROXY)
    return p.hostname, p.port or 8888


def _connect(scheme, host, port, timeout=30):
    """Connection to (host, port), tunnelling through PROXY when set.

    HTTPS goes: TCP to proxy -> CONNECT host:port -> TLS wrapped by OUR
    context (unverified, because Fiddler MITMs with its own root).  Plain
    HTTP goes: TCP to proxy, absolute-URI request line (caller passes the
    full URL as the path).  Returns (connection, path_prefix).
    """
    pp = _proxy_addr()
    if pp is None:
        cls = (http.client.HTTPSConnection if scheme == "https"
               else http.client.HTTPConnection)
        return cls(host, port, timeout=timeout), None
    if scheme == "https":
        raw = socket.create_connection(pp, timeout)
        try:
            raw.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                         % (host, port, host, port)).encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                buf += chunk
            status = buf.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            if " 200 " not in status:
                raw.close()
                raise RuntimeError("proxy CONNECT failed (%s) -- is Fiddler "
                                   "running on 127.0.0.1:8888?" % status)
            sock = ssl._create_unverified_context().wrap_socket(
                raw, server_hostname=host)
        except Exception:
            try:
                raw.close()
            finally:
                raise
        c = http.client.HTTPSConnection(host, port, timeout=timeout)
        c.sock = sock          # putrequest() skips connect() when sock is set
        return c, None
    c = http.client.HTTPConnection(pp[0], pp[1], timeout=timeout)
    return c, "proxy"          # caller must use the absolute URL as path

APP_UA = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
          % (DEVICE["os_version"], DEVICE["device_name"], DEVICE["os_build"]))
P = DEVICE
# genuine capture: created_at/sent_at sit ~0.7 s ahead of the server's own
# date header (07:35:49.294 sent vs date 07:35:50) -> the device clock is
# NOT skewed behind the wire; sign at wall time.
MINT_SKEW = 0

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


def _get(url, use_browser=True):
    """Scheme-aware hop; click chain uses full Chrome fingerprint so the
    tracker qualifies the click (Dalvik + Client-SDK on a tracker hop is
    bot-shaped and can be silently disqualified). Every hop goes through
    the Fiddler proxy so the chain shows up in the capture."""
    scheme, rest = url.split("://", 1)
    host, _, path = rest.partition("/")
    port = 443 if scheme == "https" else 80
    c, via = _connect(scheme, host, port, timeout=30)
    path = url if via == "proxy" else "/" + path
    c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    if use_browser:
        for hk, hv in BROWSER_HEADERS.items():
            if hk in ("Connection", "Host"):
                continue
            c.putheader(hk, hv)
    else:
        c.putheader("User-Agent", APP_UA)
        c.putheader("Client-SDK", CLIENT_SDK)
        c.putheader("Accept", "text/html,application/xhtml+xml,"
                              "application/xml;q=0.9,*/*;q=0.8")
        c.putheader("Accept-Encoding", "identity")
    c.putheader("Connection", "close")
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
    """Visit the tracker link as Chrome would, FIRE every http(s) hop
    including the adjust hop that carries referrer=, and return the
    adjust_reftag. Previously we returned on first Location containing
    referrer= without GETting it -- so Adjust never logged the click."""
    url = _fill_device_id(_subst(LINK, gaid), gaid)
    if "gps_adid=" not in url:
        url += "&gps_adid=" + gaid
    chain_log = open(os.path.join(HERE, "click_chain.log"), "a")
    chain_log.write("=== %s gaid=%s start=%s\n"
                    % (datetime.now().isoformat(), gaid, url))
    found_ref = None
    try:
        for attempt in (1, 2):
            for hop in range(12):
                if not (url.startswith("http://") or url.startswith("https://")):
                    # market:// / intent:// Play hops: cannot be GETed, the
                    # reftag rides in the URL itself
                    ref = _reftag_in(url)
                    chain_log.write("hop non-http: %s ref=%s\n"
                                    % (url[:220], ref))
                    if ref:
                        found_ref = ref
                        break
                    break
                try:
                    status, hdrs, text = _get(url, use_browser=True)
                except Exception as exc:
                    log("click hop error: %r" % (exc,))
                    chain_log.write("hop error %s: %r\n" % (url[:220], exc))
                    break
                loc = hdrs.get("Location") or hdrs.get("location")
                chain_log.write("hop %s -> %s loc=%s\n"
                                % (url[:160], status,
                                   (loc or "")[:300]))
                if loc:
                    # mobpine's redirect carries an unfilled {loop_id} macro in
                    # ip_address= -- strip it before it poisons the adjust click
                    loc = loc.replace("&ip_address=%7Bloop_id%7D", "")
                    loc = loc.replace("&ip_address={loop_id}", "")
                    loc = _fill_device_id(loc, gaid)
                    if "app.adjust.com" in loc and "gps_adid=" not in loc:
                        loc += ("&" if "?" in loc else "?") + "gps_adid=" + gaid
                        chain_log.write("added missing gps_adid to adjust hop\n")
                    ref = _reftag_in(loc)
                    if ref:
                        found_ref = ref
                        # FIRE the adjust hop so the click is logged, then
                        # follow one more step if it redirects
                        try:
                            st2, hd2, _tx2 = _get(loc, use_browser=True)
                            loc2 = hd2.get("Location") or hd2.get("location") or ""
                            chain_log.write("fired adjust hop -> %s next=%s\n"
                                            % (st2, loc2[:300]))
                            if loc2 and loc2.startswith("http"):
                                try:
                                    st3, _hd3, _tx3 = _get(loc2, use_browser=True)
                                    chain_log.write("followed adjust redirect -> %s\n"
                                                    % st3)
                                except Exception as exc3:
                                    chain_log.write("adjust redirect error: %r\n"
                                                    % (exc3,))
                        except Exception as exc2:
                            chain_log.write("adjust hop fire error: %r\n"
                                            % (exc2,))
                        break
                    url = loc
                    continue
                if "adjust_reftag" in text:
                    ref = _reftag_in(text)
                    if ref:
                        found_ref = ref
                        break
                m = re.search(r"(?:window\.|document\.)?location\.replace\("
                              r"\s*[\"']([^\"']+)[\"']", text)
                if m:
                    nxt = m.group(1)
                    ref = _reftag_in(nxt)
                    if ref:
                        # fire js-redirect target too before accepting it
                        try:
                            _get(nxt, use_browser=True)
                            chain_log.write("fired js-redirect target %s\n"
                                            % nxt[:160])
                        except Exception as excj:
                            chain_log.write("js-redirect fire error: %r\n"
                                            % (excj,))
                        found_ref = ref
                        break
                    url = nxt
                    continue
                break
            if found_ref:
                break
            if attempt == 1 and not found_ref:
                time.sleep(2)
        chain_log.write("result ref=%s\n" % found_ref)
        return found_ref
    finally:
        chain_log.close()


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
    """POST /sdk_click -- payruki_again_new row 66 (49 fields)."""
    click_sec = sec if click_sec is None else click_sec
    installed = _stamp(click_sec + INSTALL_AFTER, MS["installed"])  # +8.574
    # capture: install_begin_time = click+2 s, *_server = click+1 s (the
    # Play-reported server clock runs 1 s BEHIND the client here)
    begin = click_sec + 2
    begin_server = click_sec + 1
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
        "device_manufacturer": P["device_manufacturer"],
        "display_width": P["display_width"], "time_spent": "0",
        "device_name": P["device_name"], "needs_response_details": "1",
        "updated_at": installed, "screen_format": P["screen_format"],
        "click_time_server": _stamp(click_sec, 0),   # capture: exact twin
        "os_version": P["os_version"], "google_play_instant": "0",
        "install_begin_time_server": _stamp(begin_server, 0),  # click+1 s
        "android_uuid": android_uuid, "referrer": referrer,
        "environment": P["environment"], "attribution_deeplink": "1",
        "install_begin_time": _stamp(begin, 0),                  # click+2 s
        "display_height": P["display_height"], "package_name": PACKAGE_NAME,
        "os_name": "android", "tracking_enabled": "1",
    }


def build_session_request(gaid, android_uuid, sec, click_sec=None):
    """POST /session -- payruki_again_new row 65 (45 fields, queue_size 0)."""
    installed = _stamp(click_sec + INSTALL_AFTER, MS["installed"])  # +8.574
    return {
        "store_name_from_system": "com.android.vending",
        "gps_adid_attempt": "1", "country": P["country"],
        "api_level": P["api_level"], "hardware_name": P["hardware_name"],
        "partner_params": PARTNER_PARAMS,
        "app_version": APP_VERSION, "app_token": APP_TOKEN,
        "installed_at": installed, "created_at": _stamp(sec, MS["session_c"]),
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
        "android_uuid": android_uuid, "sent_at": _stamp(sec, MS["session_s"]),
        "offline_mode_enabled": "0", "environment": P["environment"],
        "screen_density": P["screen_density"], "attribution_deeplink": "1",
        "session_count": "1", "display_height": P["display_height"],
        "package_name": PACKAGE_NAME,
        "initiating_package_name": "com.android.vending",
        "os_name": "android", "ui_mode": "1",
        "enqueue_size": "0", "tracking_enabled": "1",
    }


def build_attribution_request(gaid, android_uuid, sec):
    """GET /attribution -- row 67 (22 query params)."""
    return {
        "initiated_by": "backend", "gps_adid_attempt": "1",
        "api_level": P["api_level"], "app_version": APP_VERSION,
        "app_token": APP_TOKEN, "os_version": P["os_version"],
        "created_at": _stamp(sec, MS["attr_c"]), "device_type": P["device_type"],
        "gps_adid": gaid, "foreground": "1", "android_uuid": android_uuid,
        "sent_at": _stamp(sec, MS["attr_s"]), "offline_mode_enabled": "0",
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
        "sent_at": _stamp(sec, MS["event_s"]),
        "offline_mode_enabled": "0", "screen_density": P["screen_density"],
        "session_count": "1", "ui_mode": "1", "enqueue_size": "0",
        "gps_adid_attempt": "1", "event_count": "1", "session_length": "5",
        "created_at": _stamp(sec, MS["event_c"]),
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
    c, _ = _connect("https", "app.adjust.com", 443, timeout=30)
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
    global MS
    # per-run ms jitter (genuine devices never repeat .294/.431 exactly;
    # fixed fractions every install are a bot signal). Keep created<sent.
    import random as _rnd
    _j = lambda base, lo=80: max(0, min(990, base + _rnd.randint(-lo, lo)))
    MS = dict(MS)
    MS["session_c"] = _j(294)
    MS["session_s"] = min(999, MS["session_c"] + _rnd.randint(60, 220))
    MS["click_c"] = _j(718)
    MS["click_s"] = min(999, MS["click_c"] + _rnd.randint(60, 220))
    MS["installed"] = _j(574, 120)
    MS["attr_c"] = _j(406)
    MS["attr_s"] = min(999, MS["attr_c"] + _rnd.randint(10, 60))
    MS["event_c"] = _j(205)
    MS["event_s"] = min(999, MS["event_c"] + _rnd.randint(10, 60))
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
    # persist BEFORE the CTIT wall clock -- a timeout mid-run must not lose
    # the ids needed to resume the attribution poll
    with open(os.path.join(HERE, "last_run.json"), "w") as f:
        json.dump(last_run, f, indent=1)

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

    # STORY ORDER (payruki_again_new rows 65-69): click 13:05:16 ->
    # installed +8.574 s -> session created +33.294 s -> sdk_click +0.287 s
    # after the session (pipelined) -> attribution 1 at +3.1 s (ask_in 2000)
    # -> ORGANIC + ask_in 1000 -> attribution 2 at +1.4 s -> NON-ORGANIC
    # -> event +0.4 s.  The session must never precede installed_at.
    if not DRY_RUN:
        target = click_second + SESSION_AT
        wait = target - time.time()
        if wait > 0:
            print("installing... (CTIT wall clock, %.0fs to the session)"
                  % wait)
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
        try:
            payload0 = json.loads(body)
        except Exception:
            payload0 = {}
        adid = payload0.get("adid", "")
        log("session -> HTTP %d adid %s ask_in=%s body=%s"
            % (status, adid, payload0.get("ask_in"), body[:220]))
        last_run["adid"] = adid
        last_run["session_ask_in"] = payload0.get("ask_in")
        with open(os.path.join(HERE, "last_run.json"), "w") as f:
            json.dump(last_run, f, indent=1)

    # 2. sdk_click 0.287 s after the session (row 65 sent .431 -> row 66
    #    created .718) -- pipelined on the same connection
    if not DRY_RUN:
        time.sleep(0.35)
    sec_ck = signing_second()
    signed_call("sdk_click", "click",
                build_click_request(gaid, android_uuid, sec_ck,
                                    referrer, click_sec=click_second),
                "POST", "/sdk_click", sec=sec_ck)

    # 3. attribution -- ask_in driven, exactly like the device: poll 1 at
    #    +2.98 s (session ask_in 2000) -> ORGANIC + ask_in 1000 -> poll 2
    #    +1.4 s later -> NON-ORGANIC VL-Alliance/248wk8ym.
    if DRY_RUN and not SIGN_ALL:
        with open(os.path.join(HERE, "last_run.json"), "w") as f:
            json.dump(last_run, f, indent=1)
        print()
        print("config is valid: the session signed cleanly (adj7).")
        return 0
    delays = list(POLL_DELAYS)
    verdict = {}
    for i in range(8):
        delay = delays[i] if i < len(delays) else 1.5
        time.sleep(delay)
        sec_at = signing_second()
        fields = build_attribution_request(gaid, android_uuid, sec_at)
        auth = sign(fields, "attribution", sec_at)
        _status, body = call("GET", "/attribution", fields, auth)
        payload = json.loads(body)
        verdict = payload.get("attribution") or {}
        ask_in = payload.get("ask_in")
        print("poll %-2d +%-5.1fs -> %-9s / %-9s ask_in=%s  [t=+%.0fs]"
              % (i + 1, delay, verdict.get("network"),
                 verdict.get("tracker_token"), ask_in,
                 time.time() - started))
        if verdict.get("network") and verdict["network"] != "Organic":
            break
        # the device honours the returned ask_in and re-polls ~1.4 s later
        if isinstance(ask_in, (int, float)) and ask_in > 0:
            delays.append(max(1.0, ask_in / 1000.0 + 0.4))

    log("FINAL ATTRIBUTION: %s" % json.dumps(verdict))
    last_run["attribution"] = verdict

    # 5. POST /event -- 1st-open event, +0.4 s after the attribution that
    #    resolved it (row 68 -> row 69: 37.813 -> 38.205)
    if not DRY_RUN:
        time.sleep(0.4)
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
