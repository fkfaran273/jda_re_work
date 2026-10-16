"""run_install.py — register a click, report the install, read the attribution.

adj7 Android (Adjust Signature SDK 3.62.0): 304-byte signature, pure signer.

    python -u run_install.py --dry-run          # sign and show, send nothing
    python -u run_install.py                    # live: sdk_click -> session -> attribution
    python -u run_install.py --click-url URL    # also chase a tracker click first
    python -u run_install.py --app hunch        # app selector (hanaf|hunch|mitra)

Three Adjust APIs, field-for-field the genuine capture shapes:
sdk_click (kind "click"), session, attribution (GET).
Signing is adj7_pure (one self-contained file, no emulator).
"""
import datetime, gzip, http.client, json, os, re, sys, time
import urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7_pure as S

DRY_RUN = "--dry-run" in sys.argv
APP = "hanaf"
for _i, _a in enumerate(sys.argv):
    if _a == "--app" and _i + 1 < len(sys.argv):
        APP = sys.argv[_i + 1]
CLICK_URL = None
for _i, _a in enumerate(sys.argv):
    if _a == "--click-url" and _i + 1 < len(sys.argv):
        CLICK_URL = sys.argv[_i + 1]

CFG = S.APPS[APP]

# ==========================================================================
# Device profile (the payruki capture's moto g42; fresh ids per run)
# ==========================================================================
DEVICE = {
    "api_level": "31", "os_version": "12", "device_name": "moto g42",
    "device_manufacturer": "motorola", "hardware_name": "S2SE32.28-28-4",
    "os_build": "S2SE32.28-28-4", "language": "en", "country": "IN",
    "display_width": "1080", "display_height": "2237",
    "screen_density": "high", "screen_size": "normal", "screen_format": "long",
    "cpu_type": "arm64-v8a", "connectivity_type": "1",
    "tz_minutes": 330, "tz_label": "+0530",
}
UA = ("Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
APP_VERSION = CFG.get("app_version") or "1.0.0"
INSTALL_AFTER = 20          # click -> install gap (s)
POLL_DELAYS = [10, 20, 30, 45, 60]

_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
os.makedirs(os.path.join(HERE, "work"), exist_ok=True)
_LOG_F = open(os.path.join(HERE, "work", "funnel_live_%s.log" % _ts), "a",
              encoding="utf-8")

def elog(*parts):
    line = " ".join(str(p) for p in parts)
    stamp = datetime.datetime.now().strftime("%H:%M:%S")
    _LOG_F.write("[%s] %s\n" % (stamp, line))
    _LOG_F.flush()
    print("[%s] %s" % (stamp, line))

def _stamp(ts, ms):
    dt = datetime.datetime.fromtimestamp(
        ts + DEVICE["tz_minutes"] * 60, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z"
                       + DEVICE["tz_label"])

MINT_SKEW = -2

def signing_second():
    return int(time.time()) + MINT_SKEW

# ==========================================================================
# The three request builders (capture-shaped)
# ==========================================================================
def build_session_request(gaid, auuid, sec, click_sec=None):
    installed = _stamp(sec if click_sec is None
                       else click_sec + INSTALL_AFTER, 574)
    return {
        "app_token": CFG["app_token"], "app_version": APP_VERSION,
        "package_name": CFG["package_name"],
        "gps_adid": gaid, "android_uuid": auuid,
        "environment": "production", "device_type": "phone",
        "gps_adid_src": "service", "gps_adid_attempt": "1",
        "foreground": "1", "needs_response_details": "1",
        "attribution_deeplink": "1", "offline_mode_enabled": "0",
        "ui_mode": "1", "tracking_enabled": "1", "os_name": "android",
        "api_level": DEVICE["api_level"], "os_version": DEVICE["os_version"],
        "device_name": DEVICE["device_name"],
        "device_manufacturer": DEVICE["device_manufacturer"],
        "hardware_name": DEVICE["hardware_name"],
        "os_build": DEVICE["os_build"], "language": DEVICE["language"],
        "country": DEVICE["country"],
        "display_width": DEVICE["display_width"],
        "display_height": DEVICE["display_height"],
        "screen_density": DEVICE["screen_density"],
        "screen_size": DEVICE["screen_size"],
        "screen_format": DEVICE["screen_format"],
        "cpu_type": DEVICE["cpu_type"],
        "connectivity_type": DEVICE["connectivity_type"],
        "enqueue_size": "0", "first_error": "0", "last_error": "0",
        "retry_count": "0", "wait_time": "0.0", "wait_total": "0.0",
        "store_name_from_system": "com.android.vending",
        "initiating_package_name": "com.android.vending",
        "session_count": "1",
        "created_at": _stamp(sec, 294), "sent_at": _stamp(sec, 431),
        "installed_at": installed, "updated_at": installed,
    }

def build_click_request(gaid, auuid, sec, referrer, click_sec=None):
    click_sec = sec if click_sec is None else click_sec
    installed = _stamp(click_sec + INSTALL_AFTER, 574)
    begin = click_sec + 8
    return {
        "app_token": CFG["app_token"], "app_version": APP_VERSION,
        "package_name": CFG["package_name"],
        "gps_adid": gaid, "android_uuid": auuid,
        "environment": "production", "device_type": "phone",
        "gps_adid_src": "service", "gps_adid_attempt": "1",
        "foreground": "1", "needs_response_details": "1",
        "attribution_deeplink": "1", "offline_mode_enabled": "0",
        "ui_mode": "1", "tracking_enabled": "1", "os_name": "android",
        "api_level": DEVICE["api_level"], "os_version": DEVICE["os_version"],
        "device_name": DEVICE["device_name"],
        "device_manufacturer": DEVICE["device_manufacturer"],
        "hardware_name": DEVICE["hardware_name"],
        "os_build": DEVICE["os_build"], "language": DEVICE["language"],
        "country": DEVICE["country"],
        "display_width": DEVICE["display_width"],
        "display_height": DEVICE["display_height"],
        "screen_density": DEVICE["screen_density"],
        "screen_size": DEVICE["screen_size"],
        "screen_format": DEVICE["screen_format"],
        "cpu_type": DEVICE["cpu_type"],
        "connectivity_type": DEVICE["connectivity_type"],
        "source": "install_referrer", "referrer_api": "google",
        "referrer": referrer, "google_play_instant": "0",
        "install_version": APP_VERSION,
        "session_count": "1", "session_length": "0",
        "subsession_count": "1", "time_spent": "0",
        "created_at": _stamp(sec, 961), "sent_at": _stamp(sec, 970),
        "installed_at": installed, "updated_at": installed,
        "click_time": _stamp(click_sec, 0),
        "click_time_server": _stamp(click_sec - 2, 0),
        "install_begin_time": _stamp(begin, 0),
        "install_begin_time_server": _stamp(begin - 2, 0),
    }

def build_attribution_request(gaid, auuid, sec):
    return {
        "initiated_by": "backend", "gps_adid_attempt": "1",
        "api_level": DEVICE["api_level"],
        "app_version": APP_VERSION,
        "app_token": CFG["app_token"],
        "os_version": DEVICE["os_version"],
        "created_at": _stamp(sec, 406),
        "device_type": "phone", "gps_adid": gaid, "foreground": "1",
        "android_uuid": auuid,
        "sent_at": _stamp(sec, 420),
        "offline_mode_enabled": "0",
        "device_name": DEVICE["device_name"],
        "environment": "production", "needs_response_details": "1",
        "attribution_deeplink": "1",
        "package_name": CFG["package_name"],
        "os_name": "android", "ui_mode": "1",
        "gps_adid_src": "service", "tracking_enabled": "1",
    }

def sign(fields, kind, second, nonce12):
    return S.sign(fields, kind, APP, second, nonce12)

# ==========================================================================
# HTTP layer
# ==========================================================================
def call(method, path, fields, auth):
    body = urllib.parse.urlencode(fields).encode() if method == "POST" else None
    target = path if method == "POST" else path + "?" + urllib.parse.urlencode(
        fields, quote_via=urllib.parse.quote)
    elog("--> %s https://app.adjust.com%s" % (method, target[:160]))
    elog("    Client-SDK: %s | UA: %s" % (CFG["client_sdk"], UA))
    elog("    Authorization: %s..." % auth[:80])
    if DRY_RUN:
        elog("    (dry-run: not sent)")
        return 0, ""
    if body is not None:
        elog("    POST body: %s" % body.decode("latin1"))
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest(method, target, skip_host=1, skip_accept_encoding=1)
        c.putheader("Client-SDK", CFG["client_sdk"])
        c.putheader("Authorization", auth)
        c.putheader("User-Agent", UA)
        c.putheader("Host", "app.adjust.com")
        if body is not None:
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("Content-Length", str(len(body)))
        c.putheader("Accept-Encoding", "gzip")
        c.endheaders(body)
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        text = raw.decode("utf-8", "replace")
        elog("<-- HTTP %d" % r.status)
        elog("    body: %s" % text[:500])
        return r.status, text
    finally:
        c.close()

# ==========================================================================
# The click chase (optional --click-url): follow hops until referrer=
# ==========================================================================
META_REFRESH = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^"\'>]+)', re.I)

def chase_reftag(url):
    for hop in range(12):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme in ("market", "intent"):
            elog("click-chain hop %d -> store scheme (stop)" % hop)
            return None
        c = (http.client.HTTPSConnection(parts.hostname, 443, timeout=25)
             if parts.scheme == "https" else
             http.client.HTTPConnection(parts.hostname, 80, timeout=25))
        try:
            c.request("GET", urllib.parse.urlunsplit(
                ("", "", parts.path or "/", parts.query, "")),
                headers={"User-Agent": UA})
            r = c.getresponse()
            data = r.read(65536)
            nxt = r.getheader("Location")
        finally:
            c.close()
        if nxt:
            elog("click-chain hop %d -> %s" % (hop, nxt[:140]))
            if "referrer=" in nxt:
                ref = urllib.parse.unquote(nxt.split("referrer=", 1)[1])
                return ref.split(";S.browser_fallback_url")[0]
            url = nxt
            continue
        m = META_REFRESH.search(data.decode("utf-8", "replace"))
        if m and "referrer=" in m.group(1):
            ref = urllib.parse.unquote(m.group(1).split("referrer=", 1)[1])
            return ref.split(";S.browser_fallback_url")[0]
        if m:
            url = urllib.parse.urljoin(url, m.group(1))
            continue
        elog("click-chain hop %d: dead end" % hop)
        return None
    return None

# ==========================================================================
# The funnel
# ==========================================================================
def main():
    gaid = str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    nonce12 = os.urandom(12)
    elog("=== adj7 install funnel: app=%s gaid=%s uuid=%s dry_run=%s"
         % (APP, gaid, auuid, DRY_RUN))

    click_sec = None
    referrer = None
    if CLICK_URL:
        referrer = chase_reftag(CLICK_URL.replace("{gaid}", gaid))
        click_sec = int(time.time())
        elog("click reftag/referrer: %r" % (referrer,))

    # 1) sdk_click (kind "click")
    sec = signing_second()
    fields = build_click_request(gaid, auuid, sec,
                                 referrer or "adjust_reftag=adjust_example",
                                 click_sec)
    auth = sign(fields, "click", sec, nonce12)
    st, body = call("POST", "/sdk_click", fields, auth)
    if st and st != 200:
        elog("sdk_click HTTP %d — stopping" % st)
        return

    # 2) session
    time.sleep(2)
    sec2 = signing_second()
    fields = build_session_request(gaid, auuid, sec2, click_sec)
    auth = sign(fields, "session", sec2, os.urandom(12))
    st, body = call("POST", "/session", fields, auth)
    if st and st != 200:
        elog("session HTTP %d — stopping" % st)
        return

    # 3) attribution (armed read; ask_in cadence respected)
    for delay in POLL_DELAYS:
        time.sleep(delay)
        sec3 = signing_second()
        fields = build_attribution_request(gaid, auuid, sec3)
        auth = sign(fields, "attribution", sec3, os.urandom(12))
        st, body = call("GET", "/attribution", fields, auth)
        if st == 200 and body and "ask_in" not in body[:200]:
            elog("FINAL ATTRIBUTION: %s" % body)
            break
        if st == 400 and "ask_in" in (body or ""):
            try:
                wait = json.loads(body)["ask_in"] // 1000 + 1
            except Exception:
                wait = 20
            elog("ask_in throttle — waiting %ds" % wait)
            time.sleep(wait)
    elog("funnel done (gaid=%s)" % gaid)

if __name__ == "__main__":
    main()
