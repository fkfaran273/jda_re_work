# -*- coding: utf-8 -*-
"""run_install_py27.py -- the adj8 funnel on Python 2.7 (same wire format as
run_install.py; config from campaign_data.py + device_data.py; signing from
adj8_pure_py27.py, pure Python).

    python2.7 run_install_py27.py --dry-run      # sign, send nothing
    python2.7 run_install_py27.py                # live run (customer)
    python2.7 run_install_py27.py graddef        # another campaign
"""
from __future__ import print_function

import datetime
import json
import os
import re
import sys
import time
import uuid

try:                                    # Python 3
    import gzip
    import http.client as httpclient
    from urllib.parse import (urlencode, urlsplit, urlunsplit, urljoin,
                              unquote)
    from urllib.parse import quote as _quote

    def _urlencode_get(fields):
        return urlencode(fields, quote_via=_quote)

    def _gunzip(raw):
        return gzip.decompress(raw)
except ImportError:                     # Python 2.7
    import StringIO
    import gzip as _gzip
    import httplib as httpclient
    from urlparse import urlsplit, urlunsplit, urljoin
    from urllib import urlencode, unquote
    from urllib import quote as _quote

    def _urlencode_get(fields):
        return "&".join(_quote(str(k)) + "=" + _quote(str(v))
                        for k, v in fields.items())

    def _gunzip(raw):
        return _gzip.GzipFile(fileobj=StringIO.StringIO(raw)).read()

try:
    import html
    _unescape = html.unescape
except ImportError:                     # Python 2.7
    from HTMLParser import HTMLParser
    _unescape = HTMLParser().unescape

try:
    _unichr = unichr                    # Python 2
except NameError:
    _unichr = chr                       # Python 3

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj8_pure_py27 as S
import campaign_data as C
import device_data as D

def say(msg):
    """print + flush: py2.7 has no flush= on print()."""
    print(msg)
    sys.stdout.flush()

DRY_RUN = "--dry-run" in sys.argv
SEND_EVENT = "--event" in sys.argv
GAP = 0
for _i, _a in enumerate(sys.argv):
    if _a == "--gap" and _i + 1 < len(sys.argv):
        GAP = int(sys.argv[_i + 1])
EVENT_TOKEN = None
_args2 = [a for a in sys.argv[1:] if not a.startswith("-")]
if SEND_EVENT and _args2:
    EVENT_TOKEN = _args2[-1]

_args = []
_skip = False
for _a in sys.argv[1:]:
    if _skip:
        _skip = False
        continue
    if _a == "--gap":
        _skip = True          # its numeric value is not an app name
        continue
    if not _a.startswith("-"):
        _args.append(_a)
if _args and _args[0] not in C.CAMPAIGNS:
    raise SystemExit("unknown app %r - have: %s"
                     % (_args[0], ", ".join(sorted(C.CAMPAIGNS))))
campaign = C.get(_args[0]) if _args else C.get()

# ==========================================================================
# The profiles.  Everything the requests need comes from these two files --
# the signer's subset (cert_sha1, client_sdk, adj_signing_id, ...) goes into
# every sign_request call.
# ==========================================================================
CFG = C.signer_fields(campaign)
DEVICE = D.DEVICE
PARAMS = D.device_to_params(DEVICE)
APP_UA = D.device_headers(DEVICE)

# ==========================================================================
# LIVE-FUNNEL LOG -- every request (URL, headers minus the Authorization
# secret, status, full response body) lands in work/cap/funnel_live_*.log
# ==========================================================================
_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
_LOG_F = open(os.path.join(HERE, "work", "cap", "funnel_live_%s.log" % _ts),
              "a")

def elog(*parts):
    line = " ".join(str(p) for p in parts)
    stamp = datetime.datetime.now().strftime("%H:%M:%S")
    _LOG_F.write("[%s] %s\n" % (stamp, line))
    _LOG_F.flush()

# ==========================================================================
# THE API LAYER -- what each endpoint actually puts on the wire
# (field-for-field the genuine adj8 captures: session 44, click 48,
# attribution 22 fields)
# ==========================================================================
MINT_SKEW = -2
INSTALL_AFTER = int(CFG.get("install_after", 48))

def signing_second():
    # sits a little in the past so created_at/sent_at never claim a moment
    # that has not happened yet
    return int(time.time()) + MINT_SKEW

def _stamp(ts, ms):
    dt = datetime.datetime.utcfromtimestamp(ts + D.tz_minutes(DEVICE) * 60)
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + ("%03d" % ms) + "Z"
                       + D.tz_label(DEVICE))

# the SDK's first-session counters (genuine be session shape; the click and
# attribution requests carry none of them)
_SESSION_COUNTERS = {"enqueue_size": "0", "first_error": "0",
                     "last_error": "0", "retry_count": "0",
                     "wait_time": "0.0", "wait_total": "0.0"}

def _common(gaid, android_uuid):
    out = {
        "app_token": CFG["app_token"],
        "app_version": CFG["app_version"],
        "package_name": CFG["package_name"],
        "gps_adid": gaid, "android_uuid": android_uuid,
        "environment": "production", "device_type": "phone",
        "gps_adid_src": "service", "gps_adid_attempt": "1",
        "foreground": "1", "needs_response_details": "1",
        "attribution_deeplink": "1", "offline_mode_enabled": "0",
        "ui_mode": "1", "tracking_enabled": "1", "os_name": "android",
    }
    out.update(PARAMS)
    if campaign.get("device_ids"):
        # the graddef SDK carries a per-install external id and the GMS App
        # Set ID on every request (booked capture yamistar_capture.json)
        out["external_device_id"] = campaign.get("external_device_id", "")
        out["google_app_set_id"] = campaign.get("google_app_set_id", "")
    return out

def build_session_request(gaid, android_uuid, sec, click_sec=None):
    f = _common(gaid, android_uuid)
    f.update(_SESSION_COUNTERS)
    installed = _stamp(sec if click_sec is None
                       else click_sec + INSTALL_AFTER, 774)
    f.update({
        "store_name_from_system": "com.android.vending",
        "initiating_package_name": "com.android.vending",
        "session_count": "1",
        "created_at": _stamp(sec, 928), "sent_at": _stamp(sec, 942),
        "installed_at": installed, "updated_at": installed,
    })
    return f

def build_click_request(gaid, android_uuid, sec, referrer, click_sec=None):
    f = _common(gaid, android_uuid)
    click_sec = sec if click_sec is None else click_sec
    installed = _stamp(click_sec + INSTALL_AFTER, 774)
    begin = click_sec + 8
    f.update({
        "source": "install_referrer", "referrer_api": "google",
        "referrer": referrer, "google_play_instant": "0",
        "install_version": CFG["app_version"],
        "session_count": "1", "session_length": "0",
        "subsession_count": "1", "time_spent": "0",
        "created_at": _stamp(sec, 961), "sent_at": _stamp(sec, 970),
        "installed_at": installed, "updated_at": installed,
        "click_time": _stamp(click_sec, 0),
        "click_time_server": _stamp(click_sec - 2, 0),
        "install_begin_time": _stamp(begin, 0),
        "install_begin_time_server": _stamp(begin - 2, 0),
    })
    return f

def build_attribution_request(gaid, android_uuid, sec):
    return {
        "initiated_by": "backend", "gps_adid_attempt": "1",
        "api_level": PARAMS["api_level"],
        "app_version": CFG["app_version"],
        "app_token": CFG["app_token"],
        "os_version": PARAMS["os_version"],
        "created_at": _stamp(sec, 666),
        "device_type": "phone", "gps_adid": gaid, "foreground": "1",
        "android_uuid": android_uuid,
        "sent_at": _stamp(sec, 696),
        "offline_mode_enabled": "0",
        "device_name": PARAMS["device_name"],
        "environment": "production", "needs_response_details": "1",
        "attribution_deeplink": "1",
        "package_name": CFG["package_name"],
        "os_name": "android", "ui_mode": "1",
        "gps_adid_src": "service", "tracking_enabled": "1",
    }

def build_event_request(gaid, android_uuid, sec):
    f = _common(gaid, android_uuid)
    f.update({
        "event_count": "1", "seq": "1",
        "session_count": "1", "session_length": "0",
        "subsession_count": "1", "time_spent": "0",
        "created_at": _stamp(sec, 873), "sent_at": _stamp(sec, 940),
    })
    if EVENT_TOKEN:
        f["event_token"] = EVENT_TOKEN
    return f

def sign(fields, kind, sec):
    """fields -> the Authorization header value."""
    return S.sign_request(fields, kind, CFG, second=sec)

def call(method, path, fields, auth):
    body = urlencode(fields) if method == "POST" else None
    target = (path if method == "POST"
              else path + "?" + _urlencode_get(fields))
    elog("--> %s https://app.adjust.com%s" % (method, target))
    elog("    headers: Client-SDK: %s | User-Agent: %s"
         % (CFG["client_sdk"], APP_UA))
    elog("    headers: Authorization: %s...  (signature truncated here)"
         % auth[:72])
    if body is not None:
        elog("    POST body: %s" % body)
    c = httpclient.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest(method, target, skip_host=1, skip_accept_encoding=1)
        c.putheader("Client-SDK", CFG["client_sdk"])
        c.putheader("Authorization", auth)
        c.putheader("User-Agent", APP_UA)
        c.putheader("Host", "app.adjust.com")
        if body is not None:
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("Content-Length", str(len(body)))
        c.putheader("Accept-Encoding", "gzip")
        c.endheaders(body)
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == "\x1f\x8b":
            raw = _gunzip(raw)
        text = raw.decode("utf-8", "replace")
        elog("<-- HTTP %d" % r.status)
        elog("    body: %s" % text)
        return r.status, text
    finally:
        c.close()

# ==========================================================================
# THE CLICK -- open the tracker link and follow every hop (this offer goes
# click -> web page -> Play Store) until a referrer= hands back the
# adjust_reftag.  Every hop uses the SAME UA + Client-SDK as the Adjust
# requests (one consistent story) and is logged hop by hop.
# ==========================================================================
META_REFRESH = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^"\'>]+)', re.I)
JS_LOCATION = re.compile(
    r'(?:window\.|document\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
    re.I)
JS_REPLACE = re.compile(
    r'(?:window\.|document\.)?location\.replace\(\s*["\']([^"\']+)["\']',
    re.I)
UNIESC = re.compile(r"\\u([0-9a-fA-F]{4})")

def _reftag_in(s):
    """The adjust_reftag inside a referrer= value (a Location header, a
    market:// URL or an html/js hop); None when there is none."""
    if "referrer=" not in s:
        return None
    ref = unquote(s.split("referrer=", 1)[1])
    return ref.split(";S.browser_fallback_url")[0]

def _subst(url, gaid, dp2):
    """Click-link macros: {gaid}/{dp2} as in adj9, plus {agent} (mobpine
    sub2; an empty 'agent' field drops the param rather than sending a
    literal '{agent}')."""
    agent = str(campaign.get("agent", "") or "")
    if "{agent}" in url and not agent:
        url = re.sub(r"[?&]sub2=\{agent\}", "", url)
    return (url.replace("{gaid}", gaid).replace("{dp2}", dp2 or gaid)
               .replace("{agent}", agent))

def _one_visit(url):
    """One visit: follow the redirect chain, including HTML/meta-refresh and
    JS-location hops.  Returns (reftag or None, final_url)."""
    for hop_i in range(12):
        parts = urlsplit(url)
        if parts.scheme in ("market", "intent"):
            elog("click-chain hop %d -> %s  (store scheme, stop)"
                 % (hop_i, url))
            return None, url
        c = (httpclient.HTTPConnection(parts.hostname, 80, timeout=25)
             if parts.scheme == "http" else
             httpclient.HTTPSConnection(parts.hostname, 443, timeout=25))
        try:
            c.request("GET", urlunsplit(
                ("", "", parts.path or "/", parts.query, "")),
                headers={"User-Agent": APP_UA,
                         "Client-SDK": CFG["client_sdk"],
                         "Accept": ("text/html,application/xhtml+xml,"
                                    "application/xml;q=0.9,*/*;q=0.8"),
                         "Accept-Encoding": "identity",
                         "Connection": "close"})
            r = c.getresponse()
            raw = r.read()
            location = r.getheader("Location") or ""
            elog("click-chain hop %d GET http://%s%s -> HTTP %d"
                 % (hop_i, parts.netloc, parts.path or "/", r.status))
            elog("  Location: %s" % (location or "(none)"))
            if not location and raw:
                elog("  body[:600]: %s"
                     % raw[:600].decode("utf-8", "replace")
                       .replace("\r", "").replace("\n", " "))
        except Exception as e:
            # a transient/bad hop must never crash the run AFTER the click
            # has registered (that would waste the device)
            elog("  hop error: %r -- chain ends" % e)
            return None, url
        finally:
            c.close()
        ref = _reftag_in(location)
        if ref:
            elog("  reftag from Location referrer=: %r" % ref[:120])
            return ref, url
        if location:
            url = urljoin(url, location)
            continue
        # no Location: look for the HTML/JS hop ("click like a web page").
        # go.link's deeplink page carries TWO location.replace() calls --
        # try_close() -> 'about:blank' first, then store_or_close() ->
        # "market://details?id\\u003D...&referrer\\u003Dadjust_reftag%3D..."
        # (\\uXXXX-escaped '=' and '&') -- so scan ALL candidates in order,
        # skip the non-hops, and un-escape before looking for the referrer.
        text = raw.decode("utf-8", "replace")
        candidates = []
        for rx in (META_REFRESH, JS_LOCATION, JS_REPLACE):
            candidates.extend(m.group(1).strip() for m in rx.finditer(text))
        if not candidates:
            elog("  no further hop found in the page body -- chain ends")
            break
        for cand in candidates:
            hop = UNIESC.sub(lambda x: _unichr(int(x.group(1), 16)),
                             _unescape(cand))
            if hop.lower().startswith(("javascript", "about:")) or hop == ".":
                continue
            elog("  html/js hop -> %s" % hop[:200])
            ref = _reftag_in(hop)
            if ref:
                elog("  reftag inside the hop: %r" % ref[:120])
                return ref, url
            if urlsplit(hop).scheme in ("market", "intent"):
                elog("  store scheme without a referrer -- no reftag")
                return None, url
            url = urljoin(url, hop)
            break
        else:
            elog("  only about:/javascript candidates -- chain ends")
            break
    return None, url

def open_click_link(gaid, dp2=None):
    """Visit the tracker link (twice -- this offer's first visit lands on a
    web hop) and return the adjust_reftag the Play Store redirect hands
    back."""
    for attempt in (1, 2):
        reftag, final_url = _one_visit(_subst(
            campaign["click_link"], gaid, dp2))
        if reftag:
            return reftag
        if attempt == 1:
            # second visit: some chains only redirect on a repeat hit
            time.sleep(2)
    return None

def main():
    # FUNNEL_GAID lets a pre-verified (fresh, never-clicked) GAID be injected;
    # default stays a random uuid4.
    gaid = os.environ.get("FUNNEL_GAID") or str(uuid.uuid4())
    android_uuid = str(uuid.uuid4())
    if campaign.get("device_ids"):
        campaign["external_device_id"] = os.urandom(8).encode("hex")
        campaign["google_app_set_id"] = str(uuid.uuid4())
    started = time.time()
    elog("=" * 78)
    elog("LIVE FUNNEL  app=%s  gaid=%s  android_uuid=%s"
         % (CFG["package_name"], gaid, android_uuid))
    elog("click_link: %s" % _subst(campaign["click_link"], gaid, None))
    elog("UA: %s" % APP_UA)
    elog("=" * 78)

    referrer = None
    if not DRY_RUN:
        referrer = open_click_link(gaid)
        if not referrer:
            say("no reftag in the redirect chain - aborting")
            elog("NO REFTAG in the redirect chain -- aborting before session")
            return 1
        say("click    reftag %s" % referrer[:50])
        elog("click    reftag %s" % referrer)
    click_second = int(time.time())
    # persisted so the device can be re-polled later (attribution lags
    # sometimes); one file per run
    with open(os.path.join(HERE, "last_run_py27.json"), "w") as _f:
        json.dump({"app": CFG["package_name"], "gaid": gaid,
                   "android_uuid": android_uuid, "reftag": referrer,
                   "click_second": click_second, "started": started}, _f,
                  indent=1)

    if GAP:
        time.sleep(GAP)
    sec = signing_second()
    say("signing  /session ...")
    fields = build_session_request(gaid, android_uuid, sec,
                                   click_sec=click_second)
    auth = sign(fields, "session", sec)
    adid = ""
    if DRY_RUN:
        say("         %d fields, signed - not sending" % len(fields))
        say("         %s..." % auth[:96])
    else:
        status, body = call("POST", "/session", fields, auth)
        adid = json.loads(body).get("adid", "")
        say("         -> %d adid %s  [t=+%.0fs]"
            % (status, adid, time.time() - started))
        elog("session -> HTTP %d adid %s" % (status, adid))
        try:
            _lr = json.load(open(os.path.join(HERE, "last_run_py27.json")))
            _lr["adid"] = adid
            json.dump(_lr, open(os.path.join(HERE, "last_run_py27.json"),
                                "w"), indent=1)
        except Exception:
            pass
    if not referrer:
        say("         /sdk_click needs a reftag, so it was not signed")
    else:
        # the Play Store referrer broadcast lands seconds after first open:
        # keep session -> sdk_click short and realistic
        time.sleep(12)
        sec = signing_second()
        say("signing  /sdk_click ...")
        fields = build_click_request(gaid, android_uuid, sec, referrer,
                                     click_sec=click_second)
        auth = sign(fields, "click", sec)
        say("         %d fields" % len(fields))
        if not DRY_RUN:
            status, _ = call("POST", "/sdk_click", fields, auth)
            say("         -> %d  [t=+%.0fs]"
                % (status, time.time() - started))
            elog("sdk_click -> HTTP %d" % status)

    if not DRY_RUN and SEND_EVENT:
        if GAP:
            time.sleep(GAP)
        say("signing  /event ...")
        sec = signing_second()
        fields = build_event_request(gaid, android_uuid, sec)
        auth = sign(fields, "event", sec)
        say("         %d fields" % len(fields))
        status, body = call("POST", "/event", fields, auth)
        say("         -> %d %s  [t=+%.0fs]"
            % (status, body[:60], time.time() - started))

    if DRY_RUN:
        say("attribution  DRY RUN - not polling")
        say("")
        say("config is valid: the session signed cleanly.")
        return 0

    verdict = {}
    for delay in CFG["poll_delays"]:
        time.sleep(delay)
        sec = signing_second()
        fields = build_attribution_request(gaid, android_uuid, sec)
        auth = sign(fields, "attribution", sec)
        _status, body = call("GET", "/attribution", fields, auth)
        print(body)
        verdict = json.loads(body).get("attribution") or {}
        say("poll +%-2ds   %s / %s  [t=+%.0fs]"
            % (delay, verdict.get("network"), verdict.get("tracker_token"),
               time.time() - started))
        elog("poll +%ds -> network=%s tracker=%s name=%s"
             % (delay, verdict.get("network"), verdict.get("tracker_token"),
                verdict.get("tracker_name")))
        if verdict.get("network") and verdict["network"] != "Organic":
            break

    say("")
    elog("FINAL ATTRIBUTION: %s" % json.dumps(verdict))
    elog("=" * 78)
    if verdict.get("network", "Organic") != "Organic":
        say("*** NON-ORGANIC ***   %.0fs total" % (time.time() - started))
        for field in ("network", "tracker_token", "tracker_name", "campaign",
                      "adgroup", "engagement_time"):
            say("  %-16s %s" % (field, verdict.get(field)))
        say("  %-16s %s" % ("adid", adid))
    else:
        say("*** Organic / not joined ***   %.0fs total"
            % (time.time() - started))
    return 0

if __name__ == "__main__":
    say("campaign  %s / %s" % (CFG["package_name"], CFG["app_token"]))
    say("device    %s %s (Android %s, api %s)"
        % (PARAMS["device_manufacturer"], PARAMS["device_name"],
           PARAMS["os_version"], PARAMS["api_level"]))
    say("signer    adj8_pure_py27 (pure Python, cert %s...)"
        % CFG["cert_sha1"][:12])
    raise SystemExit(main())
