# -*- coding: utf-8 -*-
"""run_berain_py27.py -- the adj7-iOS fresh install funnel for
com.berain.berain (Berain Water), PYTHON 2.7.

The click link is HARDCODED below (the tracker-20yvzdd5 direct Adjust link
that booked non-organic TMV Media / 20fholu3 on 2026-10-09).

    python2.7 run_berain_py27.py --dry-run
    python2.7 run_berain_py27.py
"""
from __future__ import print_function

import gzip
import json
import os
import sys
import time
import urllib
import urllib2
import uuid
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from adj7ios_pure_py27 import sign_request  # noqa: E402

# ============================ CAMPAIGN (berain) ==========================
CAMPAIGN = {
    "package_name": "com.berain.berain",          # bundle_id on the wire
    "app_token": "xb80fzavg0zk",
    "app_version": "1",
    "app_version_short": "4.4.4",
    "client_sdk": "ios5.5.2",
    "adj_signing_id": "1300000",
    "algorithm": "adj7",
    "headers_id": "8",
    "native_version": "3.62.0",
    "os_name": "ios",
    "os_version": "16.7.12",
    "device_name": "iPhone10,1",
    "device_type": "iPhone",
    "att_status": "3",
}
PACKAGE_NAME = CAMPAIGN["package_name"]
APP_TOKEN = CAMPAIGN["app_token"]
APP_VERSION = CAMPAIGN["app_version"]
CLIENT_SDK = CAMPAIGN["client_sdk"]
BASE = os.environ.get("FUNNEL_BASE", "https://consent.adjust.com")
DRY_RUN = "--dry-run" in sys.argv
SIGN_ALL = "--sign-all" in sys.argv

# the direct Adjust click link (tracker 20yvzdd5) + our idfa join param
LINK = ("https://app.adjust.com/20yvzdd5?campaign=TMV+May_Derby"
        "&adgroup=NP_SH_Q&os_name=ios&idfa={idfa}&gps_adid={idfa}"
        "&click_id={click_id}")

DEVICE = {
    "device_name": CAMPAIGN["device_name"],
    "device_type": CAMPAIGN["device_type"],
    "os_version": CAMPAIGN["os_version"],
    "environment": "production",
    "timezone": "+0530",
    "country": "IN",
    "language": "en",
}
if os.environ.get("FUNNEL_DEVICE_JSON"):
    DEVICE.update(json.load(open(os.environ["FUNNEL_DEVICE_JSON"])))

CIT = int(os.environ.get("FUNNEL_CIT", "22"))
ADJ_CLICK_SEC = None
CLICK_SKIPPED = False
PROXY = os.environ.get("FUNNEL_PROXY", "")

BROWSER_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 "
              "Mobile/15E148 Safari/604.1")
APP_UA = "Berain-Swift/1 CFNetwork/1410.1 Darwin/22.6.0"   # the capture's UA


def _jitter():
    import random
    return random.randint(11, 977)


def _ts_pair(sec):
    import random
    m1 = _jitter()
    m2 = m1 + random.randint(7, 45)
    s2 = sec
    if m2 > 999:
        m2 -= 1000
        s2 += 1
    return _stamp(sec, m1), _stamp(s2, m2)


def signing_second():
    return int(time.time()) - 2


def _stamp(ts, ms):
    sign = 1 if DEVICE["timezone"][0] != "-" else -1
    off = (sign * (int(DEVICE["timezone"][1:3]) * 3600
                   + int(DEVICE["timezone"][3:5]) * 60))
    dt = datetime.utcfromtimestamp(ts + off)
    return (dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms) + "Z"
            + DEVICE["timezone"])


def log(*parts):
    print("[%s] %s" % (datetime.now().strftime("%H:%M:%S"),
                       " ".join(str(p) for p in parts)))
    sys.stdout.flush()


def _proxies():
    return {"http": PROXY, "https": PROXY} if PROXY else None


# ============================ the click ==================================
def new_idfa():
    return str(uuid.uuid4()).upper()


def new_idfv():
    return str(uuid.uuid4()).upper()


def new_dedupe():
    return str(uuid.uuid4())


def _subst(url, idfa):
    return (url.replace("{click_id}", "z" + uuid.uuid4().hex[:12])
                .replace("{idfa}", idfa))


def _get(url):
    """Fetch the click as iOS Safari would (curl_cffi safari fingerprint,
    falling back to urllib)."""
    try:
        from curl_cffi import requests as _cr
        r = _cr.get(url, timeout=30, impersonate="safari17_0",
                    allow_redirects=False, verify=False,
                    headers={"User-Agent": BROWSER_UA,
                             "Accept": "text/html,application/xhtml+xml,"
                                       "application/xml;q=0.9,*/*;q=0.8",
                             "Accept-Language": "en-us",
                             "Upgrade-Insecure-Requests": "1"})
        return (r.status_code,
                {k.lower(): v for k, v in r.headers.items()}, r.text)
    except ImportError:
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers,
                                 newurl):
                return None

        req = urllib.request.Request(url, headers={
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,"
                      "application/xml;q=0.9,*/*;q=0.8"})
        opener = urllib.request.build_opener(NoRedirect)
        try:
            r = opener.open(req, timeout=30)
            return (r.getcode(),
                    {k.lower(): v for k, v in r.info().items()}, r.read())
        except urllib.request.HTTPError as e:
            return (e.code,
                    {k.lower(): v for k, v in e.headers.items()},
                    e.read())


def open_click_link(idfa):
    """Fire the Adjust click link and return (reftag_or_None, server_sec)."""
    global ADJ_CLICK_SEC, CLICK_SKIPPED
    ADJ_CLICK_SEC = None
    CLICK_SKIPPED = False
    pre = os.environ.get("FUNNEL_REFTAG")
    if pre:
        ADJ_CLICK_SEC = int(os.environ.get("FUNNEL_CLICK_SEC") or 0) or None
        return pre
    url = os.environ.get("FUNNEL_CLICK_URL") or _subst(LINK, idfa)
    if url.strip().lower() in ("skip", "none", "off"):
        CLICK_SKIPPED = True
        return None
    import re as _re
    for attempt in (1, 2):
        u = url
        for _hop in range(12):
            if not (u.startswith("http://") or u.startswith("https://")):
                break
            try:
                status, hdrs, text = _get(u)
            except Exception as exc:
                log("click hop error: %r" % (exc,))
                break
            if "app.adjust.com" in u:
                _d = hdrs.get("date")
                if _d:
                    try:
                        import email.utils as _eu
                        ADJ_CLICK_SEC = int(_eu.parsedate_to_datetime(
                            _d).strftime("%s"))
                    except Exception:
                        ADJ_CLICK_SEC = None
            loc = hdrs.get("location")
            if loc:
                ref = None
                if "referrer=" in loc:
                    r = urllib.unquote(
                        loc.split("referrer=", 1)[1])
                    r = r.split(";S.browser_fallback_url")[0]
                    r = _re.sub(r"&ip_address=\{[^&]*\}", "", r)
                    ref = r
                if ref:
                    return ref
                if loc.startswith("http"):
                    u = loc
                    continue
                print("click    terminal: %s" % loc[:160])
                break
            print("click    -> %s (no redirect; idfa join)" % status)
            break
        if attempt == 1:
            time.sleep(2)
    return None


# ============================ the wire builders =========================
def _common(sec):
    cat, sat = _ts_pair(sec)
    return {
        "app_token": APP_TOKEN,
        "app_version": APP_VERSION,
        "app_version_short": CAMPAIGN["app_version_short"],
        "att_status": CAMPAIGN["att_status"],
        "attribution_deeplink": "1",
        "bundle_id": PACKAGE_NAME,
        "created_at": cat,
        "device_name": DEVICE["device_name"],
        "device_type": DEVICE["device_type"],
        "environment": DEVICE["environment"],
        "foreground": "1",
        "idfa": _IDFA,
        "idfv": _IDFV,
        "needs_response_details": "1",
        "offline_mode_enabled": "0",
        "os_name": "ios",
        "os_version": DEVICE["os_version"],
        "primary_dedupe_token": _DEDUPE,
        "send_in_background_enabled": "0",
        "sent_at": sat,
        "started_at": _stamp(_STARTED, 0),
    }


def build_tps_request(sec):
    c = _common(sec)
    c.update({"enqueue_size": "0", "installed_at": _stamp(_INSTALL,
                                                          _jitter()),
              "retry_count": "0", "session_count": "0",
              "sharing": "enable"})
    return c


def build_session_request(sec):
    c = _common(sec)
    c.update({"enqueue_size": "0", "installed_at": _stamp(_INSTALL,
                                                          _jitter()),
              "retry_count": "0", "session_count": "1"})
    return c


def build_click_request(sec, reftag, click_sec):
    """POST /sdk_click -- the genuine berain row 045 shape."""
    installed = _stamp(click_sec + 8, _jitter())
    c = _common(sec)
    c.update({
        "source": "install_referrer",
        "attribution_token": "",
        "session_count": "1",
        "session_length": "0",
        "subsession_count": "1",
        "time_spent": "0",
        "click_time": _stamp(click_sec, 0),
        "click_time_server": _stamp(click_sec - 1, 0),
        "install_begin_time": _stamp(click_sec + 6, 0),
        "install_begin_time_server": _stamp(click_sec + 5, 0),
        "install_version": APP_VERSION,
        "google_play_instant": "0",
        "installed_at": installed,
        "updated_at": installed,
    })
    if reftag:
        c["referrer"] = reftag
        c["referrer_api"] = "google"
    return c


def build_attribution_request(sec, init_by="backend"):
    c = _common(sec)
    c.update({"initiated_by": init_by,
              "installed_at": _stamp(_INSTALL, _jitter())})
    c.pop("foreground", None)
    c.pop("offline_mode_enabled", None)
    return c


def _sign(fields, kind, sec):
    auth, blob = sign_request(fields, kind, second=sec,
                              client_sdk=CLIENT_SDK)
    return auth


def _call(method, path, fields, auth):
    import requests as _req
    if method == "POST":
        body = urllib.urlencode(fields).encode()
        url = BASE + path
    else:
        body = None
        url = BASE + path + "?" + urllib.urlencode(fields)
    headers = {"Client-Sdk": CLIENT_SDK, "User-Agent": APP_UA,
               "Accept-Encoding": "gzip"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Authorization"] = auth
    r = _req.request(method, url, data=body, headers=headers, timeout=30,
                     proxies=_proxies())
    if r.headers.get("content-encoding") == "gzip":
        try:
            txt = gzip.decompress(r.content).decode("utf-8", "replace")
        except Exception:
            txt = r.text
    else:
        txt = r.text
    return r.status_code, txt


_IDFA = None
_IDFV = None
_DEDUPE = None
_STARTED = None
_INSTALL = None


def main():
    global _IDFA, _IDFV, _DEDUPE, _STARTED, _INSTALL
    _IDFA = os.environ.get("FUNNEL_IDFA") or new_idfa()
    _IDFV = new_idfv()
    _DEDUPE = new_dedupe()
    started = time.time()
    T0 = int(started)
    _STARTED = T0 - 1020
    _INSTALL = T0 - 29
    log("=" * 78)
    log("BERAIN (adj7 iOS) INSTALL FUNNEL  bundle=%s  idfa=%s"
        % (PACKAGE_NAME, _IDFA))
    log("click: %s" % _subst(LINK, "{idfa}"))
    log("=" * 78)

    reftag = None
    if not DRY_RUN:
        reftag = open_click_link(_IDFA)
        log("click done: reftag=%s  click_server_sec=%s  [t=+%.0fs]"
            % (reftag or ("none -- idfa join" if not CLICK_SKIPPED
                          else "SKIPPED"),
               ADJ_CLICK_SEC, time.time() - started))
    click_second = ADJ_CLICK_SEC or (T0 - 1)

    last_run = {"mode": "dry-run" if DRY_RUN else "live",
                "app": PACKAGE_NAME, "idfa": _IDFA, "idfv": _IDFV,
                "dedupe": _DEDUPE, "reftag": reftag,
                "click_second": click_second}
    with open(os.path.join(HERE, "last_run_berain.json"), "w") as f:
        json.dump(last_run, f, indent=1)

    if not DRY_RUN:
        wait = 0 if CLICK_SKIPPED else (click_second + CIT - time.time())
        if wait > 0:
            log("installing... (CTIT %.0fs)" % wait)
            time.sleep(wait)

    def fire(label, fields, kind, method, path, sec):
        auth = _sign(fields, kind, sec)
        print("signing  %s ...  %d fields, blob 304 B  [t=+%.0fs]"
              % (path, len(fields), time.time() - started))
        if DRY_RUN and not SIGN_ALL:
            print("         signed -- not sending")
            return None, None
        st, body = _call(method, path, fields, auth)
        log("%s -> HTTP %d  %s" % (label, st, body[:130]))
        return st, body

    # 1. session (creates the adid -- tps first would get "device not found"
    #    on a fresh install), 2. tps, 3. sdk_click, 4. attribution
    sec2 = signing_second()
    st, body = fire("session", build_session_request(sec2), "session",
                    "POST", "/session", sec2)
    if DRY_RUN and not SIGN_ALL:
        print()
        print("config is valid: session signed cleanly (adj7 iOS).")
        return 0
    try:
        adid = json.loads(body).get("adid", "")
        ask_in = json.loads(body).get("ask_in")
    except ValueError:
        adid, ask_in = "", None
    log("session -> HTTP %d adid %s ask_in %s" % (st, adid, ask_in))
    last_run["adid"] = adid
    last_run["session_ask_in"] = ask_in
    init_by = "backend" if ask_in is not None else "sdk"

    sec = signing_second()
    fire("tps", build_tps_request(sec), "third_party_sharing", "POST",
         "/third_party_sharing", sec)

    sec3 = signing_second()
    fire("sdk_click", build_click_request(sec3, reftag, click_second),
         "click", "POST", "/sdk_click", sec3)

    verdict = {}
    for i in range(6):
        time.sleep(2.8 if i == 0 else (1.4 if i == 1 else 20))
        sec4 = signing_second()
        af = build_attribution_request(sec4, init_by)
        st4, body4 = fire("attribution", af, "attribution", "GET",
                          "/attribution", sec4)
        try:
            payload = json.loads(body4)
        except ValueError:
            payload = {}
        verdict = payload.get("attribution") or {}
        ask = payload.get("ask_in")
        print("%-14s -> %-9s / %-9s ask_in=%s  [t=+%.0fs]"
              % ("poll %d" % (i + 1), verdict.get("network"),
                 verdict.get("tracker_token"), ask,
                 time.time() - started))
        if verdict.get("network") and verdict["network"] != "Organic":
            break

    log("FINAL ATTRIBUTION: %s" % json.dumps(verdict))
    last_run["attribution"] = verdict
    with open(os.path.join(HERE, "last_run_berain.json"), "w") as f:
        json.dump(last_run, f, indent=1)
    if verdict.get("network", "Organic") != "Organic":
        print("*** NON-ORGANIC ***   %.0fs total" % (time.time() - started))
        for k in ("network", "tracker_token", "tracker_name", "campaign",
                  "adgroup", "engagement_time", "adid"):
            print("  %-16s %s" % (k, verdict.get(k)))
    else:
        print("*** Organic / not joined ***   %.0fs total"
              % (time.time() - started))
    return 0


if __name__ == "__main__":
    print("campaign  %s / %s (adj7 iOS, signing id %s, headers %s, native %s)"
          % (PACKAGE_NAME, APP_TOKEN, CAMPAIGN["adj_signing_id"],
             CAMPAIGN["headers_id"], CAMPAIGN["native_version"]))
    print("device    %s (iOS %s, idfa fresh-per-run)"
          % (DEVICE["device_name"], DEVICE["os_version"]))
    print("signer    adj7ios_pure (raw-MINSTD stream, ASCII-0 cert40)")
    raise SystemExit(main())
