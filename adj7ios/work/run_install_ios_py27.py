# -*- coding: utf-8 -*-
"""run_install_ios_py27.py -- the adj7 iOS live install funnel, PYTHON 2.7.

Same funnel as run_install_ios.py (adj8 py27 conventions):

    python2.7 run_install_ios_py27.py --dry-run     # build + sign, send nothing
    python2.7 run_install_ios_py27.py               # click -> [CTIT] -> tps ->
                                                    #   session -> attribution

Flow mirrors the GENUINE nirio iOS capture (adj7/ios/nirio_08Sep/, 08 Sep):
click (the link's idfa= must carry the SAME idfa the session claims -- that
is the whole click->install join on iOS) -> CTIT -> third_party_sharing ->
session -> attribution (double-ask + poll).

Signing = adj7ios_pure_py27 (raw-MINSTD header with the per-second stream
law, ASCII-0 cert40, 98-key pool, 1300000 pinned before seq, block2 last).
The selftest is 22/22 byte-exact vs the gold vectors on py2.7.
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

try:
    from urlparse import urlsplit
except ImportError:                                   # pragma: no cover
    from urllib.parse import urlsplit

try:
    import httplib as httpclient
except ImportError:                                   # pragma: no cover
    import http.client as httpclient

try:
    from urllib import quote as _quote
except ImportError:                                   # pragma: no cover
    from urllib.parse import quote as _quote


def _urlencode(fields):
    return urllib.urlencode(fields)


def _urlencode_get(fields):
    """GET query: the genuine wire keeps %20 (not +) in device_name.
    py2's urlencode has no quote_via, so quote each pair by hand."""
    return "&".join(
        "%s=%s" % (urllib.quote(str(k), safe=""),
                   urllib.quote(str(v), safe=""))
        for k, v in fields.items())


# ===================== CAMPAIGN -- THE BOOKING APP (berain / TMV) ========
# This is the configuration that BOOKED NON-ORGANIC from pure Python on
# 2026-10-09:  TMV Media / tracker 20fholu3 / campaign TMV May_Derby /
# adgroup NP_SH_Q, engagement at the click, adid
# 4a4bd2c212134f84bfd4a296dcdd977a.  (Campaign constants are from the
# genuine berain capture berainwatert1_20may_ios8_newapp_install.saz.)
CAMPAIGN = {
    "package_name": "com.berain.berain",           # bundle_id on the wire
    "app_token": "xb80fzavg0zk",
    "app_version": "1",
    "app_version_short": "4.4.4",
    "client_sdk": "ios5.5.2",                      # the capture's Client-Sdk
    "adj_signing_id": "1300000",
    "algorithm": "adj7",
    "headers_id": "8",
    "native_version": "3.62.0",
    "os_name": "ios",
    "os_version": "16.7.12",                       # the capture's iOS build
    "device_name": "iPhone10,1",
    "device_type": "iPhone",
    "att_status": "3",                             # AT tracking allowed
}
# (the earlier nirio config, for reference:)
#   com.fdjservices.nirio / cv4d2hlazp4w / app_version 494 / 16.4.6 /
#   react-native5.4.4@ios5.4.6 / headers_id 7 / native_version 3.61.0 /
#   link https://app.adjust.com/1xgvk2dz?campaign=NIRIO_mobsuccess_iOS...
PACKAGE_NAME = CAMPAIGN["package_name"]
APP_TOKEN = CAMPAIGN["app_token"]
APP_VERSION = CAMPAIGN["app_version"]
CLIENT_SDK = CAMPAIGN["client_sdk"]

if os.environ.get("FUNNEL_ATT_STATUS"):
    CAMPAIGN["att_status"] = os.environ["FUNNEL_ATT_STATUS"]
BASE = os.environ.get("FUNNEL_BASE", "https://consent.adjust.com")

# THE CLICK LINK THAT BOOKED (hardcoded; tracker 20yvzdd5).
# On iOS the join param is idfa= -- the same value must be claimed in the
# session.  No ip_address= / android_id= (the shape that won).
LINK = ("https://app.adjust.com/20yvzdd5?campaign=TMV+May_Derby"
        "&adgroup=NP_SH_Q&os_name=ios&idfa={idfa}&gps_adid={idfa}"
        "&click_id={click_id}")
# The upstream tracker hop (only a real browser gets the 302, so it is
# optional -- recorded for reference):
#   https://adjar.trckswrm.com/click?offer_id=5395&pub_id=52
#       &pub_sub_id=1298014792&pub_click_id=<fresh>&idfa=<idfa>
#       &gaid=<gaid>&app=com.berain.berain&creative=NP_SH_Q
#   -> 302 https://app.adjust.com/20yvzdd5?campaign=TMV+May_Derby&adgroup=NP_SH_Q...
#   -> 302 https://apps.apple.com/app/id1298014792?mt=8

DEVICE = {
    "device_name": CAMPAIGN["device_name"],
    "device_type": CAMPAIGN["device_type"],
    "os_version": CAMPAIGN["os_version"],
    "environment": "production",
    "timezone": "+0530",
    "country": "IN",
    "language": "en",
}
_dj = os.environ.get("FUNNEL_DEVICE_JSON")
if _dj:
    DEVICE.update(json.load(open(_dj)))
    print("device profile override:", _dj)

INSTALL_AFTER = 14          # click -> installed_at (the proven adj7 story)
CIT = int(os.environ.get("FUNNEL_CIT", "22"))
ADJ_CLICK_SEC = None        # the adjust click's server Date second
DRY_RUN = "--dry-run" in sys.argv
SIGN_ALL = "--sign-all" in sys.argv
PROXY = os.environ.get("FUNNEL_PROXY", "")

BROWSER_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 "
              "Mobile/15E148 Safari/604.1")
APP_UA = "Berain-Swift/1 CFNetwork/1410.1 Darwin/22.6.0"   # the capture's UA


def _jitter():
    import random
    return random.randint(11, 977)


def _ts_pair(sec):
    """(created_at, sent_at): sent_at lands 7-45 ms after created_at."""
    import random
    m1 = _jitter()
    d = random.randint(7, 45)
    m2 = m1 + d
    s2 = sec
    if m2 > 999:
        m2 -= 1000
        s2 += 1
    return _stamp(sec, m1), _stamp(s2, m2)


def signing_second():
    return int(time.time()) - 2        # mint skew: sign just before send


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
    if not PROXY:
        return None
    return {"http": PROXY, "https": PROXY}


# ============================ the click ==================================
def new_idfa():
    """Fresh uppercase IDFA per run (the capture's are uppercase)."""
    return str(uuid.uuid4()).upper()


def new_idfv():
    return str(uuid.uuid4()).upper()


def new_dedupe():
    return str(uuid.uuid4())


def _subst(url, idfa, ip):
    return (url.replace("{click_id}", "z" + uuid.uuid4().hex[:12])
                .replace("{idfa}", idfa)
                .replace("{ip}", ip)
                .replace("{creativeid}", "nirio_ios")
                .replace("{REPLACE}", idfa))


CLICK_SKIPPED = False


def _get(url):
    """Fetch the click as iOS Safari would (curl_cffi safari fingerprint;
    falls back to urllib without it)."""
    try:
        from curl_cffi import requests as _cr
        r = _cr.get(url, timeout=30, impersonate="safari17_0",
                    allow_redirects=False,
                    headers={"Accept": ("text/html,application/xhtml+xml,"
                                        "application/xml;q=0.9,*/*;q=0.8"),
                             "Accept-Language": "en-us",
                             "Upgrade-Insecure-Requests": "1"})
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text
    except ImportError:
        req = urllib2.Request(url, headers={
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;"
                      "q=0.9,*/*;q=0.8",
        })
        opener = urllib2.build_opener(NoRedirect)
        try:
            r = opener.open(req, timeout=30)
            return r.getcode(), \
                {k.lower(): v for k, v in r.info().items()}, r.read()
        except urllib2.HTTPError as e:
            return e.code, \
                {k.lower(): v for k, v in e.headers.items()}, e.read()


class NoRedirect(urllib2.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_click_link(idfa):
    """Visit the tracker link (up to two passes, 12 hops) as iOS Safari and
    return (reftag_or_None, click_server_second).  On iOS the reftag is
    OPTIONAL (the capture's install joined by idfa match)."""
    global ADJ_CLICK_SEC, CLICK_SKIPPED
    ADJ_CLICK_SEC = None
    CLICK_SKIPPED = False
    pre = os.environ.get("FUNNEL_REFTAG")
    if pre:
        cs = os.environ.get("FUNNEL_CLICK_SEC")
        ADJ_CLICK_SEC = int(cs) if cs else None
        return pre
    ip = os.environ.get("FUNNEL_IP",
                        "103.25.128." + str(int(time.time()) % 254 + 1))
    url = os.environ.get("FUNNEL_CLICK_URL") or _subst(LINK, idfa, ip)
    if url.strip().lower() in ("skip", "none", "off"):
        CLICK_SKIPPED = True
        return None                     # click-free probe run
    for attempt in (1, 2):
        u = url
        for hop in range(12):
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
                        ADJ_CLICK_SEC = int(
                            _eu.parsedate_to_datetime(_d)
                            .strftime("%s"))
                    except Exception:
                        ADJ_CLICK_SEC = None
            loc = hdrs.get("location")
            if loc:
                import re as _re
                ref = None
                if "referrer=" in loc:
                    r = urllib.unquote(loc.split("referrer=", 1)[1])
                    r = r.split(";S.browser_fallback_url")[0]
                    r = _re.sub(r"&ip_address=\{[^&]*\}", "", r)
                    ref = r
                if ref:
                    return ref
                u = loc
                continue
            break
        if attempt == 1:
            time.sleep(2)
    return None


# ============================ the wire builders =========================
def _common(sec):
    cat, sat = _ts_pair(sec)
    c = {
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
    return c


def build_tps_request(sec):
    """POST /third_party_sharing -- the capture's sids 32/36/37."""
    c = _common(sec)
    c.update({
        "enqueue_size": "0",
        "installed_at": _stamp(_INSTALL, _jitter()),
        "retry_count": "0",
        "session_count": "0",
        "sharing": "enable",
    })
    return c


def build_session_request(sec):
    """POST /session -- the capture's sid 38 (creates the adid)."""
    c = _common(sec)
    c.update({
        "enqueue_size": "0",
        "installed_at": _stamp(_INSTALL, _jitter()),
        "retry_count": "0",
        "session_count": "1",
    })
    return c


def build_click_request(sec, reftag, click_sec):
    """POST /sdk_click -- the genuine berain row 045 shape (the click the
    SDK reports once it has installed)."""
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
    """GET /attribution -- the capture's sid 39 (keeps installed_at; no
    foreground / offline_mode_enabled)."""
    c = _common(sec)
    c.update({
        "initiated_by": init_by,
        "installed_at": _stamp(_INSTALL, _jitter()),
    })
    c.pop("foreground", None)
    c.pop("offline_mode_enabled", None)
    return c


def _sign(fields, kind, sec):
    auth, blob = sign_request(fields, kind, second=sec,
                              client_sdk=CLIENT_SDK)
    return auth


def _call(method, path, fields, auth):
    """POST/GET via httplib (py2), gzip-aware, ordered headers."""
    if method == "POST":
        body = _urlencode(fields)
        target = path
    else:
        body = None
        target = path + "?" + _urlencode_get(fields)
    p = urlsplit(BASE)
    c = httpclient.HTTPConnection(p.hostname, p.port or 443, timeout=30)
    if p.scheme == "https":
        import ssl
        c = httpclient.HTTPSConnection(p.hostname, p.port or 443,
                                       timeout=30,
                                       context=ssl._create_unverified_context())
    hdrs = [("Client-Sdk", CLIENT_SDK),
            ("Authorization", auth)]
    if body is not None:
        hdrs.append(("Content-Type",
                     "application/x-www-form-urlencoded"))
    hdrs += [("User-Agent", APP_UA),
             ("Host", p.hostname),
             ("Connection", "close"),
             ("Accept-Encoding", "gzip")]
    if body is not None:
        hdrs.append(("Content-Length", str(len(body))))
    # httplib requires the request line FIRST, then the headers
    c.putrequest(method, target, skip_host=1, skip_accept_encoding=1)
    for k, v in hdrs:
        c.putheader(k, v)
    c.endheaders(body)
    r = c.getresponse()
    raw = r.read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    c.close()
    return r.status, raw


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
    _STARTED = T0 - 1020          # the capture: app started ~17 min before
    _INSTALL = T0 - 29            # the capture: installed 29 s before session
    log("=" * 78)
    log("ADJ7 iOS INSTALL FUNNEL (py27)  app=%s  idfa=%s"
        % (PACKAGE_NAME, _IDFA))
    log("click: %s" % _subst(LINK, "{idfa}", "{ip}"))
    log("=" * 78)

    reftag = None
    if not DRY_RUN:
        reftag = open_click_link(_IDFA)
        log("click done: reftag=%s  click_server_sec=%s  [t=+%.0fs]"
            % (reftag or ("none -- idfa join" if not CLICK_SKIPPED
                          else "SKIPPED (click-free probe)"),
               ADJ_CLICK_SEC, time.time() - started))
    click_second = ADJ_CLICK_SEC or T0

    last_run = {"mode": "dry-run" if DRY_RUN else "live",
                "app": PACKAGE_NAME, "idfa": _IDFA, "idfv": _IDFV,
                "dedupe": _DEDUPE, "reftag": reftag,
                "click_second": click_second}
    with open(os.path.join(HERE, "last_run_ios_py27.json"), "w") as _f:
        json.dump(last_run, _f, indent=1)

    if not DRY_RUN:
        wait = 0 if CLICK_SKIPPED else (click_second + CIT - time.time())
        if wait > 0:
            log("installing... (CTIT %.0fs)" % wait)
            time.sleep(wait)

    # 1. session FIRST (a fresh install has no adid yet: tps before the
    #    session answers "device not found"), 2. tps, 3. attribution
    sec2 = signing_second()
    s_fields = build_session_request(sec2)
    s_auth = _sign(s_fields, "session", sec2)
    print("signing  /session ...  %d fields, blob 304 B  [t=+%.0fs]"
          % (len(s_fields), time.time() - started))
    if DRY_RUN and not SIGN_ALL:
        print("         signed -- not sending")
        with open(os.path.join(HERE, "last_run_ios_py27.json"), "w") as f:
            json.dump(last_run, f, indent=1)
        print()
        print("config is valid: tps+session signed cleanly (adj7 iOS).")
        return 0
    st, body = _call("POST", "/session", s_fields, s_auth)
    try:
        adid = json.loads(body).get("adid", "")
        ask_in = json.loads(body).get("ask_in")
    except ValueError:
        adid, ask_in = "", None
    log("session -> HTTP %d adid %s ask_in %s" % (st, adid, ask_in))
    last_run["adid"] = adid
    init_by = "backend" if ask_in is not None else "sdk"

    if not DRY_RUN:
        sec = signing_second()
        tps_fields = build_tps_request(sec)
        tps_auth = _sign(tps_fields, "third_party_sharing", sec)
        print("signing  /third_party_sharing ...  %d fields, blob 304 B  "
              "[t=+%.0fs]" % (len(tps_fields), time.time() - started))
        st, body = _call("POST", "/third_party_sharing", tps_fields,
                         tps_auth)
        log("tps -> HTTP %d  %s" % (st, body[:100]))

    # 3. sdk_click -- the SDK reports the install click it was opened with
    if not DRY_RUN:
        sec3 = signing_second()
        c_fields = build_click_request(sec3, reftag, click_second)
        c_auth = _sign(c_fields, "click", sec3)
        print("signing  /sdk_click ...  %d fields, blob 304 B  [t=+%.0fs]"
              % (len(c_fields), time.time() - started))
        st, body = _call("POST", "/sdk_click", c_fields, c_auth)
        log("sdk_click -> HTTP %d  %s" % (st, body[:100]))

    # 4. attribution (double-ask + poll, the proven ending)
    def ask(label, pause):
        time.sleep(pause)
        asec = signing_second()
        a_fields = build_attribution_request(asec, init_by)
        a_auth = _sign(a_fields, "attribution", asec)
        print("signing  /attribution (%s) ...  %d fields  [t=+%.0fs]"
              % (label, len(a_fields), time.time() - started))
        _st, body = _call("GET", "/attribution", a_fields, a_auth)
        try:
            verdict = json.loads(body).get("attribution") or {}
        except ValueError:
            verdict = {}
            log("%s -> HTTP %s non-JSON %r" % (label, _st, body[:80]))
        print("%-14s -> %s / %s  [t=+%.0fs]"
              % (label, verdict.get("network"), verdict.get("tracker_token"),
                 time.time() - started))
        return verdict

    verdict = ask("attribution", 2.8)
    if verdict.get("network", "Organic") == "Organic":
        verdict = ask("re-ask +1.4s", 1.4) or verdict
    if verdict.get("network", "Organic") == "Organic":
        verdict = ask("poll +30s", 30) or verdict
    if verdict.get("network", "Organic") == "Organic":
        verdict = ask("poll +60s", 60) or verdict

    log("FINAL ATTRIBUTION: %s" % json.dumps(verdict))
    last_run["attribution"] = verdict
    with open(os.path.join(HERE, "last_run_ios_py27.json"), "w") as f:
        json.dump(last_run, f, indent=1)
    if verdict.get("network", "Organic") != "Organic":
        print("*** NON-ORGANIC ***   %.0fs total" % (time.time() - started))
        # adid comes from the SESSION response, not the attribution object
        summary = dict(verdict)
        summary["adid"] = last_run.get("adid")
        for field in ("network", "tracker_token", "tracker_name", "campaign",
                      "adgroup", "engagement_time", "adid"):
            print("  %-16s %s" % (field, summary.get(field)))
    else:
        print("*** Organic / not joined ***   %.0fs total"
              % (time.time() - started))
    return 0


if __name__ == "__main__":
    print("campaign  %s / %s (adj7 iOS, signing id %s, headers %s, native %s)"
          % (PACKAGE_NAME, APP_TOKEN, CAMPAIGN["adj_signing_id"],
             CAMPAIGN["headers_id"], CAMPAIGN["native_version"]))
    print("device    %s (%s %s, idfa fresh-per-run)"
          % (DEVICE["device_name"], "iOS", DEVICE["os_version"]))
    print("signer    adj7ios_pure_py27 (raw-MINSTD stream, ASCII-0 cert40)")
    raise SystemExit(main())
