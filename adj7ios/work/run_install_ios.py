# -*- coding: utf-8 -*-
"""run_install_ios.py -- the adj7 iOS live install funnel (non-organic).

    python run_install_ios.py --dry-run     # build + sign, send nothing
    python run_install_ios.py               # click -> [CTIT] -> tps ->
                                            #   session -> attribution

Flow mirrors the GENUINE nirio iOS capture (adj7/ios/nirio_08Sep/, 08 Sep)
with the winning-flow lessons from the adj9 reference
(adj9/adj9_tool/pentiandroid.py):

  1. CLICK   the tracker link as an iOS Safari (the link's idfa= must carry
             the SAME idfa the session later claims -- that is the whole
             click->install join on iOS; there is no Play referrer here).
             The link is the user's: https://app.adjust.com/1xgvk2dz?...
             with {REPLACE} slots filled (click_id, idfa, ...).
  2. CTIT    click -> install gap (FUNNEL_CIT, default 22 s like the
             genuine nirio Android funnel; adj9's wins were 7-8 s -- pass
             FUNNEL_CIT=10 for that shape).
  3. tps     POST /third_party_sharing  (the capture fires this FIRST on
             iOS -- 3x, then session; we fire 1)
  4. session POST /session   (creates the adid; ask_in decides who resolves)
  5. ask     GET  /attribution  initiated_by=backend (when ask_in came back)
             with the device's double-ask + a 30 s poll, exactly the
             proven Android funnel's ending.

Signing = adj7_ios_pure (raw-MINSTD header, ASCII-0 cert40, 98-key pool).
Every request signed at ITS OWN second (the header seed = send moment --
proven by the capture's sids 36/37/38).
"""
import gzip
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

from adj7_ios_pure import sign_request  # noqa: E402

# ============================ CAMPAIGN (the iOS nirio app) ================
CAMPAIGN = {
    "package_name": "com.fdjservices.nirio",       # bundle_id on the wire
    "app_token": "cv4d2hlazp4w",
    "app_version": "494",                          # the capture's build no.
    "app_version_short": "16.4.6",
    "client_sdk": "react-native5.4.4@ios5.4.6",    # the capture's Client-Sdk
    "adj_signing_id": "1300000",
    "algorithm": "adj7",
    "headers_id": "7",
    "native_version": "3.61.0",
    "os_name": "ios",
    "os_version": "16.7.16",                       # the capture's iOS build
    "device_name": "iPhone10,1",
    "device_type": "iPhone",
    "att_status": "3",                             # AT tracking allowed
}
PACKAGE_NAME = CAMPAIGN["package_name"]
APP_TOKEN = CAMPAIGN["app_token"]
APP_VERSION = CAMPAIGN["app_version"]
CLIENT_SDK = CAMPAIGN["client_sdk"]

# env overrides (the adj9_ios-proved shapes are reachable from this one
# script:  FUNNEL_ATT_STATUS=0 FUNNEL_BASE=https://analytics.adjust.com
# is the "No User Consent" replay-profile path)
if os.environ.get("FUNNEL_ATT_STATUS"):
    CAMPAIGN["att_status"] = os.environ["FUNNEL_ATT_STATUS"]
BASE = os.environ.get("FUNNEL_BASE", "https://consent.adjust.com")

# The user's link.  {REPLACE} slots:
#   {click_id}  a fresh per-run id (postback dedupe key)
#   {idfa}      the IDFA -- MUST equal the session's idfa (the join!)
#   {creativeid} creative label (kept verbatim if left as a macro)
LINK = ("https://app.adjust.com/1xgvk2dz?campaign=NIRIO_mobsuccess_iOS"
        "&adgroup=3710&creative={creativeid}_128&os_name=ios"
        "&click_id={click_id}&idfa={idfa}&gps_adid={idfa}"
        "&android_id={idfa}&ip_address={ip}&tracker_limit=250000&rt=0")

# The iPhone profile (capture-derived; env FUNNEL_DEVICE_JSON overrides).
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
CIT = int(os.environ.get("FUNNEL_CIT", "22"))   # click -> first request
ADJ_CLICK_SEC = None        # the adjust click's server Date second
DRY_RUN = "--dry-run" in sys.argv
SIGN_ALL = "--sign-all" in sys.argv
PROXY = os.environ.get("FUNNEL_PROXY", "")

BROWSER_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 "
              "Mobile/15E148 Safari/604.1")
APP_UA = "Nirio/494 CFNetwork/1410.1 Darwin/22.6.0"   # the capture's UA


def _jitter():
    import random
    return random.randint(11, 977)


def _ts_pair(sec):
    """(created_at, sent_at): sent_at lands 7-45 ms after created_at (the
    capture's pattern: 477->484, 530->542, 801->835)."""
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
    dt = datetime.fromtimestamp(ts + off, timezone.utc)
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get(url):
    """Fetch the click as iOS Safari would (curl_cffi chrome fingerprint;
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
        req = urllib.request.Request(url, headers={
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        opener = urllib.request.build_opener(NoRedirect)
        try:
            r = opener.open(req, timeout=30)
            code, hdrs, text = r.getcode(), r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            code, hdrs, text = e.code, e.headers, (e.read().decode("utf-8", "replace")
                                                   if e.fp else "")
        return code, {k.lower(): v for k, v in hdrs.items()}, text


def open_click_link(idfa):
    """Visit the tracker link (up to two passes, 12 hops) as iOS Safari and
    return (reftag_or_None, click_server_second).  On iOS the reftag is
    OPTIONAL (the capture's install joined by idfa match) -- a click that
    registers the idfa server-side is enough."""
    global ADJ_CLICK_SEC, CLICK_SKIPPED
    ADJ_CLICK_SEC = None
    CLICK_SKIPPED = False
    pre = os.environ.get("FUNNEL_REFTAG")
    if pre:
        cs = os.environ.get("FUNNEL_CLICK_SEC")
        ADJ_CLICK_SEC = int(cs) if cs else None
        return pre
    ip = os.environ.get("FUNNEL_IP", "103.25.128." + str(time.time() % 254 + 1))
    url = os.environ.get("FUNNEL_CLICK_URL") or _subst(LINK, idfa, ip)
    if url.strip().lower() in ("skip", "none", "off"):
        CLICK_SKIPPED = True
        return None                     # click-free probe run
    reftag = None
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
                            _eu.parsedate_to_datetime(_d).timestamp())
                    except Exception:
                        ADJ_CLICK_SEC = None
            loc = hdrs.get("location")
            if loc:
                m = re.search(r"adjust_reftag=([A-Za-z0-9]+)", loc)
                if m:
                    reftag = m.group(1)
                    log("click  reftag %s (hop %d)" % (reftag, hop))
                    return reftag
                u = loc
                continue
            m = re.search(r"adjust_reftag=([A-Za-z0-9]+)", text)
            if m:
                reftag = m.group(1)
                return reftag
            break
        if attempt == 1:
            time.sleep(2)
    return reftag


# ============================ the wire builders ==========================
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


def build_attribution_request(sec, init_by="backend"):
    """GET /attribution -- the capture's sid 39 (22 keys: the genuine row
    DOES carry installed_at, and carries NEITHER foreground NOR
    offline_mode_enabled -- both were verified against sid 39)."""
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
    body = urllib.parse.urlencode(fields).encode() if method == "POST" else None
    url = BASE + path
    if method == "GET":
        url = url + "?" + urllib.parse.urlencode(fields)
        body = None
    headers = {
        "Client-Sdk": CLIENT_SDK,
        "User-Agent": APP_UA,
        "Accept-Encoding": "gzip",
    }
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Authorization"] = auth
    import requests as _req
    r = _req.request(method, url, data=body, headers=headers, timeout=30,
                     proxies=_proxies())
    if r.headers.get("content-encoding") == "gzip":
        try:
            body_txt = gzip.decompress(r.content).decode("utf-8", "replace")
        except Exception:
            body_txt = r.text
    else:
        body_txt = r.text
    return r.status_code, body_txt


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
    log("ADJ7 iOS INSTALL FUNNEL  app=%s  idfa=%s" % (PACKAGE_NAME, _IDFA))
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
    with open(os.path.join(HERE, "last_run_ios.json"), "w") as _f:
        json.dump(last_run, _f, indent=1)

    if not DRY_RUN:
        wait = 0 if CLICK_SKIPPED else (click_second + CIT - time.time())
        if wait > 0:
            log("installing... (CTIT %.0fs)" % wait)
            time.sleep(wait)

    # 1. tps (the capture fires third_party_sharing before the session)
    sec = signing_second()
    tps_fields = build_tps_request(sec)
    tps_auth = _sign(tps_fields, "third_party_sharing", sec)
    print("signing  /third_party_sharing ...  %d fields, blob 304 B  "
          "[t=+%.0fs]" % (len(tps_fields), time.time() - started))
    if DRY_RUN and not SIGN_ALL:
        print("         signed -- not sending")
    else:
        st, body = _call("POST", "/third_party_sharing", tps_fields,
                         tps_auth)
        log("tps -> HTTP %d  %s" % (st, body[:100]))

    # 2. session
    sec2 = signing_second()
    s_fields = build_session_request(sec2)
    s_auth = _sign(s_fields, "session", sec2)
    print("signing  /session ...  %d fields, blob 304 B  [t=+%.0fs]"
          % (len(s_fields), time.time() - started))
    if DRY_RUN and not SIGN_ALL:
        print("         signed -- not sending")
        with open(os.path.join(HERE, "last_run_ios.json"), "w") as f:
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

    # 3. attribution (double-ask + poll, the proven ending)
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
    with open(os.path.join(HERE, "last_run_ios.json"), "w") as f:
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
    print("campaign  %s / %s (adj7 iOS, signing id %s, headers %s, native %s)"
          % (PACKAGE_NAME, APP_TOKEN, CAMPAIGN["adj_signing_id"],
             CAMPAIGN["headers_id"], CAMPAIGN["native_version"]))
    print("device    %s (%s %s, idfa fresh-per-run)" % (DEVICE["device_name"],
                                                        "iOS",
                                                        DEVICE["os_version"]))
    print("signer    adj7_ios_pure (raw-MINSTD header, ASCII-0 cert40)")
    raise SystemExit(main())
