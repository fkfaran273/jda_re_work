# -*- coding: utf-8 -*-
"""run_install.py — adj8-iOS install funnel, signed with the SOLVED adj8-iOS law
via adj8ios_pure.sign_request.

APP: com.Neon.MindAI (Adjust app_token qpe858kgxfr4), a web-bridge iOS app on
SDK 5.6.2 / native 3.67.0 — the capture whose blobs prove the signer.

  [optional click] -> signed /session -> signed /sdk_click -> signed /attribution

Everything is device-faithful to the genuine capture (same field set, same
client-sdk string, att_status honoured).  Fresh idfa / idfv / dedupe token per
run.  Python 3 (curl_cffi); Python 2.7: run_install_py27.py.

  python run_install.py --dry-run     # sign + print, send nothing
  python run_install.py
"""
import time, base64, sys, os, json, uuid, argparse, urllib.parse
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj8ios_pure as sg
try:
    from curl_cffi import requests as cr
except ImportError:                     # py2.7: the generated shim
    from _py27_transport import cr

# ============================ CAMPAIGN (backend shape) =====================
CAMPAIGN = {
    "app_name": "waveapp",
    "device_name": "iPhone10,1",         # iPhone 8, as in the genuine capture
    "os_name": "ios",
    "os_version": "16.7.15",
    "head_phase": [0x09],
    "adjust": {
        "app_token": "mrpexk5wqp6o",
        # the FULL client-sdk header value -- this is exactly what the claims carry
        "sdk": "react-native5.6.0@ios5.6.2",
        "adj_signing_id": "1400000",
        "headers_id": "9",
        "algorithm": "adj8",
        "native_version": "3.67.0",
    },
}
BUNDLE_ID = "com.ma.waveapp"
APP_VERSION = "400"
APP_VERSION_SHORT = "3.8.0"
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1")
OS_BUILD = "20H115"
TZ = "-0700"
# the team's tracker.  It 302s to the Adjust tracker app.adjust.com/1x6tr630
# (campaign GWM_43241_161 / adgroup 43241_stm_); an app.adjust.com link may be
# passed here directly instead.  Env override for other campaigns.
CLICK_LINK = os.environ.get(
    "CLICK_LINK",
    "http://clicks.appsatiate.com/api/track/v1/click?aff_id=2&offer_id=312066")
CLICK_WAIT = int(os.environ.get("CLICK_WAIT", "45"))     # click -> install gap, s
DO_CLICK = os.environ.get("DO_CLICK", "1") == "1"
CLICK_TRIES = int(os.environ.get("CLICK_TRIES", "6"))    # tracker cooldown retries
CLICK_RETRY_WAIT = int(os.environ.get("CLICK_RETRY_WAIT", "20"))
ASA_TOKEN = os.environ.get("ASA_TOKEN", "")               # AdServices token -> source=apple_ads
# ========================================================================


def now_ts():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def fmt(dt=None):
    dt = dt or now_ts()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ%s" % (dt.microsecond // 1000, TZ)


def hexid(n):
    return base64.b16encode(os.urandom(n)).decode("ascii")


def host_for(att_status):
    return ("https://consent.adjust.com" if att_status == "3"
            else "https://analytics.adjust.com")


def signed(path, params, kind, att_status, dry=False):
    """Mint the Authorization header and (unless dry) fire the request."""
    t = int(time.time()) + 1
    while time.time() < t:                     # sign inside the target second
        time.sleep(0.02)
    p = dict(params)
    p["created_at"] = p["sent_at"] = fmt(now_ts())
    auth = sg.sign_request(p, kind, c=CAMPAIGN, second=t)
    if dry:
        import re
        blob = re.search(r'signature="([^"]+)"', auth).group(1)
        print("    [dry] %-12s %2d params | blob %d B | %s"
              % (kind, len(p), len(base64.b64decode(blob)), auth[:96] + " ..."),
              flush=True)
        return None
    h = {"User-Agent": UA, "Client-Sdk": CAMPAIGN["adjust"]["sdk"],
         "Authorization": auth}
    host = host_for(att_status)
    if path == "/attribution":
        return cr.get(host + path + "?" + urlencode(p), headers=h, timeout=30)
    # curl_cffi infers this from a dict, but stdlib httplib (py2.7) does not --
    # without it Adjust parses an empty body and answers {}
    h["Content-Type"] = "application/x-www-form-urlencoded"
    return cr.post(host + path, data=p, headers=h, timeout=30)


def resolve_click(track_link, idfa, tries=CLICK_TRIES, wait=CLICK_RETRY_WAIT):
    """Resolve the link to the Adjust click URL, with our idfa + ip in it.

    Accepts either the team's tracker URL (which 302s to app.adjust.com) or an
    app.adjust.com tracker link directly.

    The tracker rate-limits per IP/offer and answers a burst with
    400 {"error":"not able to server ad"} for a cooldown window -- which is
    harmless but fatal to attribution, since without a click the install can
    only come back Organic.  So retry with a backoff instead of giving up.
    """
    ip = (cr.get("https://api.ipify.org", timeout=15).text or "").strip()
    if "/app.adjust.com" in track_link:                 # already an Adjust link
        loc = track_link
    else:
        # sub3 carries our idfa INTO the tracker, which forwards it to Adjust as
        # `idfa=` -- a device-matched click (verified: sub3=X -> idfa=X).
        tl = track_link
        if "sub3=" not in tl:
            tl += ("&" if "?" in tl else "?") + "sub3=" + urllib.parse.quote(idfa)
        print("[click] GET %s" % tl, flush=True)
        loc = ""
        for attempt in range(1, tries + 1):
            r = cr.get(tl, headers={"User-Agent": UA}, timeout=30,
                       allow_redirects=False)
            loc = r.headers.get("location") or r.headers.get("Location") or ""
            if "/app.adjust.com" in loc:
                break
            print("[click] attempt %d/%d -> %s %s" %
                  (attempt, tries, r.status_code, r.text[:60]), flush=True)
            if attempt < tries:
                print("[click] tracker in cooldown, sleeping %ds" % wait, flush=True)
                time.sleep(wait)
        if "/app.adjust.com" not in loc:
            print("[click] NO CLICK REGISTERED -- this install will come back "
                  "ORGANIC (unattributable without a click)", flush=True)
            return None, None
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query,
                                    keep_blank_values=True))
    if not q.get("idfa"):            # sub3 normally fills it; belt and braces
        q["idfa"] = idfa
    q["ip_address"] = ip
    link = "https://app.adjust.com%s?%s" % (
        urllib.parse.urlparse(loc).path, urllib.parse.urlencode(q))
    print("[click] Adjust %s | campaign=%s adgroup=%s click_id=%s"
          % (urllib.parse.urlparse(loc).path, q.get("campaign"),
             q.get("adgroup"), q.get("click_id")), flush=True)
    print("[click] device-matched idfa=%s ip=%s" % (q.get("idfa"), ip), flush=True)
    return link, q


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="sign every request, send nothing")
    ap.add_argument("--att", default=os.environ.get("ATT_STATUS", "3"),
                    help="att_status (3 = ATT authorized -> consent.adjust.com)")
    ap.add_argument("--sdk-click", action="store_true",
                    help="also fire an /sdk_click (needs a real AdServices token "
                         "to be meaningful)")
    args = ap.parse_args()
    att = args.att
    dry = args.dry_run

    idfa = str(uuid.uuid4()).upper()          # device_id; doubles as click_id
    idfv = str(uuid.uuid4()).upper()
    dedupe = str(uuid.uuid4())
    user_uuid = str(uuid.uuid4())
    installed = fmt(now_ts() - timedelta(seconds=180))
    started = fmt(now_ts() - timedelta(hours=7))
    print("idfa:", idfa, "  idfv:", idfv, "  att_status:", att, flush=True)

    click_q = None
    if CLICK_LINK and DO_CLICK and not dry:
        link, click_q = resolve_click(CLICK_LINK, idfa)
        if link:
            r = cr.get(link, headers={"User-Agent": UA}, timeout=30,
                       allow_redirects=False)
            print("[click] Adjust click:", r.status_code, flush=True)
            time.sleep(CLICK_WAIT)
        else:
            print("[click] WARNING: continuing without a click -- the verdict "
                  "below will be Organic by definition.", flush=True)

    base = {
        "bundle_id": BUNDLE_ID,
        "app_token": CAMPAIGN["adjust"]["app_token"],
        "app_version": APP_VERSION,
        "app_version_short": APP_VERSION_SHORT,
        "device_name": CAMPAIGN["device_name"],
        "device_type": "iPhone",
        "os_name": "ios",
        "os_version": CAMPAIGN["os_version"],
        "os_build": OS_BUILD,
        "environment": "production",
        "idfv": idfv,
        "att_status": att,
        "primary_dedupe_token": dedupe,
        "needs_response_details": "1",
        "attribution_deeplink": "1",
        "ff_remote_triggers_callback": "1",
        "installed_at": installed,
        "started_at": started,
        "callback_params": json.dumps({"user_uuid": user_uuid}, separators=(",", ":")),
        "send_in_background_enabled": "0",
    }
    if att == "3":
        base["idfa"] = idfa

    adid = None
    print("\n[1] /session (install) ...", flush=True)
    sp = dict(base, session_count="1", foreground="1", enqueue_size="0",
              offline_mode_enabled="0", retry_count="0")
    r = signed("/session", sp, "session", att, dry)
    adid = None
    if r is not None:
        print("[session]", r.status_code, "|", r.text[:220], flush=True)
        if r.text.startswith("{"):
            adid = r.json().get("adid")
            print("    adid:", adid, flush=True)
        time.sleep(8)

    if args.sdk_click:
        print("\n[2] /sdk_click ...", flush=True)
        cp = dict(base, session_count="1", session_length="0",
                  subsession_count="1", time_spent="0", source="apple_ads")
        if ASA_TOKEN:
            cp["attribution_token"] = ASA_TOKEN
        if click_q:
            cp["campaign"] = click_q.get("campaign", "")
            cp["adgroup"] = click_q.get("adgroup", "")
            cp["click_time"] = fmt(now_ts() - timedelta(seconds=CLICK_WAIT))
        r = signed("/sdk_click", cp, "click", att, dry)
        if r is not None:
            print("[sdk_click]", r.status_code, "|", r.text[:200], flush=True)
            time.sleep(5)

    print("\n[3] /attribution ...", flush=True)
    ap_ = dict(base, initiated_by="backend")
    r = signed("/attribution", ap_, "attribution", att, dry)
    verdict = None
    if r is not None:
        print("[attribution] status:", r.status_code, flush=True)
        raw = r.text
        try:
            body = json.loads(raw)
            print("\n---- attribution response (full JSON) ----", flush=True)
            print(json.dumps(body, indent=1, sort_keys=True), flush=True)
            print("---- end attribution response ----\n", flush=True)
        except Exception as e:
            print("    (not JSON: %s) raw: %s" % (e, raw[:2000]), flush=True)
            body = {}
        a = body.get("attribution", {}) or {}
        tk, name = a.get("tracker_token", ""), a.get("tracker_name", "")
        print("    tracker :", tk, flush=True)
        print("    name    :", name, flush=True)
        print("    network :", a.get("network"), flush=True)
        print("    engaged :", a.get("engagement_time"), flush=True)
        print("    reattr  :", a.get("is_reattributed"), flush=True)
        if "No User Consent" in name:
            verdict = "NON-ORGANIC (no user consent)"
        elif not tk:
            verdict = "NO ATTRIBUTION OBJECT (%s)" % (raw[:80] or "empty")
        elif name == "Organic":
            verdict = "ORGANIC"
        else:
            verdict = "BOOKED " + str(tk)
        print("\nVERDICT:", verdict, flush=True)

    json.dump({"idfa": idfa, "idfv": idfv, "adid": adid,
               "att_status": att, "verdict": verdict,
               "attribution_response": (body if r is not None else None),
               "dry_run": bool(dry)},
              open(os.path.join(HERE, "run_install_result.json"), "w"), indent=1)
    print("\nwrote run_install_result.json", flush=True)


if __name__ == "__main__":
    main()
