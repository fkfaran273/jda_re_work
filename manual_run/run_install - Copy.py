"""run_install.py — register a click, report an install, read the attribution.

    python -u run_install.py                     # live run (creditsea)
    python -u run_install.py penti               # pick the app
    python -u run_install.py penti --dry-run     # sign and show, send nothing
    python -u run_install.py penti --event       # also send one in-app event
    python -u run_install.py penti --event abc12 # ...a revenue event with that
                                                #    event token
    python -u run_install.py penti --gap 10   # pause 10 s before
                                                #    each request

Four steps: open the tracker link for a reftag, report the install, optionally
send an in-app event, then poll until the attribution is not Organic.

Event tokens live in the Adjust dashboard per app, so you supply the token;
there is nothing to guess.  Events are never needed to earn attribution.
"""
import datetime
import gzip
import http.client
import json
import os
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_pure as S
# --py27  use the Python 2.7 build of the same signer (identical bytes)
if "--py27" in sys.argv:
    import adj9_pure_py27 as S

DRY_RUN = "--dry-run" in sys.argv

# --event          send one plain in-app event after the click
# --event TOKEN    send one revenue event carrying that event token
#
# Event tokens are configured per app in the Adjust dashboard, so there is no
# token to guess here -- you supply the one for the app you are signing for.
# An event is never needed to earn attribution, so both forms are opt-in.
SEND_EVENT = "--event" in sys.argv
# --gap N  pause N seconds before each request, so a slow tracker can
#          register a click before we install against it
GAP = 10
for _i, _a in enumerate(sys.argv):
    if _a == "--gap" and _i + 1 < len(sys.argv):
        GAP = int(sys.argv[_i + 1])
EVENT_TOKEN = None
_args2 = [a for a in sys.argv[1:] if not a.startswith("-")]
if "--event" in sys.argv and _args2:
    EVENT_TOKEN = _args2[-1]

# The click is fetched as a browser would.  A bare "Mozilla/5.0 (Linux;
# Android 12)" makes the tracker answer 200 with no redirect, and then no
# reftag is ever issued.
BROWSER_UA = ("Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")

# ==========================================================================
# The app we are signing for.  This dict is the default; passing an app name
# on the command line overrides it with that entry from apps.json.
#
#     python -u run_install.py                # creditsea (below)
#     python -u run_install.py penti
#     python -u run_install.py declic
#     python -u run_install.py penti --dry-run
#
# apps.json holds the same settings for all three.
# ==========================================================================
campaign_data = {
    "app_name": "penti",
    "package_name": " ",
    "app_token": "jut9tib0eeps",
    "cert_sha1": "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd",
    "sdk_version": "5.8.0",
    "_note_sdk": "The 5.8 claims law, not 5.7: the genuine penti captures rebuild 192/192 under it, and their session body carries no session_length/subsession_count/time_spent -- which the 5.7 law requires. Verified against all 6 win_capture signings.",
    "client_sdk": "android5.7.0",
    "native_version": "5.0.0",
    "adj_signing_id": "1500000",
    "headers_id": "10",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "click_link": "https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id={gaid}&gps_adid={gaid}",
    "gap_seconds": 180,
    "poll_delays": [
      3,
      8,
      20
    ],
    "app_version": "3.13.9",
    "_note": "app_token is 12 chars: jut9tib0eeps. An earlier truncated copy (jut9tib0eeps -> jut9tib0eo) made /session return 500 \"failed to get app token\". Verified against the genuine capture."
  }

# the first bare argument (not starting with '-') names the app
_args = [a for a in sys.argv[1:] if not a.startswith("-")]
if _args:
    _all = json.load(open(os.path.join(HERE, "apps.json")))
    if _args[0] not in _all:
        raise SystemExit("unknown app %r - have: %s"
                         % (_args[0], ", ".join(k for k in _all
                                                if not k.startswith("_"))))
    campaign_data = dict(_all[_args[0]])


# ==========================================================================
# THE API LAYER -- what each endpoint actually puts on the wire
# ==========================================================================
# These are data modelling, not cryptography: which fields each request
# carries, and the timestamps they imply.  adj9_pure signs whatever map
# we hand it; it does not know what a /session looks like.

def _tz_parts(device):
    """'+05:30' -> minutes east of UTC, plus the original label."""
    tz = device.get("timezone", "+0530")
    sign = -1 if tz[0] == "-" else 1
    return sign * (int(tz[1:3]) * 60 + int(tz[3:5])), tz

def _stamp(ts, ms, tz_min=330, tz_label="+0530"):
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=tz_min))
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z" + tz_label)

def _device_fields(device):
    """Device settings, minus the two that are never sent on the wire."""
    fields = {k: v for k, v in device.items()
              if not str(k).startswith("_")}
    fields.pop("raw", None)          # a pasted device dump, not a param
    fields.pop("timezone", None)     # local metadata, never transmitted
    return fields

def _common_fields(gaid, android_uuid, device, campaign):
    """The identity block every request carries."""
    return {
        "app_token": campaign["app_token"],
        "app_version": (device.get("app_version")
                        or campaign.get("app_version", "3.13.9")),
        "package_name": campaign["package_name"],
        "gps_adid": gaid, "android_uuid": android_uuid,
        "environment": "production", "device_type": "phone",
        "gps_adid_src": "service", "gps_adid_attempt": "1",
        "foreground": "1", "needs_response_details": "1",
        "attribution_deeplink": "1", "offline_mode_enabled": "0",
        "ui_mode": "1", "tracking_enabled": "1", "os_name": "android",
    }

def build_session_request(gaid, android_uuid, device, campaign, t_click):
    """The fields for POST /session - the app announcing itself.  This is the
    request that creates the adid, so it carries installed_at."""
    fields = _device_fields(device)
    fields.update(_common_fields(gaid, android_uuid, device, campaign))
    tz_minutes, tz = _tz_parts(device)
    installed = _stamp(t_click + 7, 774, tz_minutes, tz)
    fields.update({
        # both true when the app was installed from the Play Store
        "store_name_from_system": "com.android.vending",
        "initiating_package_name": "com.android.vending",
        "session_count": "1",
        "created_at": _stamp(t_click + 55, 928, tz_minutes, tz),
        "sent_at": _stamp(t_click + 55, 942, tz_minutes, tz),
        "installed_at": installed, "updated_at": installed,
    })
    fields.pop("mcc", None)          # genuine bodies carry neither, even on SIM
    fields.pop("mnc", None)
    return fields

def build_click_request(gaid, android_uuid, device, campaign, t_click,
                        referrer):
    """The fields for POST /sdk_click - the install claiming a click.

    Carries the click's own timing: click_time and install_begin_time, each
    with a *_server twin exactly 1 s behind, and install_begin 20 s before
    installed_at.
    """
    fields = _device_fields(device)
    fields.update(_common_fields(gaid, android_uuid, device, campaign))
    tz_minutes, tz = _tz_parts(device)
    installed = _stamp(t_click + 25, 774, tz_minutes, tz)
    # these six are session-only; a genuine click body has none of them
    for key in ("enqueue_size", "first_error", "last_error", "retry_count",
                "wait_time", "wait_total"):
        fields.pop(key, None)
    fields.pop("mcc", None)
    fields.pop("mnc", None)
    fields.update({
        "source": "install_referrer", "referrer_api": "google",
        "referrer": referrer, "google_play_instant": "0",
        "install_version": (device.get("app_version")
                           or campaign.get("app_version", "3.13.9")),
        "session_count": "1", "session_length": "0",
        "subsession_count": "1", "time_spent": "0",
        "created_at": _stamp(t_click + 25, 961, tz_minutes, tz),
        "sent_at": _stamp(t_click + 25, 970, tz_minutes, tz),
        "installed_at": installed, "updated_at": installed,
        "click_time": _stamp(t_click, 0, tz_minutes, tz),
        "click_time_server": _stamp(t_click - 1, 0, tz_minutes, tz),
        "install_begin_time": _stamp(t_click + 5, 0, tz_minutes, tz),
        "install_begin_time_server": _stamp(t_click + 4, 0, tz_minutes, tz),
    })
    return fields

def build_attribution_request(gaid, android_uuid, device, campaign, t_click):
    """The fields for GET /attribution - asking what we were attributed to.
    Sends no mcc/mnc, no resolution, no build."""
    tz_minutes, tz = _tz_parts(device)
    return {
        "initiated_by": "backend", "gps_adid_attempt": "1",
        "api_level": device.get("api_level", "31"),
        "app_version": (device.get("app_version")
                         or campaign.get("app_version", "3.13.9")),
        "app_token": campaign["app_token"],
        "os_version": device.get("os_version", "12"),
        "created_at": _stamp(t_click + 25, 666, tz_minutes, tz),
        "device_type": "phone", "gps_adid": gaid, "foreground": "1",
        "android_uuid": android_uuid,
        "sent_at": _stamp(t_click + 25, 696, tz_minutes, tz),
        "offline_mode_enabled": "0",
        "device_name": device.get("device_name", ""),
        "environment": "production", "needs_response_details": "1",
        "attribution_deeplink": "1",
        "package_name": campaign["package_name"],
        "os_name": "android", "ui_mode": "1",
        "gps_adid_src": "service", "tracking_enabled": "1",
    }

def build_event_request(gaid, android_uuid, device, campaign, t_click,
                        event_token=None, partner_params=None, seq=1,
                        event_count=1, push_token=None):
    """The fields for POST /event - an in-app event (e.g. a purchase).

    Modelled on the genuine penti event body in adj9/cap/oracle_run3.log, whose
    signing this module reproduces 192/192.  That body carries NO installed_at,
    updated_at, store_name_from_system or initiating_package_name -- an event
    body is a session body minus the install fields, plus the event fields.

    event_token and partner_params are the revenue-event arguments.  A plain
    event passes neither and the claims law simply omits them (the law is
    presence-filtered).
    """
    fields = _device_fields(device)
    fields.update(_common_fields(gaid, android_uuid, device, campaign))
    tz_minutes, tz = _tz_parts(device)
    # the install-only fields a genuine event body does not carry
    for key in ("installed_at", "updated_at", "store_name_from_system",
                "initiating_package_name"):
        fields.pop(key, None)
    fields.pop("mcc", None)
    fields.pop("mnc", None)
    fields.update({
        "event_count": str(event_count),
        "seq": str(seq),
        "session_count": "1", "session_length": "0",
        "subsession_count": "1", "time_spent": "0",
        "created_at": _stamp(t_click + 25, 873, tz_minutes, tz),
        "sent_at": _stamp(t_click + 25, 940, tz_minutes, tz),
    })
    if event_token:
        fields["event_token"] = event_token
    if partner_params:
        fields["partner_params"] = partner_params
    if push_token:
        fields["push_token"] = push_token
    return fields


DEVICE = json.load(open(os.path.join(HERE, "device_data.json")))
APP_UA = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
          % (DEVICE["os_version"], DEVICE["device_name"], DEVICE["os_build"]))


def call(method, path, fields, auth):
    """One call to app.adjust.com.  Client-SDK is required on every request:
    without it the server answers 400 "unsupported sdk"."""
    body = urllib.parse.urlencode(fields).encode() if method == "POST" else None
    target = path if method == "POST" else path + "?" + urllib.parse.urlencode(
        fields, quote_via=urllib.parse.quote)
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest(method, target, skip_host=1, skip_accept_encoding=1)
        c.putheader("Client-SDK", campaign_data["client_sdk"])
        c.putheader("Authorization", auth)
        c.putheader("User-Agent", APP_UA)
        c.putheader("Host", "app.adjust.com")
        if body is not None:
            # Content-Length is REQUIRED on a POST: without it the server
            # never reads the body and /session answers 200 {} with no adid
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("Content-Length", str(len(body)))
        c.putheader("Accept-Encoding", "gzip")
        c.endheaders(body)
        r = c.getresponse()
        raw = r.read()
        if raw[:2] == bytes((0x1f, 0x8b)):
            raw = gzip.decompress(raw)
        return r.status, raw.decode("utf-8", "replace")
    finally:
        c.close()


def open_click_link(gaid, dp2=None):
    """Follow the tracker link and return the adjust_reftag it hands back.

    The link may carry two macros: {gaid} is the advertising id the install
    reports, {dp2} is a second id the advertiser uses for its own callback
    (click_id, sub1_af, goal1).  Both are substituted.
    """
    url = campaign_data["click_link"].replace("{gaid}", gaid).replace(
        "{dp2}", dp2 or gaid)
    for _ in range(8):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme in ("market", "intent"):
            break
        c = (http.client.HTTPConnection(parts.hostname, 80, timeout=25)
             if parts.scheme == "http" else
             http.client.HTTPSConnection(parts.hostname, 443, timeout=25))
        try:
            c.request("GET", urllib.parse.urlunsplit(
                ("", "", parts.path or "/", parts.query, "")),
                headers={"User-Agent": BROWSER_UA,
                         "Accept-Encoding": "identity",
                         "Connection": "close"})
            r = c.getresponse()
            r.read()
            location = r.getheader("Location") or ""
        finally:
            c.close()
        if "referrer=" in location:
            reftag = urllib.parse.unquote(location.split("referrer=", 1)[1])
            return reftag.split(";S.browser_fallback_url")[0]  # not part of it
        if not location:
            break
        url = urllib.parse.urljoin(url, location)
    return None


def main():
    gaid = str(uuid.uuid4())
    android_uuid = str(uuid.uuid4())
    started = time.time()

    install_clock = int(time.time())

    # 2. the install.  Signing is now ~25 ms and closed-form: no VM. The
    #    network round trip dominates.

    # 1. the click.  A dry run skips it: fetching the link IS what registers
    #    the click, so opening it would spend a click for nothing.
    referrer = None
    if not DRY_RUN:
        referrer = open_click_link(gaid)
        if not referrer:
            print("no reftag in the redirect chain — aborting")
            return 1
        print("click    reftag %s" % referrer[:50])
        # time.sleep(campaign_data["gap_seconds"])   # install timing
    install_clock = int(time.time())


    if GAP:
        time.sleep(GAP)
    print("signing  /session ...")
    fields = build_session_request(gaid, android_uuid, DEVICE, campaign_data,
                         install_clock)
    auth, _blob = S.sign_request(fields, "session", campaign_data,
                                   second=install_clock)
    adid = ""
    if DRY_RUN:
        print("         %d fields, signed %d B — not sending"
              % (len(fields), len(_blob)))
    else:
        status, body = call("POST", "/session", fields, auth)
        adid = json.loads(body).get("adid", "")
        print("         -> %d adid %s  [t=+%.0fs]"
              % (status, adid, time.time() - started))

    if not referrer:
        print("         /sdk_click needs a reftag, so it was not signed")
    else:
        if GAP:
            time.sleep(GAP)
        print("signing  /sdk_click ...")
        fields = build_click_request(gaid, android_uuid, DEVICE, campaign_data,
                                       install_clock, referrer)
        auth, _blob = S.sign_request(fields, "click", campaign_data,
                                   second=install_clock + 1)
        print("         %d fields, signed %d B"
              % (len(fields), len(_blob)))
        if not DRY_RUN:
            status, _ = call("POST", "/sdk_click", fields, auth)
            print("         -> %d  [t=+%.0fs]" % (status, time.time() - started))

    # 3. an in-app event.  Optional: --event sends one, otherwise it is skipped
    # so a plain attribution run stays exactly as it was.
    if not DRY_RUN and SEND_EVENT:
        if GAP:
            time.sleep(GAP)
        print("signing  /event ...")
        fields = build_event_request(gaid, android_uuid, DEVICE, campaign_data,
                                       int(time.time()),
                                       event_token=EVENT_TOKEN)
        auth, _blob = S.sign_request(fields, "event", campaign_data,
                                   second=int(time.time()))
        print("         %d fields, signed %d B"
              % (len(fields), len(_blob)))
        status, body = call("POST", "/event", fields,
                            auth)
        print("         -> %d %s  [t=+%.0fs]"
              % (status, body[:60], time.time() - started))
    # 4. the attribution
    if DRY_RUN:
        print("attribution  DRY RUN — not polling")
        print("\nconfig is valid: the session signed cleanly.")
        return 0

    verdict = {}
    for delay in campaign_data["poll_delays"]:
        time.sleep(delay)
        fields = build_attribution_request(gaid, android_uuid, DEVICE,
                                            campaign_data, install_clock)
        auth, _blob = S.sign_request(fields, "attribution", campaign_data,
                                   second=int(time.time()))
        _status, body = call("GET", "/attribution", fields,
                             auth)
        print(body)
        print(body)
        verdict = json.loads(body).get("attribution") or {}
        print("poll +%-2ds   %s / %s  [t=+%.0fs]"
              % (delay, verdict.get("network"), verdict.get("tracker_token"),
                 time.time() - started))
        if verdict.get("network") and verdict["network"] != "Organic":
            break

    print()
    if verdict.get("network", "Organic") != "Organic":
        print("*** NON-ORGANIC ***   %.0fs total"
              % (time.time() - started))
        for field in ("network", "tracker_token", "tracker_name", "campaign",
                      "adgroup", "engagement_time"):
            print("  %-16s %s" % (field, verdict.get(field)))
        print("  %-16s %s" % ("adid", adid))
    else:
        print("*** Organic / not joined ***   %.0fs total"
              % (time.time() - started))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
