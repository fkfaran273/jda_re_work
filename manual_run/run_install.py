# -*- coding: utf-8 -*-

"""run_install.py -- register a click, report an install, read the attribution.

    python -u run_install.py penti               # pick the app
    python -u run_install.py --dry-run           # sign and show, send nothing
    python -u run_install.py --event             # also send one in-app event
    python -u run_install.py --event abc12       # ...a revenue event with that
                                                 #    event token
    python -u run_install.py --gap 10            # pause 10 s before each
                                                 #    request
    python -u run_install.py --campaign FILE     # campaign dict, either layout
    python -u run_install.py --device FILE       # device dump, either layout

Every API method is self-contained -- it builds its fixed body dict, signs it
(headers["Authorization"] = S.sign_request(fields, "...", campaign_data,
second=sec)) and sends it with requests:

    session(campaign_data, device_data)      -> POST /session
    sdk_click(campaign_data, device_data)    -> POST /sdk_click
    attribution(campaign_data, device_data)  -> GET  /attribution
    event(...)  /  info(...)                 -> optional

main() only loads the configs, mints the per-install identity into RUN, opens
the click, and calls the methods in order.

Event tokens live in the Adjust dashboard per app, so you supply the token;
there is nothing to guess.  Events are never needed to earn attribution.
"""
import datetime
import http.client
import json
import os
import random
import re
import sys
import time
import urllib.parse
import uuid

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_pure as S
# --py27  use the Python 2.7 build of the same signer (identical bytes)
if "--py27" in sys.argv:
    import adj9_pure_py27 as S

DRY_RUN = "--dry-run" in sys.argv
# --proxy URL  route every call (click + API) through it, e.g. a residential
# session.  A burned or datacenter IP gets its clicks dropped silently --
# the redirect still works but no click is recorded (engagement_time 0001).
PROXY = None
for _i, _a in enumerate(sys.argv):
    if _a == "--proxy" and _i + 1 < len(sys.argv):
        PROXY = sys.argv[_i + 1]
PROXIES = {"http": PROXY, "https": PROXY} if PROXY else None

# --event          send one plain in-app event after the click
# --event TOKEN    send one revenue event carrying that event token
#
# Event tokens are configured per app in the Adjust dashboard, so there is no
# token to guess here -- you supply the one for the app you are signing for.
# An event is never needed to earn attribution, so both forms are opt-in.
SEND_EVENT = "--event" in sys.argv
SEND_INFO = "--info" in sys.argv
# --gap N  pause N seconds before each request, so a slow tracker can
#          register a click before we install against it
GAP = 30
for _i, _a in enumerate(sys.argv):
    if _a == "--gap" and _i + 1 < len(sys.argv):
        GAP = int(sys.argv[_i + 1])
EVENT_TOKEN = None
# bare arguments = the app name (and the event token); the values of flags
# that take one must not be mistaken for either
_VALUE_FLAGS = ("--campaign", "--device", "--gap", "--event")
_args, _skip = [], False
for _a in sys.argv[1:]:
    if _skip:
        _skip = False
        continue
    if _a.startswith("-"):
        _skip = _a in _VALUE_FLAGS
        continue
    _args.append(_a)
if "--event" in sys.argv and _args:
    EVENT_TOKEN = _args[-1]

# The click is fetched as a browser would.  A bare "Mozilla/5.0 (Linux;
# Android 12)" makes the tracker answer 200 with no redirect, and then no
# reftag is ever issued.
BROWSER_UA = ("Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
# A real Chrome click sends a full fingerprint; affiliate trackers qualify
# clicks by it.  A 3-header python click can be silently disqualified.
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


# ==========================================================================
# INPUT FORMATS -- ours or theirs
# ==========================================================================
# The campaign dict is the AutoLabs nested format and is used as-is.  The
# device side still needs a mapping, because a raw handset dump's keys
# (display_metrics, locale, build, model, ...) are not the wire keys:
# load_device() reduces it to the fields the api methods send.

def _cli_value(flag):
    """The value following `flag` on the command line, or None."""
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


_SCREEN_DENSITY = {"ldpi": "low", "mdpi": "medium", "hdpi": "high"}


def load_device(raw):
    """device dict, either layout -> canonical (wire-named keys only)."""
    if "display_metrics" not in raw and "build_prop" not in raw:
        return raw                       # already ours
    dm = raw.get("display_metrics") or {}
    loc = raw.get("locale") or {}
    dpi = str(dm.get("density_dpi", ""))
    return {
        "api_level": str(raw.get("sdk", raw.get("api_level", ""))),
        "os_version": str(raw.get("os_version", "")),
        "device_name": raw.get("model", raw.get("device_name", "")),
        "device_manufacturer": raw.get("manufacturer", ""),
        "hardware_name": raw.get("display", raw.get("os_build", "")),
        "os_build": raw.get("build", raw.get("os_build", "")),
        "language": loc.get("language", ""),
        "country": loc.get("country", ""),
        # their axis naming is swapped vs the wire: their ypx (1080) is the
        # width their own session body carries, xpx (2340) the height
        "display_width": str(dm.get("ypx", "")),
        "display_height": str(dm.get("xpx", "")),
        "screen_density": _SCREEN_DENSITY.get(dpi, "high"),
        "screen_size": dm.get("screen_layout_name", "large"),
        "screen_format": dm.get("screen_layout_format", "long"),
        "cpu_type": raw.get("cpu_abi", ""),
        "connectivity_type": "1" if raw.get("network") == "WiFi" else "0",
        "timezone": raw.get("timezone", "+0000"),
        "mcc": str(raw.get("mcc", "")),
        "mnc": str(raw.get("mnc", "")),
        "enqueue_size": "0", "first_error": "0", "last_error": "0",
        "retry_count": "0", "wait_time": "0.0", "wait_total": "0.0",
    }


# ==========================================================================
# The campaigns -- the AutoLabs nested format, used DIRECTLY under their own
# key names (campaign_data["adjust"]["app_token"], ["app_version_name"], ...).
# The first bare argument picks one:  run_install.py declic
# ==========================================================================
CAMPAIGNS = {}
CAMPAIGNS["penti"] = {
    "app_name": "Penti",
    "package_name": "com.penti.app",
    "app_size": 23,
    "app_version_name": "3.13.9",
    "app_version_code": "31309",
    "tracker": "adjust",
    "adjust": {
        "app_token": "jut9tib0eeps",
        "sdk": "android5.7.0",
        "adj_port": "60515",
        "server": "adj_t3",
    },
    "supported_os": "8.0",
    "retention": {1: 25, 2: 25, 3: 24, 4: 24, 5: 23, 6: 22, 7: 20},
    "cert_sha1": "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    # the head phase is PER BUILD: penti's libsigner uses 0x2B, the 5.8-SDK
    # builds (creditsea, declic) use 0x40 -- recovered from genuine captures
    "head_phase": (0x2B,),
    # their original_link template; {click_id}/{sub3} resolve to the install's
    # advertising id, and gps_adid= is appended because their template only
    # carries the id as idfa= (the Organic in the AutoLabs log)
    "click_link": "https://app.adjust.com/1sd1lk6a?campaign=AH"
                  "&adgroup=vkm_0926_36&creative=penti_generic"
                  "&click_id={click_id}&idfa={sub3}",
    "poll_delays": [3, 8, 20],
}
CAMPAIGNS["declic"] = {
    "app_name": "Declic",
    "package_name": "com.declic.mobile.app",
    "app_version_name": "1.0.77",
    "tracker": "adjust",
    "adjust": {
        "app_token": "1afnt5j9dsg0",
        "sdk": "android5.8.0",
    },
    "cert_sha1": "dd60fcbb9a438b4c8eb82d274aa8818595bc8445",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "head_phase": (0x40,),
    # the live tracker whose 3 Oct install JOINED (see the saz capture); its
    # template already carries gps_adid={gaid}, so nothing needs appending
    "click_link": ("https://app.adjust.com/23hfwhce?campaign=ADB_SEP"
                   "&adgroup=ADB_SEP_RNA_ADZ88_fft5t54t&click_id={dp2}"
                   "&gps_adid={gaid}"
                   "&install_callback=http%3A%2F%2Fwebdata.offersinfinite.com"
                   "%2Fpostback.php%3Faf_id%3Dadjust%26af_id2%3Dadzjunction"
                   "%26ofr_id%3DOIdecADZ%26sub1_af%3D{dp2}%26sub2_af%3D225_"
                   "jk87787%26idfa_id%3D{gaid}"),
    "poll_delays": [3, 8, 20],
}
CAMPAIGNS["creditsea"] = {
    "app_name": "Creditsea",
    "package_name": "com.creditsea.app",
    "app_version_name": "1.0.174",
    "tracker": "adjust",
    "adjust": {
        "app_token": "i2n2e5kmcpvk",
        "sdk": "flutter5.8.0@android5.8.0",                     # Flutter composite value
    },
    "cert_sha1": "06f5ffcee0541608765407ab9e0180e7b1b7e7d0",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "head_phase": (0x40,),
    # affiliate click URL (mobpine); it redirects into Adjust, and
    # open_click_link appends gps_adid= because the template lacks it
    "click_link": "http://clicks.mobpine.com/api/track/v1/click?aff_id=3&offer_id=23482250",
    "poll_delays": [3, 8, 20],
}
campaign_data = CAMPAIGNS["penti"]
if _args and _args[0] in CAMPAIGNS:
    campaign_data = CAMPAIGNS[_args[0]]

# --campaign FILE swaps the whole campaign dict (same nested layout)
_cl_campaign = _cli_value("--campaign")
if _cl_campaign:
    campaign_data = json.load(open(_cl_campaign))

# --device FILE overrides device_data.json, also in either layout
_cl_device = _cli_value("--device")
DEVICE = load_device(json.load(open(_cl_device if _cl_device else
                                    os.path.join(HERE, "device_data.json"))))

# The per-install identity: main() mints it once and every api method reads
# it, so session(campaign_data, device_data) needs no other arguments.
RUN = {"gaid": "", "android_uuid": "", "click_sec": 0, "referrer": "",
       "t0": 0.0}


# ==========================================================================
# THE API LAYER -- what each endpoint actually puts on the wire
# ==========================================================================
# These are data modelling, not cryptography: which fields each request
# carries, and the timestamps they imply.  Each method is isolated: fixed
# body dict, signature, send, response.

def _tz_parts(device):
    """'+05:30' -> minutes east of UTC, plus the original label."""
    tz = device.get("timezone", "+0530")
    sign = -1 if tz[0] == "-" else 1
    return sign * (int(tz[1:3]) * 60 + int(tz[3:5])), tz


def _stamp(ts, ms, tz_min=330, tz_label="+0530"):
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=tz_min))
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z" + tz_label)


def _ms(base):
    """A plausible millisecond near `base` -- the genuine stamps vary."""
    return max(0, min(999, base + random.randint(-180, 180)))


def _ua(device):
    """The Dalvik User-Agent the app itself would send."""
    return ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
            % (device["os_version"], device["device_name"],
               device["os_build"]))


def _headers(campaign, device, fields, kind, sec):
    """The header dict every api method sends, signature included."""
    return {
        "Client-SDK": campaign["adjust"]["sdk"],
        "Authorization": S.sign_request(fields, kind, campaign, second=sec),
        "User-Agent": _ua(device),
        "Content-Type": "application/x-www-form-urlencoded",
    }


# The signing second sits a little in the past, so created_at/sent_at never
# claim a moment that has not happened yet.
MINT_SKEW = -2
# The install must land AFTER the click that caused it: Adjust pairs a click
# with the install it produced, so a body whose installed_at predates the
# click has nothing to join to and the click is dropped (Organic).
# INSTALL_AFTER is the Play download+install time, in seconds after the
# click; the proven device story is a ~14 s gap.
INSTALL_AFTER = 14


def signing_second():
    """The second to stamp on the body AND to sign with."""
    return int(time.time()) + MINT_SKEW


def session(campaign_data, device_data):
    """POST /session -- the app announcing itself.  Returns the response dict.

    installed_at/updated_at land INSTALL_AFTER seconds after the click, so
    the body is consistent with the click -> install order the server checks.
    """
    # the gap lands BEFORE stamping: created_at/sent_at must postdate the
    # click that caused the install (and installed_at, click+INSTALL_AFTER)
    if GAP and not DRY_RUN:
        time.sleep(GAP)
    sec = signing_second()
    tz_minutes, tz = _tz_parts(device_data)
    installed = _stamp(RUN["click_sec"] + INSTALL_AFTER
                       if RUN["click_sec"] else sec, _ms(774), tz_minutes, tz)
    fields = {
        "first_error": device_data.get("first_error", "0"),
        "package_name": campaign_data["package_name"],
        "last_error": device_data.get("last_error", "0"),
        "tracking_enabled": "1",
        "needs_response_details": "1",
        "os_name": "android",
        "device_type": "phone",
        "device_manufacturer": device_data.get("device_manufacturer", ""),
        "connectivity_type": device_data.get("connectivity_type", "0"),
        "offline_mode_enabled": "0",
        "sent_at": _stamp(sec, _ms(942), tz_minutes, tz),
        "installed_at": installed,
        "environment": "production",
        "os_version": device_data.get("os_version", ""),
        "android_uuid": RUN["android_uuid"],
        "enqueue_size": device_data.get("enqueue_size", "0"),
        "display_width": device_data.get("display_width", ""),
        "screen_density": device_data.get("screen_density", "high"),
        "foreground": "1",
        "gps_adid": RUN["gaid"],
        "wait_total": device_data.get("wait_total", "0.0"),
        "wait_time": device_data.get("wait_time", "0.0"),
        "screen_size": device_data.get("screen_size", "large"),
        "gps_adid_attempt": "1",
        "updated_at": installed,
        "gps_adid_src": "service",
        "screen_format": device_data.get("screen_format", "long"),
        "store_name_from_system": "com.android.vending",
        "display_height": device_data.get("display_height", ""),
        "hardware_name": device_data.get("hardware_name", ""),
        "app_token": campaign_data["adjust"]["app_token"],
        "attribution_deeplink": "1",
        "app_version": campaign_data["app_version_name"],
        "language": device_data.get("language", ""),
        "country": device_data.get("country", ""),
        "created_at": _stamp(sec, _ms(928), tz_minutes, tz),
        "session_count": "1",
        "initiating_package_name": "com.android.vending",
        "device_name": device_data.get("device_name", ""),
        "retry_count": device_data.get("retry_count", "0"),
        "cpu_type": device_data.get("cpu_type", ""),
        "ui_mode": "1",
        "api_level": device_data.get("api_level", ""),
        "os_build": device_data.get("os_build", ""),
    }
    # mcc/mnc go in only when the device dump carries both; both shapes are
    # genuine (the 3 Oct declic capture signed them, the g42/creditsea ones
    # did not) and the claims law signs whichever keys the map carries.
    if device_data.get("mcc") and device_data.get("mnc"):
        fields["mcc"] = device_data["mcc"]
        fields["mnc"] = device_data["mnc"]
    headers = _headers(campaign_data, device_data, fields, "session", sec)
    print("session    %d fields, signed" % len(fields))
    if DRY_RUN:
        print("           dry run -- not sending")
        return {}
    r = requests.post("https://app.adjust.com/session", data=fields,
                      headers=headers, timeout=30, proxies=PROXIES)
    print("           -> %d  [t=+%.0fs]"
          % (r.status_code, time.time() - RUN["t0"]))
    return r.json() if r.content else {}


def sdk_click(campaign_data, device_data):
    """POST /sdk_click -- the install claiming a click.

    click -> install_begin (click+2..4) -> installed (click+INSTALL_AFTER)."""
    if not RUN["referrer"]:
        print("sdk_click no reftag -- skipped")
        return {}
    if GAP and not DRY_RUN:              # gap before stamping (see session)
        time.sleep(GAP)
    sec = signing_second()
    tz_minutes, tz = _tz_parts(device_data)
    click_sec = RUN["click_sec"] or sec
    installed = _stamp(click_sec + INSTALL_AFTER, _ms(774), tz_minutes, tz)
    begin = click_sec + random.randint(2, 4)
    fields = {
        "package_name": campaign_data["package_name"],
        "google_play_instant": "0",
        "tracking_enabled": "1",
        "needs_response_details": "1",
        "time_spent": "0",
        "os_name": "android",
        "device_type": "phone",
        "device_manufacturer": device_data.get("device_manufacturer", ""),
        "connectivity_type": device_data.get("connectivity_type", "0"),
        "offline_mode_enabled": "0",
        "sent_at": _stamp(sec, _ms(970), tz_minutes, tz),
        "click_time": _stamp(click_sec, 0, tz_minutes, tz),
        "os_version": device_data.get("os_version", ""),
        "installed_at": installed,
        "environment": "production",
        "source": "install_referrer",
        "click_time_server": _stamp(click_sec, 0, tz_minutes, tz),
        "session_length": "0",
        "install_version": campaign_data["app_version_name"],
        "display_width": device_data.get("display_width", ""),
        "screen_density": device_data.get("screen_density", "high"),
        "subsession_count": "1",
        "android_uuid": RUN["android_uuid"],
        "foreground": "1",
        "gps_adid": RUN["gaid"],
        "referrer_api": "google",
        "screen_size": device_data.get("screen_size", "large"),
        "gps_adid_attempt": "1",
        "updated_at": installed,
        "gps_adid_src": "service",
        "screen_format": device_data.get("screen_format", "long"),
        "display_height": device_data.get("display_height", ""),
        "hardware_name": device_data.get("hardware_name", ""),
        "app_token": campaign_data["adjust"]["app_token"],
        "attribution_deeplink": "1",
        "app_version": campaign_data["app_version_name"],
        "language": device_data.get("language", ""),
        "referrer": RUN["referrer"],
        "country": device_data.get("country", ""),
        "created_at": _stamp(sec, _ms(961), tz_minutes, tz),
        "session_count": "1",
        "device_name": device_data.get("device_name", ""),
        "install_begin_time": _stamp(begin, 0, tz_minutes, tz),
        "cpu_type": device_data.get("cpu_type", ""),
        "ui_mode": "1",
        "install_begin_time_server": _stamp(begin, 0, tz_minutes, tz),
        "api_level": device_data.get("api_level", ""),
        "os_build": device_data.get("os_build", ""),
    }
    if device_data.get("mcc") and device_data.get("mnc"):
        fields["mcc"] = device_data["mcc"]
        fields["mnc"] = device_data["mnc"]
    headers = _headers(campaign_data, device_data, fields, "click", sec)
    print("sdk_click  %d fields, signed" % len(fields))
    if DRY_RUN:
        print("           dry run -- not sending")
        return {}
    r = requests.post("https://app.adjust.com/sdk_click", data=fields,
                      headers=headers, timeout=30, proxies=PROXIES)
    print("           -> %d  [t=+%.0fs]"
          % (r.status_code, time.time() - RUN["t0"]))
    return r.json() if r.content else {}


def attribution(campaign_data, device_data):
    """GET /attribution -- ask what we were attributed to.  Returns the
    attribution dict from the response."""
    sec = signing_second()
    tz_minutes, tz = _tz_parts(device_data)
    fields = {
        "foreground": "1",
        "gps_adid": RUN["gaid"],
        "package_name": campaign_data["package_name"],
        "tracking_enabled": "1",
        "needs_response_details": "1",
        "gps_adid_attempt": "1",
        "os_name": "android",
        "gps_adid_src": "service",
        "device_type": "phone",
        "offline_mode_enabled": "0",
        "attribution_deeplink": "1",
        "sent_at": _stamp(sec, _ms(696), tz_minutes, tz),
        "initiated_by": "sdk",
        "created_at": _stamp(sec, _ms(666), tz_minutes, tz),
        "device_name": device_data.get("device_name", ""),
        "environment": "production",
        "os_version": device_data.get("os_version", ""),
        "android_uuid": RUN["android_uuid"],
        "ui_mode": "1",
        "app_token": campaign_data["adjust"]["app_token"],
        "app_version": campaign_data["app_version_name"],
        "api_level": device_data.get("api_level", ""),
    }
    headers = _headers(campaign_data, device_data, fields, "attribution", sec)
    del headers["Content-Type"]          # a GET carries no body
    if GAP:
        time.sleep(GAP)
    for _try in range(3):                # long waits see transient TLS drops
        try:
            r = requests.get("https://app.adjust.com/attribution",
                             params=fields, headers=headers, timeout=30,
                             proxies=PROXIES)
            return r.json().get("attribution", {}) if r.content else {}
        except Exception:
            if _try == 2:
                raise
            time.sleep(3)


def event(campaign_data, device_data, event_token=None, partner_params=None,
          seq=1, event_count=1, push_token=None):
    """POST /event -- an in-app event.  A plain event passes neither
    event_token nor partner_params and the claims law omits them."""
    if GAP and not DRY_RUN:              # gap before stamping (see session)
        time.sleep(GAP)
    sec = signing_second()
    tz_minutes, tz = _tz_parts(device_data)
    fields = {
        "package_name": campaign_data["package_name"],
        "tracking_enabled": "1",
        "needs_response_details": "1",
        "time_spent": "0",
        "os_name": "android",
        "device_type": "phone",
        "device_manufacturer": device_data.get("device_manufacturer", ""),
        "connectivity_type": device_data.get("connectivity_type", "0"),
        "offline_mode_enabled": "0",
        "sent_at": _stamp(sec, _ms(940), tz_minutes, tz),
        "environment": "production",
        "os_version": device_data.get("os_version", ""),
        "android_uuid": RUN["android_uuid"],
        "enqueue_size": device_data.get("enqueue_size", "0"),
        "display_width": device_data.get("display_width", ""),
        "screen_density": device_data.get("screen_density", "high"),
        "foreground": "1",
        "gps_adid": RUN["gaid"],
        "wait_total": device_data.get("wait_total", "0.0"),
        "wait_time": device_data.get("wait_time", "0.0"),
        "screen_size": device_data.get("screen_size", "large"),
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "screen_format": device_data.get("screen_format", "long"),
        "display_height": device_data.get("display_height", ""),
        "hardware_name": device_data.get("hardware_name", ""),
        "app_token": campaign_data["adjust"]["app_token"],
        "attribution_deeplink": "1",
        "app_version": campaign_data["app_version_name"],
        "language": device_data.get("language", ""),
        "country": device_data.get("country", ""),
        "device_name": device_data.get("device_name", ""),
        "retry_count": device_data.get("retry_count", "0"),
        "first_error": device_data.get("first_error", "0"),
        "last_error": device_data.get("last_error", "0"),
        "cpu_type": device_data.get("cpu_type", ""),
        "ui_mode": "1",
        "api_level": device_data.get("api_level", ""),
        "os_build": device_data.get("os_build", ""),
        "event_count": str(event_count),
        "seq": str(seq),
        "session_count": "1",
        "session_length": "0",
        "subsession_count": "1",
        "created_at": _stamp(sec, _ms(873), tz_minutes, tz),
    }
    if event_token:
        fields["event_token"] = event_token
    if partner_params:
        fields["partner_params"] = partner_params
    if push_token:
        fields["push_token"] = push_token
    headers = _headers(campaign_data, device_data, fields, "event", sec)
    print("event      %d fields, signed" % len(fields))
    if DRY_RUN:
        print("           dry run -- not sending")
        return {}
    r = requests.post("https://app.adjust.com/event", data=fields,
                      headers=headers, timeout=30, proxies=PROXIES)
    print("           -> %d  [t=+%.0fs]"
          % (r.status_code, time.time() - RUN["t0"]))
    return r.json() if r.content else {}


def info(campaign_data, device_data, source="push", push_token=None):
    """POST /info -- SDK diagnostics, not an attribution path.  The claims
    key list is verified against two independent captures
    (verify_info_law.py)."""
    if GAP and not DRY_RUN:              # gap before stamping (see session)
        time.sleep(GAP)
    sec = signing_second()
    tz_minutes, tz = _tz_parts(device_data)
    fields = {
        "package_name": campaign_data["package_name"],
        "tracking_enabled": "1",
        "needs_response_details": "1",
        "os_name": "android",
        "device_type": "phone",
        "device_manufacturer": device_data.get("device_manufacturer", ""),
        "connectivity_type": device_data.get("connectivity_type", "0"),
        "offline_mode_enabled": "0",
        "sent_at": _stamp(sec, _ms(232), tz_minutes, tz),
        "environment": "production",
        "os_version": device_data.get("os_version", ""),
        "android_uuid": RUN["android_uuid"],
        "enqueue_size": device_data.get("enqueue_size", "0"),
        "display_width": device_data.get("display_width", ""),
        "screen_density": device_data.get("screen_density", "high"),
        "foreground": "1",
        "gps_adid": RUN["gaid"],
        "wait_total": device_data.get("wait_total", "0.0"),
        "wait_time": device_data.get("wait_time", "0.0"),
        "screen_size": device_data.get("screen_size", "large"),
        "gps_adid_attempt": "1",
        "gps_adid_src": "service",
        "screen_format": device_data.get("screen_format", "long"),
        "display_height": device_data.get("display_height", ""),
        "hardware_name": device_data.get("hardware_name", ""),
        "app_token": campaign_data["adjust"]["app_token"],
        "attribution_deeplink": "1",
        "app_version": campaign_data["app_version_name"],
        "language": device_data.get("language", ""),
        "country": device_data.get("country", ""),
        "device_name": device_data.get("device_name", ""),
        "retry_count": device_data.get("retry_count", "0"),
        "first_error": device_data.get("first_error", "0"),
        "last_error": device_data.get("last_error", "0"),
        "cpu_type": device_data.get("cpu_type", ""),
        "ui_mode": "1",
        "api_level": device_data.get("api_level", ""),
        "os_build": device_data.get("os_build", ""),
        "source": source,
        "created_at": _stamp(sec, _ms(210), tz_minutes, tz),
    }
    if push_token:
        fields["push_token"] = push_token
    headers = _headers(campaign_data, device_data, fields, "info", sec)
    print("info       %d fields, signed" % len(fields))
    if DRY_RUN:
        print("           dry run -- not sending")
        return {}
    r = requests.post("https://app.adjust.com/info", data=fields,
                      headers=headers, timeout=30, proxies=PROXIES)
    print("           -> %d  [t=+%.0fs]"
          % (r.status_code, time.time() - RUN["t0"]))
    return r.json() if r.content else {}


def open_click_link(gaid, dp2=None):
    """Follow the tracker link and return the adjust_reftag it hands back.

    The link may carry the device id under several macro names: {gaid} and
    {dp2} are ours; {click_id}, {sub3} and {idfa} are the AutoLabs names.
    All resolve to the advertising id the install will report.

    THE ORGANIC TRAP: the click must carry the id as gps_adid= -- the Android
    parameter.  The same value passed as idfa= (the iOS parameter) is NOT
    matched against the install's gps_adid, the click has nothing to join to,
    and Adjust answers Organic.  If the template lacks gps_adid= it is
    appended here.
    """
    url = campaign_data["click_link"]
    for _k in ("gaid", "dp2", "click_id", "sub3", "idfa"):
        url = url.replace("{%s}" % _k, gaid)

    def fill(u):
        """Fill empty or macro gps_adid params with the install's id, at any
        hop.  Affiliate chains (mobpine -> go.link) forward their OWN device
        param adj_gps_adid= EMPTY, and an Adjust click without a device id
        can never join the install."""
        u = re.sub(r'adj_gps_adid=(&|$)', 'adj_gps_adid=' + gaid + r'\1', u)
        u = re.sub(r'(?<!adj_)gps_adid=(&|$)', 'gps_adid=' + gaid + r'\1', u)
        u = re.sub(r'adj_gps_adid=%7B[^&]*%7D', 'adj_gps_adid=' + gaid, u)
        u = re.sub(r'(?<!adj_)gps_adid=%7B[^&]*%7D', 'gps_adid=' + gaid, u)
        u = re.sub(r'adj_gps_adid=[{][^&]*[}]', 'adj_gps_adid=' + gaid, u)
        u = re.sub(r'(?<!adj_)gps_adid=[{][^&]*[}]', 'gps_adid=' + gaid, u)
        return u

    url = fill(url)
    if "gps_adid=" not in url:
        url += "&gps_adid=" + gaid
        print("NOTE       click template had no gps_adid= -- appended %s"
              % gaid)
        print("           a click that carries the id only as idfa= is never")
        print("           joined: that is the Organic in the AutoLabs log")
    for _ in range(8):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme in ("market", "intent"):
            break
        if PROXIES:
            _p = urllib.parse.urlsplit(PROXY if PROXY.startswith("http")
                                       else "http://" + PROXY)
            c = http.client.HTTPSConnection(_p.hostname, _p.port or 443,
                                            timeout=25)
            _path = (parts.scheme + "://" + parts.hostname
                     + urllib.parse.urlunsplit(("", "", parts.path or "/",
                                                parts.query, "")))
        else:
            c = (http.client.HTTPConnection(parts.hostname, 80, timeout=25)
                 if parts.scheme == "http" else
                 http.client.HTTPSConnection(parts.hostname, 443, timeout=25))
            _path = urllib.parse.urlunsplit(("", "", parts.path or "/",
                                             parts.query, ""))
        try:
            c.request("GET", _path, headers=dict(BROWSER_HEADERS))
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
        url = fill(urllib.parse.urljoin(url, location))
    return None


def main():
    RUN["gaid"] = str(uuid.uuid4())
    RUN["android_uuid"] = str(uuid.uuid4())
    RUN["t0"] = time.time()

    # 1. the click.  A dry run skips it: fetching the link IS what registers
    #    the click, so opening it would spend a click for nothing.
    if not DRY_RUN:
        referrer = open_click_link(RUN["gaid"])
        if not referrer:
            print("no reftag in the redirect chain -- aborting")
            return 1
        print("click      reftag %s" % referrer[:50])
        RUN["referrer"] = referrer
        RUN["click_sec"] = int(time.time())

    # 2. the install.  Signing is closed-form and pure Python: no VM.  The
    #    network round trip dominates.
    resp = session(campaign_data, DEVICE)
    adid = resp.get("adid", "")

    # 3. the install claiming the click.
    sdk_click(campaign_data, DEVICE)

    # 3a. an in-app event.  Optional: --event sends one, otherwise it is
    #     skipped so a plain attribution run stays exactly as it was.
    if SEND_EVENT:
        event(campaign_data, DEVICE, event_token=EVENT_TOKEN)

    # 3b. an /sdk_info call.  Optional: --info sends one, otherwise skipped.
    if SEND_INFO:
        info(campaign_data, DEVICE)

    # 4. the attribution
    if DRY_RUN:
        print("\nconfig is valid: the session signed cleanly.")
        return 0

    verdict = {}
    for delay in campaign_data["poll_delays"]:
        time.sleep(delay)
        verdict = attribution(campaign_data, DEVICE)
        print("poll +%-2ds   %s / %s  eng %s  [t=+%.0fs]"
              % (delay, verdict.get("network"),
                 verdict.get("tracker_token"),
                 (verdict.get("engagement_time") or "")[:19],
                 time.time() - RUN["t0"]))
        if verdict.get("network") and verdict["network"] != "Organic":
            break

    print()
    if verdict.get("network", "Organic") != "Organic":
        print("*** NON-ORGANIC ***   %.0fs total"
              % (time.time() - RUN["t0"]))
        for field in ("network", "tracker_token", "tracker_name", "campaign",
                      "adgroup", "engagement_time"):
            print("  %-16s %s" % (field, verdict.get(field)))
        print("  %-16s %s" % ("adid", adid))
    else:
        print("*** Organic / not joined ***   %.0fs total"
              % (time.time() - RUN["t0"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
