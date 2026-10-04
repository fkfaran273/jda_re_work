# -*- coding: utf-8 -*-
import os

import json
import random
import re
import time
import urllib.parse
import urllib.request
import uuid
from urllib.error import HTTPError

import adjust_v1
import util
from adjust_v1 import AdjustConfig

# --------------------------------------------------------------------------
# CONFIG -- everything you may want to change for one run lives here.
# --------------------------------------------------------------------------

GPS_ADID = ""              # empty => a FRESH GAID for every run
CLICK_UA = ""              # empty => a UA built from DEVICE_DATA
REFERRER = ""              # empty => take it from the click's redirect
DEVICE_DATA = ""           # path / JSON / dict; empty => probe the phone by adb
APP_SIZE_MB = 8.0          # only used to model the download duration

# Timing, taken from the account's three CONFIRMED non-organic attributions
# (rev/farm_win_result_prev.json, rev/farm_win_result.json -- creatives
# cline_fw_a, cline_fw_b, cline_nonorg_c_b).  Every one of them credits a
# click-to-install gap of 7-8 s:
#     cline_fw_a       engagement 10:29:47Z -> install 10:29:54Z    7 s
#     cline_fw_b       engagement 10:30:11Z -> install 10:30:18Z    7 s
#     cline_nonorg_c_b engagement 20:49:53Z -> install 20:50:01Z    8 s
# The 217 s figure came from penti_android_test.saz, but that capture's
# attribution credits an engagement 1.95 h BEFORE the install and 1.88 h before
# the click_time its own sdk_click reports -- i.e. the sdk_click click is a
# leftover from an earlier click, not the click that earned the credit.  The 217
# s gap in it is the gap between that stale click and the install, so it says
# nothing about the CTIT a real win needs.  Real wins here are single-digit
# seconds, so the timeline below models a short, believable install.
CTIT = 8.0                  # click -> install_complete
CTIT_BEGIN = 6.0            # click -> download_begin
INSTALL_SPAN = 2.0          # download_begin -> install_complete
SESSION_DELAY = 0.0         # session follows the install immediately
WAIT_FOR_CLOCK = True       # sleep for the modelled gaps instead of faking them

POLLS = 3                  # attribution polls when ask_in asks us to wait
POLL_GAP = 12              # seconds between polls
DRY = False                # True => build and sign every request, send nothing

# The installer the Play Store reports; the app repeats it in the session.
STORE = "com.android.vending"

# The winning sdk_click carries NO referrer: the capture's is the literal
# placeholder "utm_source=(not set)&utm_medium=(not set)", i.e. the install had no
# Play referrer and Adjust credited it purely by matching the click's gps_adid to
# the session's gps_adid.  Presenting a reftag we minted ourselves does not
# credit anything and instead advertises the install as referred.  The previous
# default was worse still -- "utm_source=google-play&utm_medium=organic" claims a
# Play organic install, which is a direct request for an Organic verdict.
EMPTY_REFERRER = "utm_source=(not%20set)&utm_medium=(not%20set)"
GENERIC_PLAY_REFERRER = EMPTY_REFERRER
GAID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


campaign_data = {
    'app_name': 'Penti',
    'package_name': 'com.penti.app',
    'app_version_name': u'3.13.9',
    'app_version_code': u'31309',
    'adjust': {
        "app_token": "jut9tib0eeps",
        "sdk": u'android5.7.0',
        "adj_port": "60515",
        "server": "adj_t3",
    },
}


# --------------------------------------------------------------------------
# the click
# --------------------------------------------------------------------------

def new_gaid():
    """A fresh advertising id for this run.  Never reuse a GAID: Adjust treats
    a repeated adid as the same device, and a reused one is the single easiest
    way to get two installs collapsed into one."""
    if GPS_ADID and GAID_RE.fullmatch(GPS_ADID.strip()):
        return GPS_ADID.strip().lower()
    return str(uuid.uuid4()).lower()


def browser_ua(device_data):
    """The Chrome-on-Android UA the real click presents from this phone."""
    if CLICK_UA:
        return CLICK_UA
    dev = device_data or {}
    model = dev.get("model") or dev.get("product") or "Android Device"
    osver = dev.get("os_version") or "12"
    chrome = "153.0.8010.36"
    for entry in (dev.get("User-Agent"), dev.get("user_agent")):
        if entry and "Chrome/" in entry:
            chrome = entry.split("Chrome/", 1)[1].split(" ")[0]
            break
    return ("Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/%s Mobile Safari/537.36"
            % (osver, model, chrome))


def extract_referrer(location):
    if not location:
        return None
    vals = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    for key in ("referrer", "pt"):
        if vals.get(key):
            return urllib.parse.unquote_plus(vals[key][0])
    return None


def fire_click(link, click_id, user_agent):
    """Click the tracker link as this device, and read the referrer back out.

    Returns (click_time, referrer).  The redirect is deliberately NOT followed:
    it points at market://, which urllib cannot fetch, and the only thing we
    need from it is the Location header that carries the real referrer.
    """
    if not link:
        return time.time(), (REFERRER or GENERIC_PLAY_REFERRER)

    url = link.replace("{click_id}", click_id).replace("{sub3}", click_id)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None                      # stop; we want the Location header

    opener = urllib.request.build_opener(NoRedirect)
    t_click = time.time()
    location = None
    try:
        r = opener.open(urllib.request.Request(
            url, headers={"User-Agent": user_agent,
                          "Accept": "text/html,application/xhtml+xml,text/xml;q=0.9,*/*;q=0.8"}),
            timeout=45)
        code, location = r.getcode(), r.headers.get("Location")
    except HTTPError as e:
        code, location = e.code, (e.headers.get("Location") if e.headers else None)
    except Exception as e:
        print("  click error: %s" % e)
        return t_click, None

    print("  click HTTP %s" % code)
    if location:
        print("  redirect -> %s" % location[:110])

    referrer = extract_referrer(location)
    if referrer:
        print("  referrer  : %s" % referrer[:160])
    else:
        referrer = REFERRER or GENERIC_PLAY_REFERRER
        print("  no referrer in redirect; using %s" % referrer)
    return t_click, referrer




def read_attribution(body):
    try:
        return json.loads(body).get("attribution")
    except Exception:
        return None


def load_device_data():
    """The device profile that goes on the wire.

    DEVICE_DATA may be a path to a JSON file, an inline JSON string, or a dict.
    With none of those set we fall back to the captured profile next to this
    script -- the physical moto g42 the genuine capture came from.  We do NOT
    probe the attached device: the wire must present ONE consistent fingerprint
    for the whole run, and mixing a live probe with a captured profile is how a
    session ends up self-contradictory (and instantly flagged).
    """
    if isinstance(DEVICE_DATA, dict):
        return dict(DEVICE_DATA)
    if DEVICE_DATA:
        text = DEVICE_DATA
        if os.path.exists(DEVICE_DATA):
            with open(DEVICE_DATA, encoding="utf-8") as fh:
                text = fh.read()
        return json.loads(text)
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "device_data.json"), encoding="utf-8") as fh:
        return json.load(fh)


def banner(text):
    print("\nAdjust : %s%s\n" % (text, "_" * max(4, 62 - len(text))))


def install(app_data, device_data, gaid, referrer, click_time):
    # The genuine capture's gaps are real elapsed time, so spend them for real.
    # installed_at has to be a timestamp the clock has actually reached: a
    # backdated install_complete that lands "now" is how the old run ended up
    # reporting a 0.9 s CTIT.  Sleeping here makes every stamp below consistent
    # with wall-clock time, which is also what the signature's embedded second is
    # checked against.
    target = click_time + CTIT + SESSION_DELAY
    if WAIT_FOR_CLOCK and not DRY:
        remaining = target - time.time()
        if remaining > 0:
            print("  waiting %.0fs for the capture's click->install->session gaps"
                  % remaining)
            time.sleep(remaining)

    # Supply the measured times through app_data so AdjustConfig adopts them at
    # construction instead of inventing its own modelled ones.
    app_data["times"] = {
        "click_time": click_time,
        "download_begin_time": click_time + CTIT_BEGIN,
        "download_end_time": click_time + CTIT_BEGIN + INSTALL_SPAN,
        "install_complete_time": click_time + CTIT
    }
    ins = AdjustConfig(campaign_data, app_data, device_data, min_ctit=CTIT)

    banner("Session")
    resp = ins.adjust_session(t1=0, t2=2)
    # adjust_session() returns the whole response dict, not the raw body, so the
    # ask_in field has to be read out of resp["data"].  When the backend answers
    # /session with ask_in (the genuine capture returns 2000), it owns the
    # attribution: the follow-up /attribution must then be initiated_by=backend,
    # not sdk.  Asking as "sdk" tells the server the SDK is resolving the click
    # itself, and it will not hand back the click it already linked -> Organic.
    ask_in = None
    try:
        body = resp.get("data") if isinstance(resp, dict) else resp
        v = json.loads(body).get("ask_in")
        if v:
            ask_in = v
    except Exception:
        pass
    init_by = "backend" if ask_in is not None else "sdk"
    print("  session ask_in=%s -> initiated_by=%s" % (ask_in, init_by))
    banner("SDK Click")
    # No referrer override: the winning capture reports the "(not set)"
    # placeholder, so let adjust_sdk_click send that.  Attribution then resolves
    # by matching this click's gps_adid against the session's gps_adid, which is
    # why the click link carries gps_adid at all.  Injecting the redirect's
    # reftag here would instead advertise a referrer the backend never issued.
    ins.adjust_sdk_click(source="install_referrer", t1=0, t2=2,
                         u_data={"foreground": "1",
                                 "offline_mode_enabled": "0"})

    attr = None
    for i in range(max(1, POLLS)):
        time.sleep(8)
        banner("Attribution (%d/%d)" % (i + 1, POLLS))
        # The genuine SDK polls attribution with GET and reads the JSON body.
        # HEAD returns no body, so fetch_response must be True or the
        # attribution can never be parsed.
        resp = ins.adjust_attribution(init_by=init_by, t1=0, t2=2,
                                      fetch_response=True)
        attr = read_attribution(resp.get("data"))
        if attr:
            break

    return {"attribution": attr, "gps_adid": gaid, "referrer": referrer,
            "initiated_by": init_by}


# --------------------------------------------------------------------------
# dry mode -- build and sign every request, send none
# --------------------------------------------------------------------------

def dry_stub(url, httpmethod, headers, params, data, **kwargs):
    kind = url.rsplit("/", 1)[-1]
    sent = data if isinstance(data, dict) and data else (params or {})
    n = len(sent)
    print(">>> [DRY] %s %s | %d params | %s"
          % (httpmethod.upper(), kind, n,
             (headers or {}).get("Authorization", "NO AUTH")[:60]))
    with open("_scratch/dry_maps.json", "a") as fh:
        fh.write(json.dumps({"kind": kind, "method": httpmethod,
                             "auth": headers.get("Authorization", ""),
                             "map": sent}, sort_keys=True) + "\n")
    body = {"ask_in": 2000, "adid": sent.get("gps_adid")} \
        if kind == "session" else {}
    return {"res": None, "status": 1, "code": 200, "error": None,
            "data": json.dumps(body), "req_length": 0, "cookies_length": 0}


# --------------------------------------------------------------------------

def main():
    # The local MITM proxy is only needed to CAPTURE traffic for reverse
    # engineering; delivering a live signed request works fine direct.  Only
    # route through it when PENTI_PROXY is set (and the proxy is actually up),
    # otherwise a dead :8888 would make every request fail.
    if os.environ.get("PENTI_PROXY"):
        os.environ['HTTP_PROXY'] = os.environ["PENTI_PROXY"]
        os.environ['HTTPS_PROXY'] = os.environ["PENTI_PROXY"]
    # The genuine capture -- and the real device this account belongs to -- is a
    # physical moto g42 (motorola/hawao_g/hawao:12/S2SE32.28-28-4, Android 12,
    # API 31).  An emulator fingerprint (sdk_gphone64/emu64a, Goldfish sensors,
    # "AArch64 Processor rev 4") is an instant anti-fraud flag: Adjust records the
    # click but will not credit a non-organic install to it, so attribution falls
    # back to Organic.  The wire fingerprint must therefore be the real device.
    device_data = load_device_data()
    # The install session is keyed by gps_adid (the GAID).  A click that only
    # carries idfa= is recorded but orphaned: Adjust has no way to match it to
    # the gps_adid the session reports, so the install falls back to Organic.
    # The genuine winning device recipe sends click_id + idfa + gps_adid, so we
    # must present gps_adid on the click too.
    _link = "https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id={click_id}&idfa={sub3}&gps_adid={click_id}&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp"
    gaid = new_gaid()
    print("  gaid      : %s" % gaid)

    click_time, referrer = fire_click(_link, gaid, browser_ua(device_data))

    # The wire's gps_adid is the device's adid field, so the fresh id has to be
    # planted there -- and nowhere else, or the signed claim and the param drift.
    device_data["adid"] = gaid

    app_data = {
        # Left unset on purpose.  adjust_sdk_click substitutes its own
        # "(not set)" placeholder when there is no referrer, and that fallback
        # already carries the literal %20 the capture shows.  Supplying a value
        # here would instead route it through unquote(), which would decode
        # that %20 back into a space and put a "+" on the wire.
        "referrer": None,
        "store_name_from_system": STORE,
        "initiating_package_name": STORE,
    }
    # A fresh GAID means a fresh app identity too: the UUID must not be carried
    # over from a previous run or the two installs look like one device.
    app_data.pop("and_uuid", None)

    if DRY:
        util.execute_request = dry_stub

    out = install(app_data, device_data, gaid, referrer, click_time)
    print("\nResult: %s" % json.dumps(out, indent=1))
    with open("last_run.json", "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    return out


if __name__ == "__main__":
    main()
