"""oneclick.py -- click, install, sign and send, all from one file.

The run has four steps:

  1. read the phone   -- every device fact comes off the device over adb
                         (screen, build, locale, timezone, ...), so the run
                         always signs as the phone it is actually talking to
  2. click            -- MODE A fires the tracker link and reads the real
                         install referrer out of the redirect; MODE B reuses
                         a click you already made
  3. install          -- optionally really install the app on that phone, so
                         the click->install timing is measured, not invented
  4. send             -- /session + /sdk_click, then poll /attribution

Everything you might want to change is in the CONFIG block below.
"""
import json
import os
import re
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_api as A
import adj9_signer as S
import device_probe

# ===========================================================================
#  CONFIG -- change these
# ===========================================================================

# "A" = paste the full link in LINK below; the script clicks it.
# "B" = you already clicked; fill in REFERRER + GAID below instead.
MODE = "A"

# --- MODE A only ----------------------------------------------------------
# The full tracker link.  {click_id} is replaced with the GAID.
LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id={click_id}&gps_adid={click_id}&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")

# --- MODE B only ----------------------------------------------------------
# The referrer the click produced.  Either the Play referrer the device saw:
#     "utm_source=google-play&utm_medium=organic"
# or an Adjust reftag:
#     "adjust_reftag=XXXX&adj_click_type=Click&..."
REFERRER = ""
# The GAID that was clicked.  "" here would make a fresh one (usually wrong
# for MODE B -- the click is tied to a specific GAID).
GAID = ""
# How many seconds ago that click actually fired.
CLICK_AGO = 6

# --- the phone ------------------------------------------------------------
# Which device to drive.  "" = the single connected phone (error if more than
# one is plugged in, so a run can never land on the wrong phone by accident).
SERIAL = ""

# Device facts.  Leave this "" and the script reads them off the phone with
# adb every run -- that is the recommended setting, because it cannot drift
# from the device you are actually testing.  You can still paste a JSON dump
# here (or name a file) to sign as some OTHER phone without touching this one.
DEVICE_DATA = ""

# --- install --------------------------------------------------------------
# INSTALL = True really installs the app on the phone, so the click->install
# timing is real instead of the CTIT guess below.  It runs `adb install`, which
# bypasses the Play Store, so the install referrer still has to come from the
# click in step 2 -- adb cannot manufacture one.
INSTALL = False
# Wipe the app before installing so the install is genuinely first-time.
# This DELETES the app and its data from the phone.
UNINSTALL_FIRST = True
# The app bundle to install (base + splits).  Paths are relative to this file.
APKS = ["../../base.apk",
        "../../split_config.arm64_v8a.apk",
        "../../split_config.en.apk",
        "../../split_config.xxxhdpi.apk"]

# --- how the requests leave ----------------------------------------------
TRANSPORT = "pc"          # "pc" = this computer, "device" = phone's IP (adb)

# --- timing / polling -----------------------------------------------------
CTIT = 6.0                # click->install seconds; only used when INSTALL=False
CTIT_BEGIN = 4.0          # click->download-start; only used when INSTALL=False
POLLS = 5                 # how many times to ask for the verdict
POLL_GAP = 12             # seconds between polls

# The browser User-Agent the CLICK presents as.  Leave "" to auto-build a
# standard Chrome-on-Android UA using your device's Android version, e.g.
#   Mozilla/5.0 (Linux; Android 15; sdk_gphone64_arm64) ... Chrome/153...
# Set it explicitly to pin an exact string.
CLICK_UA = ""

DRY = False               # True = build + show everything, send nothing

# ===========================================================================

GAID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def default_click_ua(os_version):
    """A standard Chrome-on-Android UA using the device's Android version."""
    return ("Mozilla/5.0 (Linux; Android %s; sdk_gphone64_arm64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/153.0.8010.36 Mobile Safari/537.36" % os_version)



ANDROID_UA = ("Mozilla/5.0 (Linux; Android 12; moto g42) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36")


def _extract_referrer(location):
    """Pull the install referrer out of a Play/App Store redirect URL.

    Handles  market://details?id=..&referrer=<urlencoded>  and
            https://play.google.com/..&referrer=<urlencoded>  and the
            apps.apple.com "...&pt=<...>" form.
    """
    import urllib.parse
    q = urllib.parse.urlparse(location).query
    vals = urllib.parse.parse_qs(q)
    for key in ("referrer", "pt"):
        if key in vals and vals[key]:
            return urllib.parse.unquote_plus(vals[key][0])
    return None


def fire_click(link, gps, click_ua=None):
    """Click the tracker link AS THE GIVEN DEVICE (its real browser UA).

    Returns (t_click, referrer).  We do NOT follow the redirect (it points at
    market://, which urllib cannot fetch); we capture the 302 Location and pull
    the real install referrer out of it.  If no referrer is present we fall
    back to the generic Play referrer.
    """
    import urllib.request
    import urllib.parse
    from urllib.error import HTTPError

    url = link.replace("{click_id}", gps).replace("{sub3}", gps)
    ua = click_ua or ANDROID_UA

    # Capture the redirect target without following it.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None                      # stop; we want the Location header
    opener = urllib.request.build_opener(NoRedirect)

    t_click = time.time()
    referrer = None
    try:
        r = opener.open(urllib.request.Request(url,
                                               headers={"User-Agent": ua}),
                        timeout=45)
        code = r.getcode()
        location = r.headers.get("Location")
    except HTTPError as e:
        code = e.code
        location = e.headers.get("Location") if e.headers else None
    except Exception as e:
        print("  click error: %s" % e)
        return t_click, None

    print("  click HTTP %s" % code)
    if location:
        print("  redirect -> %s" % location[:100])
        referrer = _extract_referrer(location)
    if not referrer:
        referrer = "utm_source=google-play&utm_medium=organic"
        print("  no referrer in redirect; using generic Play referrer")
    else:
        print("  referrer  : %s" % referrer)
    return t_click, referrer


def read_device(serial):
    """Get the device facts: off the phone, or from DEVICE_DATA if you set it.

    Returns (profile, source_description).
    """
    if isinstance(DEVICE_DATA, str) and DEVICE_DATA.lstrip().startswith("{"):
        return A.load_profile(DEVICE_DATA), "DEVICE_DATA (inline JSON)"
    if isinstance(DEVICE_DATA, dict):
        return A.load_profile(DEVICE_DATA), "DEVICE_DATA (dict)"
    if DEVICE_DATA:
        return A.load_profile(os.path.join(HERE, DEVICE_DATA)), \
               "DEVICE_DATA (%s)" % DEVICE_DATA

    # Default: ask the phone.
    info = device_probe.collect(serial or None)
    path = device_probe.save(info, os.path.join(HERE, "device_data.json"))
    return A.load_profile(json.dumps(info)), "the phone (saved %s)" \
                                               % os.path.basename(path)


def describe_device(api, serial):
    """A few lines saying which phone this run signs as."""
    d = api.DEV
    print("  model      : %s %s  (Android %s / API %s)"
          % (d["device_manufacturer"], d["device_name"], d["os_version"],
             d["api_level"]))
    print("  build      : %s" % d["os_build"])
    print("  screen     : %sx%s  %s" % (d["display_width"], d["display_height"],
                                       d["screen_density"]))
    print("  timezone   : %s" % api.OFF_LABEL)
    if serial:
        print("  serial     : %s" % serial)


def install_app(serial, off_minutes):
    """Really install the app on the phone; return the real install timings.

    Returns (t_begin, t_done) as unix seconds.  `adb install` writes the app
    for real, so the gap between these two is a measured install, not a guess.
    """
    apks = [os.path.normpath(os.path.join(HERE, a)) for a in APKS]
    missing = [a for a in apks if not os.path.isfile(a)]
    if missing:
        raise SystemExit("missing APK(s):\n  " + "\n  ".join(missing))
    if not serial:
        raise SystemExit("INSTALL needs a device: connect the phone or set SERIAL")

    if UNINSTALL_FIRST:
        print("  uninstalling %s (its data is deleted)" % A.PACKAGE)
        device_probe.adb("uninstall", A.PACKAGE, serial=serial, retries=0)

    t_begin = time.time()
    out = device_probe.adb("install-multiple", "-r", "-d", *apks,
                           serial=serial, timeout=300, retries=0)
    t_done = time.time()
    ok = "Success" in out
    print("  install-multiple -> %s" % (out.strip().splitlines()[-1]
                                       if out.strip() else "(no output)"))
    if not ok:
        raise SystemExit("install failed:\n%s" % out)

    # Cross-check against what the package manager recorded.  That clock is
    # the device's local time, so put it back onto the run's offset.
    pkg = device_probe.adb("shell", "dumpsys", "package", A.PACKAGE,
                           serial=serial)
    m = re.search(r"firstInstallTime=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", pkg)
    if m:
        import datetime
        recorded = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        print("  package manager firstInstallTime: %s" % m.group(1))
        t_done = recorded.replace(
            tzinfo=datetime.timezone(datetime.timedelta(
                minutes=off_minutes))).timestamp()
    print("  real install took %.1fs" % (t_done - t_begin))
    return t_begin, t_done


def show_blobs(api, gps, auid, t_click, referrer, ins, tb, sec_install):
    """DRY mode: show the three signatures without sending anything."""
    for kind in ("session", "click", "attribution"):
        p = build_params(api, kind, gps, auid, t_click, referrer, ins, tb,
                         sec_install)
        val = A.S.claims_from_wire(p, kind)
        V = api._V_for(p, sec_install, None)
        blob, info = S.mint_blob(val, kind, second=sec_install, V=V)
        print("\n--- %s ---" % kind)
        print("  params : %d   claims : %d" % (len(p), len(val)))
        print("  #10    : %d B" % info["desc10_unpadded"])
        print("  blob   : %d B  %s" % (len(blob), info["status"]))
        print("  auth   : %s..." % S.auth_header(blob)[:88])
    print("\n=== DRY RUN: nothing was sent ===")


def build_params(api, kind, gps, auid, t_click, referrer, ins, tb,
                 sec_install):
    """The exact params one endpoint will carry (also used by DRY mode)."""
    if kind == "session":
        p = api._base("S1P")
        p.update({"gps_adid": gps, "android_uuid": auid,
                  "created_at": api.fmt(sec_install, 928).decode(),
                  "sent_at": api.fmt(sec_install, 942).decode(),
                  "installed_at": ins, "updated_at": ins})
        return p
    if kind == "attribution":
        d = api._dev_fields()
        p = {"initiated_by": "backend", "gps_adid_attempt": "1",
             "api_level": d["api_level"], "app_version": d["app_version"],
             "app_token": A.APP_TOKEN, "os_version": d["os_version"],
             "created_at": api.fmt(sec_install, 666).decode(),
             "device_type": "phone", "gps_adid": gps, "foreground": "1",
             "android_uuid": auid,
             "sent_at": api.fmt(sec_install, 696).decode(),
             "offline_mode_enabled": "0", "device_name": d["device_name"],
             "environment": "production", "needs_response_details": "1",
             "attribution_deeplink": "1", "package_name": "com.penti.app",
             "os_name": "android", "ui_mode": "1",
             "gps_adid_src": "service", "tracking_enabled": "1"}
        if api.ADD_IDFA:
            p["idfa"] = gps
        return p
    # kind == "click"  (the /sdk_click endpoint)
    p = api._base("S2P")
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": api.fmt(sec_install, 961).decode(),
              "sent_at": api.fmt(sec_install, 970).decode(),
              "installed_at": ins, "updated_at": ins,
              "referrer": referrer, "source": "install_referrer",
              "referrer_api": "google",
              "click_time": api.fmt(t_click, 0).decode(),
              "click_time_server": api.fmt(t_click - 2, 0).decode(),
              "install_begin_time": api.fmt(tb, 0).decode(),
              "install_begin_time_server": api.fmt(tb - 2, 0).decode()})
    return p


def read_ask_in(body):
    """How long the server wants us to wait before asking for attribution.

    The real /session answers {"adid": ..., "ask_in": 2000} -- "come back in
    2 seconds" -- and the genuine capture duly asks 3.5s later.  Returns
    seconds, or None when the field is absent.
    """
    try:
        v = json.loads(body).get("ask_in")
        return float(v) / 1000.0 if v is not None else None
    except Exception:
        return None


def main():
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8888'
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8888'
    label = "A (script clicks the link)" if MODE == "A" else "B (already clicked)"
    print("=" * 62)
    print(" adj9 oneclick -- MODE %s   transport=%s  %s"
          % (label, TRANSPORT, "[DRY]" if DRY else "[LIVE]"))
    print(" install=%s   device=%s" % ("real" if INSTALL else "simulated",
                                       "phone" if not DEVICE_DATA else "DEVICE_DATA"))
    print("=" * 62)

    # --- step 1: which phone are we signing as? --------------------------
    print("\nSTEP 1  device")
    try:
        profile, source = read_device(SERIAL)
    except device_probe.ProbeError as e:
        print("  could not read the phone: %s" % e)
        print("  (set DEVICE_DATA to a JSON dump to run without a phone)")
        return
    api = A.Api(profile=profile, transport=TRANSPORT, serial=SERIAL)
    serial = None
    if not DEVICE_DATA:
        try:
            serial = device_probe.pick_serial(SERIAL or None)
        except device_probe.ProbeError:
            serial = None
    print("  source     : %s" % source)
    describe_device(api, serial)

    # --- identity ---------------------------------------------------------
    # MODE B must reuse the GAID that actually clicked.  MODE A makes a fresh
    # one (never reuse a GAID).
    if MODE == "B" and GAID:
        gps = GAID
    else:
        gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    print("  gps_adid   : %s" % gps)
    print("  android_uuid: %s" % auid)

    # --- click ------------------------------------------------------------
    if MODE == "B":
        t_click = time.time() - float(CLICK_AGO)
        referrer = REFERRER
        print("\nSTEP 2  click SKIPPED (MODE B)")
        print("  referrer : %s" % referrer[:120])
        print("  clicked %.0fs ago" % CLICK_AGO)
    else:
        if DRY:
            # A dry run must not hit the network, so don't fire a real click.
            t_click = time.time()
            referrer = "utm_source=google-play&utm_medium=organic"
            print("\nSTEP 2  click SKIPPED (DRY run sends nothing)")
            print("  referrer : %s" % referrer)
        else:
            click_ua = CLICK_UA or default_click_ua(api.DEV["os_version"])
            print("\nSTEP 2  firing the click (as Chrome on Android)")
            print("  click UA : %s" % click_ua)
            t_click, referrer = fire_click(LINK, gps, click_ua)
            print("  referrer : %s" % referrer)

    # --- install ----------------------------------------------------------
    if INSTALL and not DRY:
        print("\nSTEP 3  installing for real on %s" % serial)
        tb, sec_install_f = install_app(serial, api.OFF_MINUTES)
        sec_install = int(sec_install_f)
        ins = api.fmt(sec_install, 0).decode()
        print("  click->install: %.1fs (measured, not guessed)"
              % (sec_install - t_click))
    else:
        if INSTALL and DRY:
            print("\nSTEP 3  install SKIPPED (DRY run changes nothing)")
        sec_install = int(t_click) + int(CTIT)
        ins = api.fmt(sec_install, 431).decode()
        tb = t_click + CTIT_BEGIN
        print("\nSTEP 3  simulated install (CTIT=%.0fs)" % CTIT)

    if DRY:
        show_blobs(api, gps, auid, t_click, referrer, ins, tb, sec_install)
        return

    # --- wait out the CTIT (only needed when the install was simulated) ---
    if not INSTALL:
        wait = sec_install - time.time()
        if wait > 0:
            print("  waiting %.0fs for the click->install delay..." % wait)
            time.sleep(wait)

    # --- send -------------------------------------------------------------
    print("\nSTEP 4  session + sdk_click")
    code, body = api.session(gps, auid, installed_at=ins)
    print("  /session    -> %s %s" % (code, body[:100]))
    ask_in = read_ask_in(body)
    if ask_in is not None:
        print("  server says ask_in=%.0fms -- it wants the verdict %.1fs "
              "after the click" % (ask_in * 1000, ask_in))
    code, body = api.sdk_click(gps, auid, referrer, t_click, tb, ins)
    print("  /sdk_click  -> %s %s" % (code, body[:100]))

    # --- verdict ----------------------------------------------------------
    # The real SDK asks for attribution once, roughly ask_in later, and only
    # re-asks if the answer was not ready.  Follow that instead of hammering.
    print("\nSTEP 5  polling attribution")
    initiated_by = "backend" if ask_in is not None else "sdk"
    first_gap = ask_in if ask_in is not None else 1.0
    print("  initiated_by=%s  first wait=%.1fs" % (initiated_by, first_gap))
    verdict = None
    for i in range(POLLS):
        time.sleep(first_gap if i == 0 else POLL_GAP)
        code, body = api.attribution(gps, auid, initiated_by=initiated_by)
        v = A.read_verdict(body)
        if v:
            verdict = v
            print("  poll %d/%d  %s token=%s eng=%s => %s"
                  % (i + 1, POLLS, code, v["token"], v["engagement_time"],
                     v["verdict"]))
            if not v["organic"]:
                break
        else:
            print("  poll %d/%d  %s (no verdict yet)" % (i + 1, POLLS, code))

    print("\n" + "=" * 62)
    print(" VERDICT: %s" % (verdict["verdict"] if verdict else "NO VERDICT"))
    print("=" * 62)
    with open(os.path.join(HERE, "last_run.json"), "w") as f:
        json.dump({"gps_adid": gps, "referrer": referrer,
                   "installed": bool(INSTALL and not DRY),
                   "click_to_install": round(sec_install - t_click, 1),
                   "device": api.DEV["device_name"],
                   "verdict": verdict}, f, indent=1)
    print("saved last_run.json")


if __name__ == "__main__":
    main()
