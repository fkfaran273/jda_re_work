import base64
import http.client
import json
import os
import re
import secrets
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as F


HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as F

# ============ PASTE HERE (used when no CLI args given) ============
# 1) LINK: paste the tracker click link. BOTH forms work:
#    - template with placeholders: ...&click_id={click_id}&idfa={sub3}&...
#      -> {click_id} AND {sub3} are both replaced with the install GAID
#    - already-clicked link (real GAID inside): ...&click_id=<GAID>&idfa=<GAID>
#      -> if REFERRER_PASTED is set, the click is NOT fired again
LINK = "https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id=80970d76-1b90-4e28-97cc-a6e5cd55f690&idfa=80970d76-1b90-4e28-97cc-a6e5cd55f690&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D80970d76-1b90-4e28-97cc-a6e5cd55f690%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D80970d76-1b90-4e28-97cc-a6e5cd55f690%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp"

# 2) DEVICE_JSON: paste the device-data JSON (raw JSON, or a file path).
DEVICE_JSON = """{"kernel": "15", "locale": {"country": "IN", "language": "en"}, "ram": {"available": "5401", "shown": "8112"}, "os_incremental": "OS2.0.3.0.VNUINXM", "bluetooth": "3.0", "hardware": "", "imei": "868663035562624", "cpu_core": "7", "private_ip": "10.0.211.23", "device_type": "phone", "timezone": "+0530", "serial": "232427507a2a1454", "mnc": "908", "android_id": "b9b26e146de12319", "cpu_arch": "aarch64", "display_metrics": {"ypx": "1080", "screen_layout_name": "large", "screen_layout_format": "long", "xpx": "2312", "ydp": 440.098, "xdp": 439.962, "aspect_ratio": "14:6", "density_dpi": "xxhdpi"}, "last_rebooted_at": 1789928380318, "network_band": "LTE", "cpu_abi2": "", "User-Agent": "Mozilla/5.0 (Linux; Android 15; 2406ERN9CI Build/AQ3A.240912.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/152.0.7977.42 Mobile Safari/537.36", "cpu_frequency": {"max": "1958.0", "min": "499.0"}, "os_version": "15", "build": "AQ3A.240912.001", "manufacturer": "Xiaomi", "product": "breeze_in", "brand": "Redmi", "screen_size": "5.8", "mcc": "405", "device_id": "80970d76-1b90-4e28-97cc-a6e5cd55f690", "adid": "80970d76-1b90-4e28-97cc-a6e5cd55f690", "fingerprint": "Redmi/breeze_in/breeze:15/AQ3A.240912.001/OS2.0.3.0.VNUINXM:user/release-keys", "device": "breeze", "sdk": "35", "mainboard": "breeze", "country": "India", "cpu_abi": "arm64-v8a", "network": "WiFi", "carrier": "Vi India", "os_codename": "REL", "model": "2406ERN9CI", "resolution": "1080x2312", "dpi": "440"}"""

# 3) PIN_GPS: the GAID / install identity.
#    "" -> taken from the LINK (idfa=/gps_adid=/click_id=) if present, else fresh.
PIN_GPS = ""

# 4) REFERRER_PASTED: set ONLY if the link was already clicked and you do NOT
#    want a new click fired. When set, the click step is SKIPPED and this
#    referrer string is used directly.
REFERRER_PASTED = ""


# =====================================================================

DENSITY = {"ldpi": "low", "mdpi": "medium", "hdpi": "high",
           "xhdpi": "xhigh", "xxhdpi": "xxhigh", "xxxhdpi": "xxxhigh"}


def dev_from_json(d):
    loc = d.get("locale", {}) or {}
    dm = d.get("display_metrics", {}) or {}
    return {
        "api_level": str(d.get("sdk", "36")),
        "os_version": str(d.get("os_version", "16")),
        "device_name": d.get("model", "2407FPN8EG"),
        "device_manufacturer": d.get("brand", "Xiaomi"),
        # wire hardware_name = the device's mainboard on real calls (vivo
        # V2347 -> k6985v1_64, NOT "qcom"); fall back sanely.
        "hardware_name": (d.get("mainboard") or d.get("hardware")
                          or d.get("board") or "qcom"),
        "os_build": d.get("build", ""),
        "app_version": "3.13.9",
        "install_version": "3.13.9",
        "language": loc.get("language", "tr"),
        "mcc": str(d.get("mcc", "286")),
        "mnc": str(d.get("mnc", "01")),
        "display_width": str(dm.get("xpx", "1220")),
        "display_height": str(dm.get("ypx", "2712")),
        "screen_density": DENSITY.get(dm.get("density_dpi", "xxxhdpi"),
                                      "xxxhigh"),
    }


def ua_from_json(d):
    return ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
            % (d.get("os_version", "16"), d.get("model", ""),
               d.get("build", "")))


def click_tracker(link, gps, ua, dev):
    """Stamp ids, follow hops like the device's own Chrome, return referrer.

    Uses the device JSON's browser UA + Chrome header set + Chrome TLS
    impersonation (curl_cffi), so the click carries the device's brand,
    model, locale and TLS fingerprint — not Python/Dalvik's.
    """
    from curl_cffi import requests as cr
    loc = (dev.get("locale", {}) or {})
    lang = loc.get("language", "tr")
    country = loc.get("country", "TR")
    chrome_ua = (dev.get("User-Agent") or ua).replace("Dalvik/2.1.0 ", "")
    if "Chrome/" not in chrome_ua:
        chrome_ua = ("Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36"
                     " (KHTML, like Gecko) Chrome/151.0.7922.47 Mobile"
                     " Safari/537.36"
                     % (dev.get("os_version", "16"),
                        dev.get("model", "")))
    ver = "151"
    if "Chrome/" in chrome_ua:
        try:
            ver = chrome_ua.split("Chrome/")[1].split(".")[0]
        except Exception:
            pass
    headers = {
        "User-Agent": chrome_ua,
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "%s-%s,%s;q=0.9" % (lang, country, lang),
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "sec-ch-ua": ('"Chromium";v="%s", "Google Chrome";v="%s", '
                      '"Not-A.Brand";v="99"' % (ver, ver)),
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
    }
    print("  click UA:", chrome_ua[:110], flush=True)
    parts = urllib.parse.urlsplit(link)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    # Tracker click still stamps both ids for the click record, but the
    # SESSION / CLICK / ATTR bodies must NOT carry idfa (SAZ-proven).
    q["gps_adid"] = gps
    q["idfa"] = gps  # click URL only (Adjust records both); wire bodies omit idfa
    url = urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q), parts.fragment))
    hop = url
    s = cr.Session(impersonate="chrome131")
    if F.USE_PROXY:
        s.proxies = {"http": F.PROXY_URL, "https": F.PROXY_URL}
        s.verify = False
    for _ in range(4):
        pr = urllib.parse.urlsplit(hop)
        if pr.scheme == "market":
            break
        r = s.get(hop, headers=headers, allow_redirects=False, timeout=30)
        loc = r.headers.get("Location", "")
        print("  hop: HTTP %s %s" % (r.status_code, (loc or "")[:120]),
              flush=True)
        if r.status_code not in (301, 302, 303, 307, 308) or not loc:
            break
        if "referrer=" in loc:
            return (urllib.parse.unquote(loc.split("referrer=", 1)[1]),
                    hop)
        hop = urllib.parse.urljoin(hop, loc)
    return None, hop


def parse_args(argv):
    """--name value pairs + bare positional fallbacks (device, link)."""
    named = {"--link": None, "--referrer": None, "--device": None,
             "--gps": None}
    pos, flags, skip = [], [], False
    for a in argv:
        if skip:
            skip = False
            continue
        if a in named:
            named[a] = None
            skip = True
            continue
        if a.startswith("--"):
            flags.append(a)
            continue
        pos.append(a)
    # second pass: attach values to the --name keys in order
    for i, a in enumerate(argv):
        if a in named:
            named[a] = argv[i + 1] if i + 1 < len(argv) else None
    return named, pos, flags


def main():
    named, pos, flags = parse_args(sys.argv[1:])
    args = [a for a in pos if a != "noproxy"]
    devsrc = (named.get("--device") or (args[0] if len(args) > 0 else None)
              or DEVICE_JSON or None)
    if not devsrc or devsrc in ("--link", "--referrer", "--gps"):
        print(__doc__)
        sys.exit(2)
    devsrc = devsrc.strip()
    dev = (json.loads(devsrc) if devsrc.startswith("{")
           else json.load(open(devsrc)))
    link = LINK
    ref_pasted = named.get("--referrer") or REFERRER_PASTED

    # GAID: CLI > PIN_GPS > the link's own idfa/gps_adid/click_id > fresh uuid
    gps = named.get("--gps") or PIN_GPS or ""
    if not gps and link:
        m = re.search(r"(?:idfa|gps_adid|click_id)=([A-Za-z0-9-]{8,})", link)
        if m:
            gps = m.group(1)
    if not gps:
        gps = str(uuid.uuid4())
    print("install gps:", gps, flush=True)

    # Expand BOTH placeholders to the GAID (matches the user's link pattern
    # where click_id and idfa both carry the GAID). If the link is already
    # expanded (real GAID inside), these replaces are no-ops.
    link = link.replace("{click_id}", gps).replace("{sub3}", gps)

    F.DEV, F.UA = dev_from_json(dev), ua_from_json(dev)
    # Timezone follows the DEVICE (Indian +0530, TR +0200) — never hardcoded.
    _tz = (dev.get("timezone") or "+0200").strip()
    _m = {"+0530": 330, "+0200": 120}.get(_tz)
    if _m is None:
        _sgn = -1 if _tz.startswith("-") else 1
        _d = _tz.lstrip("+-")
        _m = _sgn * (int(_d[:2]) * 60 + int(_d[2:4]))
    F.OFF_MINUTES, F.OFF_LABEL = _m, _tz
    print("device tz:", _tz, flush=True)
    F.ADD_IDFA = False  # SAZ-proven: NO idfa on SDK wire; keep off
    if "via-device" in sys.argv:
        F.USE_DEVICE = True
        print("transport: DEVICE — the signed calls are sent by the phone",
              "itself (adb shell curl), from its own IP/TLS stack", flush=True)
    elif "noproxy" in sys.argv:
        print("proxy OFF (direct)", flush=True)
    else:
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:8888"
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8888"
        F.USE_PROXY = True
        print("proxy ON via Fiddler 127.0.0.1:8888 (noproxy to disable)",
              flush=True)
    auid = str(uuid.uuid4())
    print("gps", gps, "auid", auid, flush=True)

    print("STEP 1/4 click...", flush=True)
    t_click = time.time()
    if "--click-only" in sys.argv:
        # click with THIS gps stamped (idfa+gps_adid), print referrer, STOP.
        # Never session/click/attr a device-bound adid with crafted sigs:
        # crafted calls are never 'booked' (slice 92) and pollute the record
        # the device's own install is about to join.
        ref2, hop2 = click_tracker(link, gps, F.UA, dev)
        print("CLICK-ONLY referrer:", ref2, flush=True)
        print("gps used:", gps, flush=True)
        print("Now install the app on the device with this adid; read the",
              "verdict on-device (AdjustAttribution), not via crafted polls.",
              flush=True)
        json.dump({"gps": gps, "referrer": ref2, "reftag": (
            ref2.split("adjust_reftag=", 1)[1].split("&")[0]
            if ref2 and "adjust_reftag=" in ref2 else "-")},
            open(os.path.join(HERE, "run_funnel_result.json"), "w"), indent=1)
        return
    if ref_pasted:
        ref = ref_pasted
        print("REFERRER (pasted, click skipped):", ref, flush=True)
    else:
        ref, hop = click_tracker(link, gps, F.UA, dev)
        print("REFERRER:", ref, flush=True)
        assert ref and "adjust_reftag=" in ref, "tracker gave no referrer"
    reftag = (ref.split("adjust_reftag=", 1)[1].split("&")[0]
              if "adjust_reftag=" in ref else "-")
    t_track = int(t_click)
    try:
        import installtimenew
        _loc = dev.get("locale") or {}
        _ram = dev.get("ram") or {}
        _idev = {
            "locale": {"country": _loc.get("country")
                       or dev.get("country") or "TR"},
            "ram": {"shown": (_ram.get("shown") if isinstance(_ram, dict)
                              else _ram) or dev.get("ram_shown") or "8192"},
            "os_version": str(dev.get("os_version", "16")),
        }
        _times = installtimenew.main({"click_time": float(t_click)},
                                     _idev, 79)
        _ins, _tb = _times["install_complete_time"], _times["download_end_time"]
        print("human-timing: browse_end=%.0f download_end=%.0f "
              "installed=%.0f (CTIT %.0fs, slept in real time)" % (
                  _times["download_begin_time"], _tb, _ins,
                  _ins - _times["click_time"]), flush=True)
    except Exception as e:
        print("human-timing fallback (+37s): %s" % str(e)[:100], flush=True)
        _ins, _tb = t_track + 37, t_track + 30
    ins = F.fmt(int(_ins), int((_ins % 1) * 1000))
    tb = int(_tb)
    import random as _rnd
    _open = _rnd.uniform(25, 75)  # human first-open delay after install
    print("first-open delay: %.0fs..." % _open, flush=True)
    time.sleep(_open)

    print("STEP 2/4 session...", flush=True)
    s2, r2 = F.api_session(gps, auid, ins)
    print("SESSION:", s2, r2[:200], flush=True)
    time.sleep(3)

    print("STEP 3/4 sdk_click...", flush=True)
    s1, r1 = F.api_sdk_click(gps, auid, ref, t_track, tb, ins)
    print("CLICK:", s1, r1[:200], flush=True)
    time.sleep(3)

    print("STEP 4/4 attribution x2...", flush=True)
    ptoken = ("e" + secrets.token_urlsafe(24) + ":APA91b"
              + secrets.token_urlsafe(96))
    try:
        _ask = json.loads(r2).get("ask_in", 0) or 0
    except Exception:
        _ask = 0
    try:
        _ask = max(_ask, json.loads(r1).get("ask_in", 0) or 0)
    except Exception:
        pass
    _ib = "backend" if _ask else "sdk"
    if _ask:
        _wait = min(_ask / 1000.0, 180.0)
        print("ask_in=%dms -> initiated_by=backend, waiting %.0fs%s..."
              % (_ask, _wait, " (capped)" if _ask / 1000.0 > 180 else ""),
              flush=True)
        time.sleep(_wait)
    else:
        print("no ask_in -> initiated_by=sdk", flush=True)
    s3, r3 = F.api_attribution(gps, auid, ptoken, _ib)
    print("ATTR:", s3, r3[:600], flush=True)

    time.sleep(4)
    s3, r3 = F.api_attribution(gps, auid, ptoken, _ib)
    print("ATTR:", s3, r3[:2000], flush=True)

    time.sleep(4)

    s3, r3 = F.api_attribution(gps, auid, ptoken, _ib)
    print("ATTR:", s3, r3[:2000], flush=True)

    time.sleep(4)

    s3, r3 = F.api_attribution(gps, auid, ptoken, _ib)
    print("ATTR:", s3, r3[:2000], flush=True)

    try:
        a = json.loads(r3)["attribution"]
        net = "%s/%s" % (a.get("tracker_token"), a.get("network"))
    except Exception:
        net = "?"
    print("VERDICT (crafted poll, UNRELIABLE):", net, flush=True)
    print("  slice 92: crafted signatures always receive the silent Organic")
    print("  record, even when the record IS non-organic. Authoritative verdict:")
    print('  adb shell "/debug_ramdisk/su -c \'cat /data/data/com.penti.app/'
          'files/AdjustAttribution\'"')
    print("  (on the device whose adid matches this gps, after ITS OWN install)")
    print("  or replay a freshly captured genuine signed request verbatim.")
    json.dump({"gps": gps, "auid": auid, "reftag": reftag,
               "referrer": ref, "session": [s2, r2[:300]],
               "click": [s1, r1[:300]], "attr": [s3, r3[:2000]],
               "verdict_crafted_unreliable": net},
              open(os.path.join(HERE, "run_funnel_result.json"), "w"),
              indent=1)


if __name__ == "__main__":
    main()
