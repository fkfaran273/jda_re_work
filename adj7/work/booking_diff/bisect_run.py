"""bisect_run.py -- controlled experiments: which single change turns the
Organic funnel into the booked non-organic?

    python bisect_run.py E2      # python click, PLAIN url, verbatim hops
    python bisect_run.py E3      # curl_cffi click, funnel url, verbatim hops
    python bisect_run.py E4      # full golden-shape: moto g42 coherent story
    python bisect_run.py E5      # E2 + golden-shape install (server-times,
                                 #  no push_token/init_pkg, golden order)
    python bisect_run.py E6      # curl_cffi + PLAIN url + moto install
                                 #  (E3+E4 combined)

Each experiment: fresh GAID -> click chain (hop-logged) -> CTIT wall clock ->
POST /session -> POST /sdk_click -> GET /attribution (-> +30s poll).
Only writes inside work/booking_diff/.
"""
import gzip
import http.client
import json
import os
import re
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
sys.path.insert(0, ADJ7)

import run_install as ri          # builders, call(), signing helpers
from adj7_pure import mint_adj7

MOBILE_GAID_URL = ("http://clicks.mobpine.com/api/track/v1/click"
                   "?aff_id=3&offer_id=23483498")
FUNNEL_URL = (MOBILE_GAID_URL + "&sub3={gaid}&sub2=zt1")

# golden-shape device story (payrupik_new capture: moto g42, Android 12, IN)
DEVICE_MOTO = {
    "api_level": "31", "os_version": "12",
    "device_name": "moto g42", "device_manufacturer": "motorola",
    "hardware_name": "S2SE32.28-28-4", "os_build": "S2SE32.28-28-4",
    "language": "en", "country": "IN",
    "display_width": "1080", "display_height": "2237",
    "screen_density": "high", "screen_size": "normal", "screen_format": "long",
    "cpu_type": "arm64-v8a", "connectivity_type": "1",
    "device_type": "phone", "environment": "production",
    "timezone": "+0530",
}

CHROME_UA_MOTO = ("Mozilla/5.0 (Linux; Android 12; moto g42) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/131.0.0.0 Mobile Safari/537.36")

results = []


def stamp(ts, ms, tz="+0530"):
    sign = 1 if tz[0] != "-" else -1
    off = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(ts + off, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms) + "Z" + tz


def log(*p):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), " ".join(str(x) for x in p)))
    sys.stdout.flush()


# ---------------------------------------------------------------- click
def click_chain(url, transport, ua=None, verbatim=True, gaid=None):
    """Follow the tracker chain hop by hop.  verbatim=True = a real browser:
    never edit the Location.  Returns (referrer_or_None, hops)."""
    hops = []
    headers = dict(ri.BROWSER_HEADERS)
    if ua:
        headers["User-Agent"] = ua
    for _ in range(12):
        if not url.startswith(("http://", "https://")):
            hops.append({"url": url, "status": "non-http"})
            if "adjust_reftag" in url:
                return urllib.parse.unquote(
                    url.split("referrer=", 1)[1]), hops
            return None, hops
        try:
            if transport == "curl":
                from curl_cffi import requests as cr
                r = cr.get(url, impersonate="chrome131_android",
                           allow_redirects=False, timeout=20)
                status, loc = r.status_code, r.headers.get("Location", "")
            else:
                sp = urllib.parse.urlsplit(url)
                cls = (http.client.HTTPSConnection if sp.scheme == "https"
                       else http.client.HTTPConnection)
                c = cls(sp.hostname, 443 if sp.scheme == "https" else 80,
                        timeout=20)
                path = (sp.path or "/") + (("?" + sp.query) if sp.query else "")
                c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
                for k, v in headers.items():
                    c.putheader(k, v)
                c.putheader("Host", sp.hostname)
                c.endheaders()
                resp = c.getresponse()
                status, loc = resp.status, resp.getheader("Location") or ""
                resp.read()
                c.close()
        except Exception as exc:
            hops.append({"url": url[:120], "status": "ERR %r" % exc})
            return None, hops
        hops.append({"url": url[:150], "status": status, "loc": loc[:200]})
        log("  hop %s %s" % (status, url[:110]))
        if status in (301, 302, 303, 307, 308) and loc:
            if verbatim:
                url = urllib.parse.urljoin(url, loc)
            else:                       # the funnel's mangling
                loc = loc.replace("&ip_address=%7Bloop_id%7D", "")
                loc = ri._fill_device_id(loc, gaid)
                m = ri._reftag_in(loc)
                if m:
                    return m, hops
                url = loc
            continue
        break
    # reftag from the last Location chain
    for h in reversed(hops):
        for cand in (h.get("loc"), h["url"]):
            if cand and "adjust_reftag" in cand:
                return urllib.parse.unquote(
                    cand.split("referrer=", 1)[1].split(";S.")[0]), hops
    return None, hops


# -------------------------------------------------------------- install
def build_session(gaid, auuid, sec, click_sec, dev, push_token,
                  partner, golden_order=False):
    inst = stamp(click_sec + 42, 629)
    f = {
        "store_name_from_system": "com.android.vending",
        "gps_adid_attempt": "1", "country": dev["country"],
        "api_level": dev["api_level"], "hardware_name": dev["hardware_name"],
        "app_version": ri.APP_VERSION, "app_token": ri.APP_TOKEN,
        "installed_at": inst, "created_at": stamp(sec, 198),
        "wait_total": "0.0", "device_type": "phone",
        "language": dev["language"], "gps_adid": gaid, "foreground": "1",
        "connectivity_type": "1", "device_manufacturer":
            dev["device_manufacturer"],
        "display_width": dev["display_width"], "device_name":
            dev["device_name"],
        "needs_response_details": "1", "os_build": dev["os_build"],
        "updated_at": inst, "cpu_type": dev["cpu_type"], "retry_count": "0",
        "screen_size": "normal", "screen_format": "long", "last_error": "0",
        "gps_adid_src": "service", "wait_time": "0.0",
        "os_version": dev["os_version"], "first_error": "0",
        "push_token": push_token, "partner_params": partner,
        "initiating_package_name": "com.android.vending",
        "android_uuid": auuid, "sent_at": stamp(sec, 523),
        "offline_mode_enabled": "0", "environment": "production",
        "screen_density": "high", "attribution_deeplink": "1",
        "session_count": "1", "display_height": dev["display_height"],
        "package_name": ri.PACKAGE_NAME, "os_name": "android", "ui_mode": "1",
        "enqueue_size": "0", "tracking_enabled": "1",
    }
    if golden_order:                 # payrupik_new wire order, no push_token
        f.pop("push_token")
        items = [("store_name_from_system", f["store_name_from_system"]),
                 ("gps_adid_attempt", "1"), ("country", f["country"]),
                 ("api_level", f["api_level"]),
                 ("hardware_name", f["hardware_name"]),
                 ("partner_params", partner), ("app_version", f["app_version"]),
                 ("app_token", f["app_token"]), ("installed_at", inst),
                 ("created_at", f["created_at"]), ("wait_total", "0.0"),
                 ("device_type", "phone"), ("language", f["language"]),
                 ("gps_adid", gaid), ("foreground", "1"),
                 ("connectivity_type", "1"),
                 ("device_manufacturer", f["device_manufacturer"]),
                 ("display_width", f["display_width"]),
                 ("device_name", f["device_name"]),
                 ("needs_response_details", "1"), ("os_build", f["os_build"]),
                 ("updated_at", inst), ("cpu_type", f["cpu_type"]),
                 ("retry_count", "0"), ("screen_size", "normal"),
                 ("screen_format", "long"), ("last_error", "0"),
                 ("gps_adid_src", "service"), ("wait_time", "0.0"),
                 ("os_version", f["os_version"]), ("first_error", "0"),
                 ("android_uuid", auuid), ("sent_at", f["sent_at"]),
                 ("offline_mode_enabled", "0"),
                 ("environment", "production"), ("screen_density", "high"),
                 ("attribution_deeplink", "1"), ("session_count", "1"),
                 ("display_height", f["display_height"]),
                 ("package_name", f["package_name"]),
                 ("initiating_package_name", "com.android.vending"),
                 ("os_name", "android"), ("ui_mode", "1"),
                 ("enqueue_size", "0"), ("tracking_enabled", "1")]
        return dict(items)
    return f


def build_sdk_click(gaid, auuid, sec, click_sec, referrer, dev,
                    server_times=False, with_init_pkg=False,
                    golden_order=False):
    click_time = stamp(click_sec, 0)
    begin_time = stamp(click_sec + 1, 0)
    f = {
        "country": dev["country"], "api_level": dev["api_level"],
        "hardware_name": dev["hardware_name"], "app_version": ri.APP_VERSION,
        "app_token": ri.APP_TOKEN,
        "installed_at": stamp(click_sec + 42, 629),
        "device_type": "phone", "language": dev["language"],
        "gps_adid": gaid, "source": "install_referrer", "foreground": "1",
        "connectivity_type": "1", "os_build": dev["os_build"],
        "click_time": click_time, "cpu_type": dev["cpu_type"],
        "install_version": ri.APP_VERSION,
        "partner_params": ri.PARTNER_PARAMS,
        "screen_size": "normal", "gps_adid_src": "service",
        "subsession_count": "1", "sent_at": stamp(sec, 263),
        "offline_mode_enabled": "0", "screen_density": "high",
        "session_count": "1", "ui_mode": "1", "gps_adid_attempt": "1",
        "session_length": "0", "created_at": stamp(sec, 252),
        "referrer_api": "google", "device_manufacturer":
            dev["device_manufacturer"],
        "display_width": dev["display_width"], "time_spent": "0",
        "device_name": dev["device_name"], "needs_response_details": "1",
        "updated_at": stamp(click_sec + 42, 629), "screen_format": "long",
        "os_version": dev["os_version"], "google_play_instant": "0",
        "android_uuid": auuid, "referrer": referrer,
        "environment": "production", "attribution_deeplink": "1",
        "install_begin_time": begin_time,
        "display_height": dev["display_height"],
        "package_name": ri.PACKAGE_NAME, "os_name": "android",
        "tracking_enabled": "1",
    }
    if with_init_pkg:
        f["initiating_package_name"] = "com.android.vending"
    if server_times:
        f["click_time_server"] = click_time
        f["install_begin_time_server"] = begin_time
    if golden_order:
        ordered = ["country", "api_level", "hardware_name", "app_version",
                   "app_version", "partner_params", "app_token",
                   "installed_at", "device_type", "language", "gps_adid",
                   "source", "foreground", "connectivity_type", "os_build",
                   "click_time", "cpu_type", "install_version", "screen_size",
                   "gps_adid_src", "subsession_count", "sent_at",
                   "offline_mode_enabled", "screen_density", "session_count",
                   "ui_mode", "gps_adid_attempt", "session_length",
                   "created_at", "referrer_api", "device_manufacturer",
                   "display_width", "time_spent", "device_name",
                   "needs_response_details", "updated_at", "screen_format",
                   "click_time_server", "os_version", "google_play_instant",
                   "install_begin_time_server", "android_uuid", "referrer",
                   "environment", "attribution_deeplink", "install_begin_time",
                   "display_height", "package_name", "os_name",
                   "tracking_enabled"]
        seen = set()
        out = {}
        for k in ordered:
            if k in f and k not in seen:
                out[k] = f[k]
                seen.add(k)
        return out
    return f


def build_event(gaid, auuid, sec, dev):
    return {
        "country": dev["country"], "api_level": dev["api_level"],
        "hardware_name": dev["hardware_name"], "app_version": ri.APP_VERSION,
        "app_token": ri.APP_TOKEN, "wait_total": "0.0",
        "device_type": "phone", "language": dev["language"],
        "gps_adid": gaid, "foreground": "1", "connectivity_type": "1",
        "os_build": dev["os_build"], "cpu_type": dev["cpu_type"],
        "retry_count": "0", "screen_size": "normal", "gps_adid_src": "service",
        "subsession_count": "1", "wait_time": "0.0", "first_error": "0",
        "sent_at": stamp(sec, 351), "offline_mode_enabled": "0",
        "screen_density": "high", "session_count": "1", "ui_mode": "1",
        "enqueue_size": "0", "gps_adid_attempt": "1", "event_count": "1",
        "session_length": "5", "created_at": stamp(sec, 343),
        "device_manufacturer": dev["device_manufacturer"],
        "display_width": dev["display_width"], "event_token": "y3sjx5",
        "time_spent": "5", "device_name": dev["device_name"],
        "needs_response_details": "1", "screen_format": "long",
        "last_error": "0", "seq": "1", "os_version": dev["os_version"],
        "callback_params": json.dumps({"google_adid": gaid},
                                      separators=(",", ":")),
        "android_uuid": auuid, "environment": "production",
        "attribution_deeplink": "1", "display_height":
            dev["display_height"],
        "package_name": ri.PACKAGE_NAME, "os_name": "android",
        "tracking_enabled": "1",
    }


def sign_and_post(label, kind, fields, method, path, sec):
    # the py27 runner's proven path: the campaign dict goes straight into
    # the signer (mint_adj7 returns the Authorization VALUE, no blob tuple)
    auth = mint_adj7(kind, fields, unix_sec=sec, include_block2=True,
                     campaign=ri.CAMPAIGN)
    status, body = ri.call(method, path, fields, auth)
    log("%s -> HTTP %d %s" % (label, status, body[:130]))
    return status, body


def run_experiment(name, click_transport, url_mode, click_ua, verbatim,
                   device, server_times, with_init_pkg, push_token,
                   golden_order, send_event, ctit):
    gaid = str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    partner = json.dumps({"payrupik_c_id": str(uuid.uuid4())},
                         separators=(",", ":"))
    # the install UA must tell the SAME story as the body fields
    ri.APP_UA = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
                 % (device["os_version"], device["device_name"],
                    device["os_build"]))
    print("=" * 78)
    log("EXPERIMENT %s  gaid=%s" % (name, gaid))
    log("  click: transport=%s url=%s ua=%s verbatim=%s"
        % (click_transport, url_mode, "moto" if click_ua == "moto"
           else ("funnel" if click_ua == "funnel" else click_ua), verbatim))
    log("  install: device=%s ua=%r server_times=%s init_pkg=%s push=%s "
        "golden_order=%s event=%s ctit=%ss"
        % (device["device_name"], ri.APP_UA, server_times, with_init_pkg,
           push_token[:8] + "..", golden_order, send_event, ctit))
    url = (FUNNEL_URL.replace("{gaid}", gaid) if url_mode == "funnel"
           else MOBILE_GAID_URL)
    ua = {"moto": CHROME_UA_MOTO, "funnel": ri.BROWSER_UA}.get(click_ua,
                                                               click_ua)
    T0 = int(time.time())
    referrer, hops = click_chain(url, click_transport, ua, verbatim, gaid)
    log("click reftag: %s" % (referrer,))
    if not referrer:
        results.append({"exp": name, "result": "no reftag"})
        return
    log("installing... CTIT %ss" % ctit)
    time.sleep(max(0, T0 + ctit - int(time.time())))
    sec = int(time.time()) - 2
    s = build_session(gaid, auuid, sec, T0, device, push_token, partner,
                      golden_order)
    status, body = sign_and_post("session", "session", s, "POST", "/session",
                                 sec)
    try:
        adid = json.loads(body).get("adid", "")
    except Exception:
        adid = "?"
    time.sleep(0.05)
    sec2 = int(time.time()) - 2
    c = build_sdk_click(gaid, auuid, sec2, T0, referrer, device,
                        server_times, with_init_pkg, golden_order)
    sign_and_post("sdk_click", "click", c, "POST", "/sdk_click", sec2)
    time.sleep(2.8)
    a = dict(ri.build_attribution_request(gaid, auuid, int(time.time()) - 2))
    a["api_level"] = device["api_level"]
    a["os_version"] = device["os_version"]
    a["device_name"] = device["device_name"]
    sec3 = int(time.time()) - 2
    _st, body = sign_and_post("attribution", "attribution", a, "GET",
                              "/attribution", sec3)
    verdict = (json.loads(body).get("attribution") or {}) \
        if body.startswith("{") else {}
    if verdict.get("network", "Organic") == "Organic":
        log("poll +30s ...")
        time.sleep(30)
        a2 = dict(ri.build_attribution_request(gaid, auuid,
                                               int(time.time()) - 2))
        a2["api_level"] = device["api_level"]
        a2["os_version"] = device["os_version"]
        a2["device_name"] = device["device_name"]
        _st, body = sign_and_post("attribution2", "attribution", a2, "GET",
                                  "/attribution", int(time.time()) - 2)
        verdict = (json.loads(body).get("attribution") or verdict) \
            if body.startswith("{") else verdict
    if send_event and verdict:
        sec4 = int(time.time()) - 2
        e = build_event(gaid, auuid, sec4, device)
        sign_and_post("event", "event", e, "POST", "/event", sec4)
    log("VERDICT %s: %s / %s / %s" % (name, verdict.get("network"),
                                      verdict.get("tracker_token"),
                                      verdict.get("tracker_name")))
    results.append({"exp": name, "gaid": gaid, "reftag": referrer,
                    "adid": adid, "verdict": verdict})
    with open(os.path.join(HERE, "bisect_results.json"), "w") as f:
        json.dump(results, f, indent=1)


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else ""
    funnel_dev = dict(ri.DEVICE)
    if which == "E2":
        # python click, PLAIN url (no sub2/zt1, no injected gps_adid),
        # verbatim Chrome-style hops, otherwise the standard funnel install
        run_experiment("E2", "python", "plain", "funnel", True,
                       funnel_dev, False, True, ri.PUSH_TOKEN, False,
                       False, 88)
    elif which == "E3":
        # curl_cffi chrome131_android click, funnel url (zt1 + gps_adid),
        # verbatim, standard GM1901 install
        run_experiment("E3", "curl", "funnel", "funnel", True,
                       funnel_dev, False, True, ri.PUSH_TOKEN, False,
                       False, 88)
    elif which == "E4":
        # FULL golden shape: moto click UA, moto device install,
        # server times, no push_token, golden order, event sent
        run_experiment("E4", "curl", "plain", "moto", True,
                       DEVICE_MOTO, True, False, ri.PUSH_TOKEN, True,
                       True, 88)
    elif which == "E5":
        # python click + golden-shape INSTALL only (server times, order,
        # no push/init_pkg) with funnel UA and funnel url
        run_experiment("E5", "python", "funnel", "funnel", False,
                       DEVICE_MOTO, True, False, ri.PUSH_TOKEN, True,
                       False, 88)
    elif which == "E6":
        # curl click + PLAIN url + moto install: E3 click side + E4 shape
        run_experiment("E6", "curl", "plain", "moto", True,
                       DEVICE_MOTO, True, False, ri.PUSH_TOKEN, True,
                       False, 88)
    else:
        print("usage: bisect_run.py E2|E3|E4|E5|E6")


# ---------------------------------------------------------------- E8
def call_curl(method, path, fields, auth, ua):
    """ri.call over curl_cffi chrome131_android (device-grade TLS + h2),
    same app-header order as the genuine capture."""
    from curl_cffi import requests as cr
    body = urllib.parse.urlencode(fields).encode() if method == "POST" else None
    target = (path if method == "POST" else path + "?" +
              urllib.parse.urlencode(fields, quote_via=urllib.parse.quote))
    hdrs = [("Client-SDK", "android5.6.0"), ("Authorization", auth)]
    if body is not None:
        hdrs.append(("Content-Type", "application/x-www-form-urlencoded"))
    hdrs.append(("User-Agent", ua))
    hdrs.append(("Accept-Encoding", "gzip"))
    if body is not None:
        hdrs.append(("Content-Length", str(len(body))))
    r = cr.request(method, "https://app.adjust.com" + target, headers=hdrs,
                   data=body if body is not None else None,
                   impersonate="chrome131_android", timeout=30)
    raw = r.content
    if raw[:2] == bytes((0x1f, 0x8b)):
        raw = gzip.decompress(raw)
    return r.status_code, raw.decode("utf-8", "replace")


def run_experiment_e8():
    name = "E8-curl-install"
    gaid = str(uuid.uuid4())
    auuid = str(uuid.uuid4())
    partner = json.dumps({"payrupik_c_id": str(uuid.uuid4())},
                         separators=(",", ":"))
    device = DEVICE_MOTO
    ri.APP_UA = ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
                 % (device["os_version"], device["device_name"],
                    device["os_build"]))
    print("=" * 78)
    log("EXPERIMENT %s gaid=%s  (install over curl_cffi chrome131_android)"
        % (name, gaid))
    url = MOBILE_GAID_URL
    T0 = int(time.time())
    referrer, hops = click_chain(url, "curl", CHROME_UA_MOTO, True, gaid)
    log("click reftag: %s" % (referrer,))
    if not referrer:
        results.append({"exp": name, "result": "no reftag"})
        return
    time.sleep(max(0, T0 + 430 - int(time.time())))
    sec = int(time.time()) - 2
    s = build_session(gaid, auuid, sec, T0, device, ri.PUSH_TOKEN, partner,
                      True)
    auth = mint_adj7("session", s, unix_sec=sec, include_block2=True,
                     campaign=ri.CAMPAIGN)
    st, body = call_curl("POST", "/session", s, auth, ri.APP_UA)
    log("session -> HTTP %d %s" % (st, body[:110]))
    time.sleep(0.05)
    sec2 = int(time.time()) - 2
    c = build_sdk_click(gaid, auuid, sec2, T0, referrer, device,
                        True, False, True)
    auth2 = mint_adj7("click", c, unix_sec=sec2, include_block2=True,
                      campaign=ri.CAMPAIGN)
    st, body = call_curl("POST", "/sdk_click", c, auth2, ri.APP_UA)
    log("sdk_click -> HTTP %d %s" % (st, body[:110]))
    time.sleep(2.8)
    a = dict(ri.build_attribution_request(gaid, auuid, int(time.time()) - 2))
    a["api_level"] = device["api_level"]
    a["os_version"] = device["os_version"]
    a["device_name"] = device["device_name"]
    sec3 = int(time.time()) - 2
    auth3 = mint_adj7("attribution", a, unix_sec=sec3, include_block2=True,
                      campaign=ri.CAMPAIGN)
    st, body = call_curl("GET", "/attribution", a, auth3, ri.APP_UA)
    log("attribution -> HTTP %d %s" % (st, body[:200]))
    verdict = (json.loads(body).get("attribution") or {}) \
        if body.startswith("{") else {}
    if verdict.get("network", "Organic") == "Organic":
        log("poll +30s ...")
        time.sleep(30)
        a2 = dict(ri.build_attribution_request(gaid, auuid,
                                               int(time.time()) - 2))
        a2["api_level"] = device["api_level"]
        a2["os_version"] = device["os_version"]
        a2["device_name"] = device["device_name"]
        auth4 = mint_adj7("attribution", a2, unix_sec=int(time.time()) - 2,
                          include_block2=True, campaign=ri.CAMPAIGN)
        st, body = call_curl("GET", "/attribution", a2, auth4, ri.APP_UA)
        log("attribution2 -> HTTP %d %s" % (st, body[:200]))
        verdict = (json.loads(body).get("attribution") or verdict) \
            if body.startswith("{") else verdict
    log("VERDICT %s: %s / %s / %s" % (name, verdict.get("network"),
                                      verdict.get("tracker_token"),
                                      verdict.get("tracker_name")))
    results.append({"exp": name, "gaid": gaid, "reftag": referrer,
                    "verdict": verdict})
    with open(os.path.join(HERE, "bisect_results.json"), "w") as f:
        json.dump(results, f, indent=1)
