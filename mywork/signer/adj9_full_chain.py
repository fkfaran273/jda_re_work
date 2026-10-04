"""adj9_full_chain.py — adj9 signature + all 4 Adjust calls, one script.

Needs beside it: fin_vm2.py, header_gen.py, fin_descs.json, golden_saz.json
Usage:  python adj9_full_chain.py [link|profile] [profile]
  profiles: cph = OnePlus CPH2585 (default), poco = POCO 23122PCD1G
  poco uses the real adid + pasted tracker referrer (books on that id).
"""
import base64
import datetime
import gzip
import http.client
import json
import os
import secrets
import struct
import sys
import time
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header



APP_TOKEN = "jut9tib0eeps"
TRACKER = "https://app.adjust.com/1sd1lk6a"
CAMPAIGN = {"campaign": "AH", "adgroup": "vkm_0926_36",
            "creative": "penti_generic"}
UA = ("Dalvik/2.1.0 (Linux; U; Android 16; CPH2585 "
      "Build/CPH2585_16.0.5.702(EX01))")
DEV = {"api_level": "36", "os_version": "16", "device_name": "CPH2585",
       "device_manufacturer": "OnePlus", "hardware_name": "qcom",
       "os_build": "CPH2585_16.0.5.702(EX01)", "app_version": "3.13.9",
       "install_version": "3.13.9", "language": "tr", "mcc": "404",
       "mnc": "10", "display_width": "1080", "display_height": "2376",
       "screen_density": "xxhigh"}
POCO = {"api_level": "35", "os_version": "15",
        "device_name": "23122PCD1G", "device_manufacturer": "Xiaomi",
        "hardware_name": "qcom", "os_build": "AQ3A.240912.001",
        "app_version": "3.13.9", "install_version": "3.13.9",
        "language": "tr", "mcc": "286", "mnc": "02",
        "display_width": "1220", "display_height": "2560",
        "screen_density": "xxhigh"}
POCO_UA = ("Dalvik/2.1.0 (Linux; U; Android 15; 23122PCD1G "
           "Build/AQ3A.240912.001)")
DEFAULT_LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
                "&creative=penti_generic&click_id={click_id}&idfa={sub3}"
                "&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp"
                "&event_callback_bfi71x=http%3A%2F%2Fec2-13-126-162-113.ap-south-1.compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fevents%3Fclick_id%3D{click_id}%26goal%3Dbfi71x%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital%26offer_id%3Dpntvkmdup1mmp")
MOTO = {"api_level": "31", "os_version": "12", "device_name": "moto g42",
        "device_manufacturer": "motorola", "hardware_name": "S2SE32.28-28-4",
        "os_build": "S2SE32.28-28-4", "app_version": "3.13.9",
        "install_version": "3.13.9", "language": "tr", "mcc": "405",
        "mnc": "872", "display_width": "1080", "display_height": "2237",
        "screen_density": "high", "no_sim": True}
MOTO_UA = ("Dalvik/2.1.0 (Linux; U; Android 12; moto g42 "
           "Build/S2SE32.28-28-4)")
SAMSUNG = {"api_level": "33", "os_version": "13",
           "device_name": "SM-M526B", "device_manufacturer": "samsung",
           "hardware_name": "qcom", "os_build": "TP1A.220624.014",
           "app_version": "3.13.9", "install_version": "3.13.9",
           "language": "tr", "mcc": "286", "mnc": "03",
           "display_width": "1080", "display_height": "2271",
           "screen_density": "high"}
SAMSUNG_UA = ("Dalvik/2.1.0 (Linux; U; Android 13; SM-M526B "
              "Build/TP1A.220624.014)")
SAMSUNG_GPS = "9c39b6ca-f779-4d44-97c4-5d26677e7841"
SAMSUNG_REF = ("adjust_reftag=cAHE9yNSfVX9D&utm_source=VKM+Digital+Yeni"
               "&utm_campaign=AH&utm_content=vkm_0926_36"
               "&utm_term=penti_generic")
SAMSUNG_CLICK = 1789390573  # clicker timestamp (real click, TR residential)
XIAOMI = {"api_level": "36", "os_version": "16",
          "device_name": "2407FPN8EG", "device_manufacturer": "Xiaomi",
          "hardware_name": "qcom", "os_build": "BP2A.250605.015",
          "app_version": "3.13.9", "install_version": "3.13.9",
          "language": "tr", "mcc": "286", "mnc": "01",
          "display_width": "1220", "display_height": "2712",
          "screen_density": "xxxhigh"}
XIAOMI_UA = ("Dalvik/2.1.0 (Linux; U; Android 16; 2407FPN8EG "
             "Build/BP2A.250605.015)")
XIAOMI_GPS = "015a16da-9507-4d24-96e6-09cf4a901f2f"
XIAOMI_REF = ("adjust_reftag=cVUSAghyXZKai&utm_source=VKM+Digital+Yeni"
              "&utm_campaign=AH&utm_content=vkm_0926_36"
              "&utm_term=penti_generic")
POCO_GPS = "0d0b7778-956e-4ae6-9fd2-d59c032c6323"
POCO_REF = ("adjust_reftag=csD2mExrEMpLs&utm_source=VKM+Digital+Yeni"
            "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")
OFF_MINUTES, OFF_LABEL = 330, "+0530"  # poco switches to 120, "+0200"
MINT_SKEW, ZERO0, HRAND = -2, True, True  # present-tense, not future
ADD_IDFA = False  # xiaomi: click carried idfa= (no gps_adid) — send both

D = json.load(open(os.path.join(HERE, "fin_descs.json")))
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
GOLD = json.load(open(os.path.join(HERE, "golden_saz.json")))
S1P, S2P = GOLD["s1"]["params"], GOLD["s2"]["params"]


def fmt(ts, ms):  # wire stamp in profile tz
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=OFF_MINUTES))
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z{OFF_LABEL}").encode()


def swap_eq(data, old, new):  # equal-length only; logs misses
    if old is not None and new is not None and len(old) == len(new) \
            and data.count(old) >= 1:
        return data.replace(old, new)
    print("  ! swap SKIP %r -> %r" % (old, new))
    return data


def rep1(data, old, new):  # positional; any length (#7 tracks it)
    if data.count(old) >= 1:
        return data.replace(old, new, 1)
    print("  ! rep1 MISS %r" % old)
    return data


def make_signature(second, created, gps=None, auid=None, installed=None):
    """Mint one 192-B adj9 blob: Random3 header + FinEx body."""
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
          for d in D["descs"]}
    if HRAND:
        by[4] = (8, secrets.token_bytes(32))
    if ZERO0:
        by[0] = (36, bytes(144))
    # Claims stamps keep the caller's suffix VERBATIM (wire == signed input;
    # forcing +0200 once shipped wire+0530/claims+0200 mismatches, 3.5 h off).
    d10 = by[10][1].replace(b"2026-09-12T21:15:11.678Z+0200", created)
    if gps:
        d10 = swap_eq(d10, b"f476b3d4-e0b1-4707-bc43-6153d17f7f8c",
                      gps.encode())
    if auid:
        d10 = swap_eq(d10, b"d773f47f-fc0e-4994-9cf7-7c3cf5bb6368",
                      auid.encode())
    d10 = rep1(d10, b"moto g42", DEV["device_name"].encode())
    d10 = rep1(d10, b"S2SE32.28-28-4", DEV["hardware_name"].encode())
    d10 = rep1(d10, b"S2SE32.28-28-4", DEV["os_build"].encode())
    if DEV["app_version"] != "3.13.9":
        d10 = swap_eq(d10, b"3.13.9", DEV["app_version"].encode())
    d10 = swap_eq(d10, b"12com.penti.app",
                  (DEV["os_version"] + "com.penti.app").encode())
    d10 = swap_eq(d10, b"31jut9tib0eeps",
                  (DEV["api_level"] + "jut9tib0eeps").encode())
    if installed:
        ins = installed  # verbatim: same bytes go on the wire (see above)
        d10 = swap_eq(d10, b"2026-09-08T12:20:49.782Z+0200", ins)
        d10 = swap_eq(d10, b"2026-09-10T07:26:18.015Z+0200", ins)
    # NO com.android.vending12 swap: it eats the updated_at stamp's "2"
    by[7] = (1, struct.pack(">I", len(d10)))
    by[10] = (len(d10) // 4, d10)
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    status = ex.run(max_steps=20_000_000)
    sinks = defaultdict(dict)
    for (s, n, v) in ex.emit_trace:
        sinks[s][n] = v
    blob = b"".join(struct.pack(">I", sinks[0x5500000000].get(i, 0))
                    for i in range(48))
    assert blob[:16] == make_header(second)
    return status, ex.steps, blob


USE_PROXY = False  # run_funnel sets True: route via Fiddler 127.0.0.1:8888
USE_DEVICE = False  # run_funnel `via-device`: transport by the PHONE itself
NO_SIGN = False     # unsigned_test: send WITHOUT the Authorization header at all
                    # (the "non-adj9 app" control: does this app_token need adj9?)
PROXY_URL = "http://127.0.0.1:8888"


def _auth_header(blob):
    if NO_SIGN:
        return None
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())


def send_device(url, params, blob, method="POST"):
    """Same signed request, but transported by the DEVICE (`adb shell curl`).

    The call then leaves from the phone's IP + TLS stack instead of this PC's,
    which is the only transport variable never yet isolated between 'the app's
    own booked stream' and our PC sends (slice 97 §7).

    NOTE: `adb shell` concatenates its args into ONE remote shell command, so
    every part is shlex-quoted here — otherwise the `&` inside the urlencoded
    body is re-parsed by the device shell and the call hangs/breaks.
    """
    import shlex
    import subprocess
    auth = _auth_header(blob)
    parts = ["curl", "-s", "-S", "-k", "--max-time", "45", "-X", method,
             "-w", "\n###HTTP:%{http_code}",
             "-H", "Client-SDK: android5.7.0",
             "-H", "User-Agent: " + UA]
    if auth:
        parts += ["-H", "Authorization: " + auth]
    if method == "POST":
        parts += ["-H", "Content-Type: application/x-www-form-urlencoded"]
        parts += [url, "--data-raw", urllib.parse.urlencode(params)]
    else:
        sep = "&" if "?" in url else "?"
        parts += [url + sep + urllib.parse.urlencode(params)]
    remote = " ".join(shlex.quote(p) for p in parts)
    try:
        p = subprocess.run(["adb", "shell", remote], capture_output=True,
                           timeout=120)
        out = p.stdout.decode("utf-8", "replace")
        code = "ERR"
        if "###HTTP:" in out:
            out, code = out.rsplit("###HTTP:", 1)
            try:
                code = int(code.strip())
            except ValueError:
                pass
        if not out.strip() and p.stderr:
            return "ERR", p.stderr.decode("utf-8", "replace")[:200]
        return code, out
    except Exception as e:
        return "ERR", str(e)[:200]


def send_proxy(url, params, blob, method="POST"):
    """Same byte-exact headers as send(), but through the Fiddler proxy
    (curl_cffi, verify off for the Fiddler MITM cert)."""
    from curl_cffi import requests as cr
    auth = ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())
    headers = {"Client-SDK": "android5.7.0", "Authorization": auth}
    if method == "POST":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["User-Agent"] = UA
    headers["Connection"] = "Keep-Alive"
    headers["Accept-Encoding"] = "gzip"
    px = {"http": PROXY_URL, "https": PROXY_URL}
    try:
        if method == "POST":
            r = cr.post(url, data=params, headers=headers, proxies=px,
                        verify=False, timeout=30)
        else:
            r = cr.get(url, params=params, headers=headers, proxies=px,
                       verify=False, timeout=30)
        return r.status_code, r.text
    except Exception as e:
        return "ERR", str(e)[:200]


def send(url, params, blob, method="POST"):
    # byte-exact SAZ transport: header case+order via http.client
    # (urllib rewrites Client-SDK -> Client-Sdk and reorders).
    if USE_PROXY:
        return send_proxy(url, params, blob, method)
    if USE_DEVICE:
        return send_device(url, params, blob, method)
    import http.client
    auth = _auth_header(blob)
    pr = urllib.parse.urlsplit(url)
    try:
        conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
            conn.putrequest("POST", pr.path, skip_host=1,
                            skip_accept_encoding=1)
            conn.putheader("Client-SDK", "android5.7.0")
            if auth:
                conn.putheader("Authorization", auth)
            conn.putheader("Content-Type",
                           "application/x-www-form-urlencoded")
            conn.putheader("User-Agent", UA)
            conn.putheader("Host", pr.hostname)
            conn.putheader("Connection", "Keep-Alive")
            conn.putheader("Accept-Encoding", "gzip")
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
        else:
            # genuine OkHttp encodes the query with %20, not '+'
            path = pr.path + "?" + urllib.parse.urlencode(
                params, quote_via=urllib.parse.quote)
            conn.putrequest("GET", path, skip_host=1,
                            skip_accept_encoding=1)
            conn.putheader("Client-SDK", "android5.7.0")
            if auth:
                conn.putheader("Authorization", auth)
            conn.putheader("User-Agent", UA)
            conn.putheader("Host", pr.hostname)
            conn.putheader("Connection", "Keep-Alive")
            conn.putheader("Accept-Encoding", "gzip")
            conn.endheaders()
        resp = conn.getresponse()
        raw = resp.read()
        # we advertise gzip, so honour it instead of returning mojibake
        if raw[:2] == b"\x1f\x8b" or \
                (resp.getheader("Content-Encoding") or "").lower() == "gzip":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        data = raw.decode("utf-8", "replace")
        conn.close()
        return resp.status, data
    except Exception as e:
        return "ERR", str(e)[:200]


def mint_call(label, created_ms, gps, auid, installed=None, ims=774):
    sec = int(time.time()) + MINT_SKEW
    insb = installed if installed is not None else (
        fmt(sec - 170, ims) if ims else None)
    st, n, blob = make_signature(sec, fmt(sec - 1, created_ms), gps, auid,
                                 insb)
    print(label, "mint", st, n, "sec", sec)
    return sec, blob


def api_sdk_click(gps, auid, referrer, t_track, t_begin=None, ins=None):
    sec, blob = mint_call("click", 961, gps, auid, ins)
    insd = (ins or fmt(sec - 170, 774)).decode()
    tb = t_begin if t_begin is not None else t_track + 5
    p = dict(S2P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": fmt(sec - 1, 961).decode(),
              "sent_at": fmt(sec - 1, 970).decode(),
              "installed_at": insd,
              "updated_at": insd,
              "referrer": referrer, "source": "install_referrer",
              "referrer_api": "google",
              "click_time": fmt(t_track, 0).decode(),
              "click_time_server": fmt(t_track - 2, 0).decode(),
              "install_begin_time": fmt(tb, 0).decode(),
              "install_begin_time_server": fmt(tb - 2, 0).decode()})
    p.update(DEV)
    p.pop("no_sim", None)  # helper flag, never a wire param
    if DEV.get("no_sim"):
        p.pop("mcc", None)
        p.pop("mnc", None)
    if ADD_IDFA:
        p["idfa"] = gps
    return send("https://app.adjust.com/sdk_click", p, blob)


def api_session(gps, auid, ins=None):
    sec, blob = mint_call("session", 928, gps, auid, ins)
    insd = (ins or fmt(sec - 170, 774)).decode()
    p = dict(S1P)
    p.update({"gps_adid": gps, "android_uuid": auid,
              "created_at": fmt(sec - 1, 928).decode(),
              "sent_at": fmt(sec - 1, 942).decode(),
              "installed_at": insd,
              "updated_at": insd})
    p.update(DEV)
    p.pop("no_sim", None)  # helper flag, never a wire param
    if DEV.get("no_sim"):
        p.pop("mcc", None)
        p.pop("mnc", None)
    p.pop("install_version", None)  # 3.13.9 session has none (winner-proven)
    if ADD_IDFA:
        p["idfa"] = gps
    return send("https://app.adjust.com/session", p, blob)


def api_sdk_info(gps, auid, ptoken):
    sec, blob = mint_call("sdk_info", 550, gps, auid)
    p = {"gps_adid_attempt": "1", "wait_time": "0.0", "app_token": APP_TOKEN,
         "created_at": fmt(sec - 1, 550).decode(), "wait_total": "0.0",
         "first_error": "0", "gps_adid": gps, "source": "push",
         "foreground": "1", "android_uuid": auid,
         "sent_at": fmt(sec - 1, 665).decode(), "offline_mode_enabled": "0",
         "environment": "production", "needs_response_details": "1",
         "attribution_deeplink": "1", "retry_count": "0", "last_error": "0",
         "gps_adid_src": "service", "push_token": ptoken,
         "enqueue_size": "1", "tracking_enabled": "1"}
    return send("https://app.adjust.com/sdk_info", p, blob)


def api_attribution(gps, auid, ptoken, initiated_by="backend"):
    sec, blob = mint_call("attr", 666, gps, auid)
    p = {"initiated_by": initiated_by, "gps_adid_attempt": "1",
         "api_level": DEV["api_level"],
         "app_version": DEV["app_version"], "app_token": APP_TOKEN,
         "os_version": DEV["os_version"],
         "created_at": fmt(sec - 1, 666).decode(), "device_type": "phone",
         "gps_adid": gps, "foreground": "1",
         "android_uuid": auid, "sent_at": fmt(sec - 1, 696).decode(),
         "offline_mode_enabled": "0", "device_name": DEV["device_name"],
         "environment": "production", "needs_response_details": "1",
         "attribution_deeplink": "1", "package_name": "com.penti.app",
          "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
          "tracking_enabled": "1"}
    if ADD_IDFA:
        p["idfa"] = gps
    return send("https://app.adjust.com/attribution", p, blob, method="GET")


def tracker_referrer(gps, link=None):
    """Click the tracker (gps stamped on), follow hops, return referrer."""
    if link:
        parts = urllib.parse.urlsplit(link)
        q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    else:
        parts = urllib.parse.urlsplit(TRACKER)
        q = dict(CAMPAIGN)
    q["gps_adid"] = gps
    url = urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(q), parts.fragment))
    for _ in range(2):  # attempts
        hop = url
        for _ in range(4):  # hops
            pr = urllib.parse.urlsplit(hop)
            if pr.scheme == "market":
                break
            try:
                conn = http.client.HTTPSConnection(pr.hostname, 443,
                                                   timeout=30)
                conn.request(
                    "GET", urllib.parse.urlunsplit(
                        ("", "", pr.path or "/", pr.query, pr.fragment)),
                    headers={"User-Agent": UA, "Host": pr.hostname,
                             "Accept-Encoding": "identity",
                             "Connection": "close"})
                resp = conn.getresponse()
                resp.read()
                code, loc = resp.status, resp.getheader("Location", "")
                conn.close()
            except Exception as e:
                print("  tracker: %s %s" % (type(e).__name__, str(e)[:80]))
                break
            if code not in (301, 302, 303, 307, 308) or not loc:
                print("  tracker: HTTP %s, retrying" % code)
                break
            if "referrer=" in loc:
                return urllib.parse.unquote(
                    loc.split("referrer=", 1)[1]), hop
            hop = urllib.parse.urljoin(hop, loc)
        time.sleep(5)
    return None, hop


def main():
    global DEV, UA, OFF_MINUTES, OFF_LABEL, ADD_IDFA
    a1 = sys.argv[1] if len(sys.argv) > 1 else None
    a2 = sys.argv[2] if len(sys.argv) > 2 else None
    profile, link = ("cph", None)
    if a1 and not a1.startswith("http"):
        profile = a1
    else:
        link, profile = a1, (a2 or "cph")
    import re as _re
    gps_arg = next((a for a in sys.argv[1:]
                    if _re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12}", a or "")), None)
    poco = (profile == "poco")
    if poco:
        DEV, UA = dict(POCO), POCO_UA
        OFF_MINUTES, OFF_LABEL = 120, "+0200"
        print("PROFILE poco: REAL adid + REAL referrer")
    elif profile == "moto":
        DEV, UA = dict(MOTO), MOTO_UA
        print("PROFILE moto: whcap-native (body needs no device swaps)")
    samsung = (profile == "samsung")
    if samsung:
        DEV, UA = dict(SAMSUNG), SAMSUNG_UA
        OFF_MINUTES, OFF_LABEL = 120, "+0200"
        print("PROFILE samsung: REAL click/adid/referrer, pasted, no fetch")
    xiaomi = (profile == "xiaomi")
    if xiaomi:
        DEV, UA = dict(XIAOMI), XIAOMI_UA
        OFF_MINUTES, OFF_LABEL = 120, "+0200"
        print("PROFILE xiaomi: REAL click/adid/referrer, pasted, no fetch")
    gps = gps_arg or (POCO_GPS if poco else
                      (SAMSUNG_GPS if samsung else
                       (XIAOMI_GPS if xiaomi else str(uuid.uuid4()))))
    if gps_arg:
        print("gps override:", gps)
    auid = str(uuid.uuid4())
    ptoken = ("e" + secrets.token_urlsafe(24) + ":APA91b"
              + secrets.token_urlsafe(96))
    if link is None:
        link = None if (poco or samsung or xiaomi) else DEFAULT_LINK  # pasted ref
    if link:
        link = link.replace("{click_id}", "clk-" + uuid.uuid4().hex[:12])
        link = link.replace("{sub3}", gps)
    t_track = SAMSUNG_CLICK if samsung else (
        int(time.time()) - 600 if xiaomi else int(time.time()))
    print("gps", gps, "auid", auid, "track_t", t_track)
    env_ref = os.environ.get("ADJ_REF")
    if env_ref:
        ref = env_ref
        print("REFERRER (ADJ_REF):", ref)
    elif link is None and samsung:
        ref = SAMSUNG_REF
        print("REFERRER (pasted):", ref)
    elif link is None and xiaomi:
        ref = XIAOMI_REF
        print("REFERRER (pasted):", ref)
    elif link is None and poco:
        ref = POCO_REF
        print("REFERRER (pasted):", ref)
    else:
        ref, hop = tracker_referrer(gps, link)
        print("hop:", (hop or "")[:160])
        print("REFERRER:", ref)
        assert ref and "adjust_reftag=" in ref, "tracker gave no referrer"
    reftag = ref.split("adjust_reftag=", 1)[1].split("&")[0]
    print("reftag", reftag)

    # samsung/xiaomi: installed = real click +37s (winner: begin+7s), ms .431
    ins = fmt(t_track + 37, 431) if (samsung or xiaomi) else None
    tb = t_track + 30 if (samsung or xiaomi) else None
    s2, r2 = api_session(gps, auid, ins)  # SAZ order: session before click
    print("SESSION:", s2, r2[:200])
    time.sleep(3)
    if (samsung or xiaomi):
        s1, r1 = api_sdk_click(gps, auid, ref, t_track, tb, ins)
    else:
        s1, r1 = api_sdk_click(gps, auid, ref, t_track)
    print("CLICK:", s1, r1[:200])
    time.sleep(3)
    # NO sdk_info: the winning 3.13.9 install never sent one
    s2b, r2b = "SKIP", "not sent (winner has no sdk_info)"
    s3, r3 = api_attribution(gps, auid, ptoken)
    print("ATTR:", s3, r3[:2000])
    time.sleep(10)

    s3, r3 = api_attribution(gps, auid, ptoken)
    print("ATTR:", s3, r3[:2000])
    try:
        net = json.loads(r3)["attribution"]["network"]
    except Exception:
        net = "?"
    print("VERDICT:", net)
    json.dump({"profile": profile, "gps": gps, "auid": auid,
               "reftag": reftag, "referrer": ref,
               "session": [s2, r2[:300]], "click": [s1, r1[:300]],
               "sdk_info": [s2b, r2b[:200]], "attr": [s3, r3[:2000]],
               "verdict": net},
              open(os.path.join(HERE, "adj9_chain_result.json"), "w"),
              indent=1)


if __name__ == "__main__":
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8888'
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8888'
    main()
