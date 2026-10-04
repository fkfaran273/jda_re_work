"""decisive_fresh_ip.py - decisive test: Python signer on a FRESH IP + device read.

Flow (all from the PC = one fresh IP):
  1. fresh GAID + fresh android_uuid
  2. click from the PC with the GAID stamped
  3. Python-minted /session (lawful region)
  4. Python-minted /sdk_click (the referrer from step 2)
  5. set GAID on the moto, wipe app, launch -> the app reads the record
     (sticky: booked stays booked; not-booked cannot be re-booked later)
"""
import base64
import datetime as dt
import http.client
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from region_synth import synth_region, check

SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
GMS_XML = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
OUT = os.path.join(HERE, "decisive_result.json")
MARKER = "cline_fresh1"
LOG = {}


def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)


def adb(*a, t=40):
    r = subprocess.run(["adb", "-s", SERIAL] + list(a), capture_output=True, timeout=t)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return adb("shell", '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2)


def set_gaid(new):
    cur = su("cat %s" % GMS_XML)
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    if not m:
        return None
    b64 = base64.b64encode(cur.replace(m.group(0), new).encode()).decode()
    su("echo %s | base64 -d > /data/local/tmp/adid_new.xml && "
       "cat /data/local/tmp/adid_new.xml > %s" % (b64, GMS_XML))
    su("am force-stop com.google.android.gms")
    return m.group(0)


def plus0530(ts, ms=0):
    d = (dt.datetime.fromtimestamp(ts, dt.timezone.utc)
         + dt.timedelta(hours=5, minutes=30))
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)


def ws_bytes(words):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in words)


def synth_bytes():
    d0, d2, d4 = synth_region()
    assert check(d0, d4)
    return ws_bytes(d0), ws_bytes([d2]), ws_bytes(d4)


UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
LINK = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
        "&creative=penti_generic&click_id={click_id}&idfa={sub3}"
        "&install_callback=http%3A%2F%2Fec2-13-126-162-113.ap-south-1"
        ".compute.amazonaws.com%2Fapi%2Ftrack%2Fv1%2Fpostback%3Fclick_id%3D"
        "{click_id}%26p_sub1%3Dadjust%26advertising_id%3Dvkmdigital"
        "%26offer_id%3Dpntvkmdup1mdu%26offer_id%3Dpntvkmdup1mmp")


def fire_click(gps, marker):
    url = (LINK.replace("{click_id}", gps).replace("{sub3}", gps)
           .replace("creative=penti_generic", "creative=" + marker))
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=25)
    path = url[url.index("/1sd1lk6a"):]
    conn.putrequest("GET", path, skip_accept_encoding=1)
    conn.putheader("User-Agent", "Mozilla/5.0 (Linux; Android 12; moto g42)")
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    loc = r.getheader("Location") or ""
    code = r.status
    conn.close()
    m = re.search(r"adjust_reftag=([A-Za-z0-9+/=_-]+)", body + loc)
    return code, (m.group(0) if m else None)


def send(method, path, params, blob=None, timeout=25):
    q = urllib.parse.urlencode(params)
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=timeout)
    if method == "GET":
        conn.putrequest("GET", path + ("?" + q if q else ""), skip_accept_encoding=1)
        conn.putheader("Content-Length", "0")
    else:
        conn.putrequest("POST", path, skip_accept_encoding=1)
        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
        conn.putheader("Content-Length", str(len(q.encode())))
    conn.putheader("Client-SDK", "android5.7.0")
    if blob:
        conn.putheader("Authorization", F.auth_header(blob))
    conn.putheader("User-Agent", UA)
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    if method == "POST":
        conn.send(q.encode())
    r = conn.getresponse()
    out = (r.status, r.read().decode("utf-8", "replace"))
    conn.close()
    return out


def main():
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    log("identity", "gps=%s auid=%s" % (gps, auid))
    log("ip_check", subprocess.run(
        ["python", "-X", "utf8", "-c",
         "import urllib.request; print(urllib.request.urlopen('https://api.ipify.org',"
         " timeout=10).read().decode())"],
        capture_output=True, text=True).stdout.strip())

    code, ref = fire_click(gps, MARKER)
    if not ref:
        # fallback: the campaign's proven clicker
        try:
            import farm_win as fw
            code, ref, hops, url = fw.fire_click(gps, MARKER, None)
        except Exception as e:
            print("click fallback failed:", type(e).__name__, str(e)[:120])
    log("click", "%s reftag=%s" % (code, (ref or "")[:50]))
    if not ref:
        print("click produced no referrer; abort"); return

    now = time.time()
    val = {
        "gps_adid": gps, "android_uuid": auid,
        "api_level": "31", "app_version": "3.13.9",
        "app_token": "jut9tib0eeps",
        "os_name": "android", "os_version": "12",
        "device_name": "moto g42", "device_type": "phone",
        "device_manufacturer": "motorola",
        "environment": "production", "package_name": "com.penti.app",
        "hardware_name": "S2SE32.28-28-4", "os_build": "S2SE32.28-28-4",
        "language": "tr", "cpu_type": "arm64-v8a",
        "screen_size": "normal", "screen_format": "long",
        "screen_density": "high",
        "display_width": "1080", "display_height": "2237",
        "connectivity_type": "1", "ui_mode": "1", "foreground": "1",
        "tracking_enabled": "1", "gps_adid_src": "service",
        "gps_adid_attempt": "1", "needs_response_details": "1",
        "attribution_deeplink": "1", "offline_mode_enabled": "0",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "adj_signing_id": "1500000", "headers_id": "10",
        "native_version": "5.0.0", "algorithm": "adj9",
        "client_sdk": "android5.7.0",
        "initiating_package_name": "com.android.vending",
        "store_name_from_system": "com.android.vending",
        "enqueue_size": "0", "wait_total": "0.0", "wait_time": "0.0",
        "first_error": "0", "last_error": "0", "retry_count": "0",
        "created_at": plus0530(now, 100), "sent_at": plus0530(now, 130),
        "installed_at": plus0530(now - 2, 200),
        "updated_at": plus0530(now - 2, 200),
        "session_count": "1", "activity_kind": "session",
        "initiated_by": "sdk",
    }
    sec = int(now)
    d0b, d2b, d4b = synth_bytes()
    st, blob, desc, unp = F.make_signature_law(val, "session", second=sec,
                                               d0=d0b, d2=d2b, d4=d4b)
    log("session/mint", "%s #10=%dB blob=%dB" % (st, unp, len(blob)))
    p = dict(val)
    p["ask_in"] = "2000"
    c, b = send("POST", "/session", p, blob)
    log("session/send", "%s %s" % (c, b[:200]))

    time.sleep(2)
    now2 = time.time()
    cv = dict(val)
    cv.update({"activity_kind": "click", "google_play_instant": "0",
               "referrer": ref, "referrer_api": "google",
               "source": "install_referrer", "session_length": "0",
               "subsession_count": "1", "time_spent": "0",
               "created_at": plus0530(now2, 100), "sent_at": plus0530(now2, 130),
               "session_count": "1"})
    sd0, sd2, sd4 = synth_bytes()
    st2, blob2, _, n2 = F.make_signature_law(cv, "click", second=int(now2),
                                             d0=sd0, d2=sd2, d4=sd4)
    c2, b2 = send("POST", "/sdk_click", cv, blob2)
    log("sdk_click/send", "%s %s" % (c2, b2[:200]))

    # DEVICE READ: set the GAID, wipe the app, launch -> app reads the record
    old = set_gaid(gps)
    log("gaid_set", "%s -> %s" % (old, gps))
    su("am force-stop %s" % PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs /data/data/%s/databases"
       % (PKG, PKG, PKG))
    adb("shell", "am start -n %s/.ui.main.MainActivity" % PKG)
    verdict = None
    for k in range(8):
        time.sleep(12)
        raw = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null" % PKG)
        m = re.search(r'\{"tracker_token.*?\}', raw)
        if m:
            try:
                verdict = json.loads(m.group(0) + "}")
            except Exception:
                pass
            break
    log("verdict", json.dumps(verdict)[:300] if verdict else "none")
    if verdict:
        net = verdict.get("network")
        print("\n=== RESULT: %s ===" % ("NON-ORGANIC — PYTHON BOOKED!" if net != "Organic"
                                        else "ORGANIC (python session did not book)"))
    json.dump(LOG, open(OUT, "w"), indent=1)
    print("saved", OUT)


if __name__ == "__main__":
    main()

