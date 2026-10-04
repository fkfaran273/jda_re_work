"""py_tls_test.py - TLS fingerprint spoofing test (okhttp4_android_10 via tls_client)."""
import base64, datetime as dt, json, os, re, struct, subprocess, sys, time
import urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from region_synth import synth_region, check
import tls_client

SERIAL = "cc749213"
PKG = "com.penti.app"
GMS = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
OUT = os.path.join(HERE, "py_tls_result.json")
UA = "Mozilla/5.0 (Linux; Android 13; KB2001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.7922.47 Mobile Safari/537.36"
LOG = {}
REF = "adjust_reftag=PLACEHOLDER&utm_source=VKM+Digital+Yeni&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic"

def log(k, v):
    LOG[k] = v
    print("[%s] %s" % (k, v), flush=True)

def adb(*a, t=40):
    r = subprocess.run(["adb", "-s", SERIAL] + list(a), capture_output=True, timeout=t)
    return (r.stdout + r.stderr).decode("utf-8", "replace")

def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    return adb("shell", '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2_base(inner))

def b2_base(inner):
    import base64 as b
    return b.b64encode(inner.encode()).decode()

def set_gaid(new):
    cur = su("cat " + GMS)
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    if not m: return None
    b64 = base64.b64encode(cur.replace(m.group(0), new).encode()).decode()
    su("echo %s | base64 -d > /data/local/tmp/aid.xml && cat /data/local/tmp/aid.xml > %s" % (b64, GMS))
    su("am force-stop com.google.android.gms")
    return m.group(0)

def wipe_app():
    su("am force-stop " + PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs /data/data/%s/databases" % (PKG, PKG, PKG))

def device_click(gps, marker):
    url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
           "&creative=%s&click_id=%s&idfa=%s&gps_adid=%s" % (marker, gps, gps, gps))
    return adb("shell", "curl -s -o /dev/null -w '%%{http_code}' -L '%s' "
               "-H 'User-Agent: Mozilla/5.0 (Linux; Android 13; KB2001)'" % url).strip()

def plus0530(ts, ms=0):
    d = dt.datetime.fromtimestamp(ts, dt.timezone.utc) + dt.timedelta(hours=5, minutes=30)
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)

def ws_bytes(words):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in words)

def synth_bytes():
    d0, d2, d4 = synth_region()
    assert check(d0, d4)
    return ws_bytes(d0), ws_bytes([d2]), ws_bytes(d4)

def tls_send(method, path, params, blob=None):
    s = tls_client.Session(client_identifier="okhttp4_android_10", random_tls_extension_order=True)
    url = "https://app.adjust.com" + path
    headers = {"Client-SDK": "android5.7.0", "User-Agent": UA, "Accept-Encoding": "gzip"}
    if blob: headers["Authorization"] = F.auth_header(blob)
    if method == "GET":
        r = s.get(url + "?" + urllib.parse.urlencode(params), headers=headers, timeout_seconds=30)
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = s.post(url, data=urllib.parse.urlencode(params), headers=headers, timeout_seconds=30)
    return r.status_code, r.text

def session_map(gps, auid, now):
    return {"gps_adid": gps, "android_uuid": auid, "api_level": "33",
        "app_version": "3.13.9", "app_token": "jut9tib0eeps", "os_name": "android",
        "os_version": "13", "device_name": "KB2001", "device_type": "phone",
        "device_manufacturer": "OnePlus", "environment": "production",
        "package_name": "com.penti.app", "hardware_name": "qcom",
        "os_build": "KB2001_11_C.50", "language": "en", "cpu_type": "arm64-v8a",
        "screen_size": "normal", "screen_format": "long", "screen_density": "xxhdpi",
        "display_width": "1080", "display_height": "2400", "connectivity_type": "1",
        "ui_mode": "1", "foreground": "1", "tracking_enabled": "1",
        "gps_adid_src": "service", "gps_adid_attempt": "1",
        "needs_response_details": "1", "attribution_deeplink": "1",
        "offline_mode_enabled": "0",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "adj_signing_id": "1500000", "headers_id": "10", "native_version": "5.0.0",
        "algorithm": "adj9", "client_sdk": "android5.7.0",
        "initiating_package_name": "com.android.vending",
        "store_name_from_system": "com.android.vending",
        "created_at": plus0530(now, 100), "sent_at": plus0530(now, 130),
        "installed_at": plus0530(now - 2, 200), "updated_at": plus0530(now - 2, 200),
        "session_count": "1", "activity_kind": "session", "initiated_by": "sdk"}


def main():
    fresh = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    old = set_gaid(fresh)
    wipe_app()
    log("gaid", "%s -> %s" % (old, fresh))

    code = device_click(fresh, "cline_tls1")
    log("click", code)

    now = time.time()
    val = session_map(fresh, auid, now)
    d0b, d2b, d4b = synth_bytes()
    sec = int(now)
    st, blob, desc, unp = F.make_signature_law(val, "session", second=sec,
                                               d0=d0b, d2=d2b, d4=d4b)
    p = dict(val)
    p["ask_in"] = "2000"
    c, b = tls_send("POST", "/session", p, blob)
    log("session/tls", "%s %s" % (c, b[:200]))

    time.sleep(2)
    now2 = time.time()
    cv = dict(val)
    cv.update({"activity_kind": "click", "google_play_instant": "0",
               "referrer": REF, "referrer_api": "google",
               "source": "install_referrer", "session_length": "0",
               "subsession_count": "1", "time_spent": "0",
               "created_at": plus0530(now2, 100), "sent_at": plus0530(now2, 130),
               "session_count": "1"})
    sd0, sd2, sd4 = synth_bytes()
    try:
        st2, blob2, _, n2 = F.make_signature_law(cv, "click", second=int(now2),
                                                 d0=sd0, d2=sd2, d4=sd4)
        c2, b2 = tls_send("POST", "/sdk_click", cv, blob2)
        log("sdk_click/tls", "%s %s" % (c2, b2[:200]))
    except Exception as e:
        log("sdk_click/tls", "%s: %s" % (type(e).__name__, str(e)[:120]))

    set_gaid(fresh)
    wipe_app()
    adb("shell", "am start -n %s/.ui.main.MainActivity" % PKG)
    verdict = None
    for _ in range(8):
        time.sleep(12)
        raw = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null" % PKG)
        m = re.search(r'\{"tracker_token.*?\}', raw)
        if m:
            try:
                verdict = json.loads(m.group(0) + "}")
            except Exception:
                pass
            break

    if verdict:
        log("verdict", "token=%s network=%s name=%s" % (
            verdict.get("tracker_token"), verdict.get("network"),
            verdict.get("tracker_name")))
        if verdict.get("network") != "Organic":
            log("RESULT", "NON-ORGANIC — TLS fingerprint spoofing BOOKED!")
        else:
            log("RESULT", "Organic — TLS fingerprint is NOT the discriminator")
    else:
        log("RESULT", "no verdict found")

    LOG.update({"gps": fresh, "verdict": verdict})
    json.dump(LOG, open(OUT, "w"), indent=1)


if __name__ == "__main__":
    main()

