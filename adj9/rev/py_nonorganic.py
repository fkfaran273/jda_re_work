"""py_nonorganic.py - full non-organic flow: device click + Python session + device read.

All from the phone's IP. Click fired from the device, session sent from the device
via adb curl (our Python-minted blob), verdict read from the device.
"""
import base64, datetime as dt, http.client, json, os, re, struct, subprocess, sys, time
import urllib.parse, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from region_synth import synth_region, check

SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
GMS_XML = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
OUT = os.path.join(HERE, "nonorganic_result.json")
LOG = {}
MARKER = "cline_py1"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"

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
    cur = su("cat " + GMS_XML)
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    if not m: return None
    b64 = base64.b64encode(cur.replace(m.group(0), new).encode()).decode()
    su("echo %s | base64 -d > /data/local/tmp/aid.xml && cat /data/local/tmp/aid.xml > %s" % (b64, GMS_XML))
    su("am force-stop com.google.android.gms")
    return m.group(0)

def plus0530(ts, ms=0):
    d = dt.datetime.fromtimestamp(ts, dt.timezone.utc) + dt.timedelta(hours=5, minutes=30)
    return "%s.%03dZ+0530" % (d.strftime("%Y-%m-%dT%H:%M:%S"), ms)

def ws_bytes(words):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in words)

def synth_bytes():
    d0, d2, d4 = synth_region()
    assert check(d0, d4)
    return ws_bytes(d0), ws_bytes([d2]), ws_bytes(d4)

# The 43-param session body (device's exact order)
PARAM_ORDER = [
    "store_name_from_system", "gps_adid_attempt", "api_level", "hardware_name",
    "app_version", "app_token", "installed_at", "created_at", "wait_total",
    "device_type", "language", "gps_adid", "foreground", "connectivity_type",
    "device_manufacturer", "display_width", "device_name",
    "needs_response_details", "os_build", "updated_at", "cpu_type",
    "retry_count", "screen_size", "screen_format", "last_error",
    "gps_adid_src", "wait_time", "os_version", "first_error", "android_uuid",
    "sent_at", "offline_mode_enabled", "environment", "screen_density",
    "attribution_deeplink", "session_count", "display_height", "package_name",
    "initiating_package_name", "os_name", "ui_mode", "enqueue_size",
    "tracking_enabled",
]

def send_from_device(q, auth):
    """Send /session FROM the phone via adb shell curl (phone's own IP)."""
    b64q = base64.b64encode(q.encode()).decode()
    b64a = base64.b64encode(auth.encode()).decode()
    cmd = ("echo %s | base64 -d > /data/local/tmp/s.txt; "
           "echo %s | base64 -d > /data/local/tmp/a.txt; "
           "curl -s -o /dev/null -w '%%{http_code}' -X POST "
           "'https://app.adjust.com/session' "
           "-H 'Client-SDK: android5.7.0' "
           "-H \"Authorization: $(cat /data/local/tmp/a.txt)\" "
           "-H 'Content-Type: application/x-www-form-urlencoded' "
           "-H 'User-Agent: %s' "
           "--data-binary @/data/local/tmp/s.txt" % (b64q, b64a, UA))
    r = su(cmd)
    code = int(r.strip()) if r.strip().isdigit() else 0
    return code

def main():
    # 1. fresh GAID
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    old = set_gaid(gps)
    log("gaid", "%s -> %s" % (old, gps))

    # 2. click from the DEVICE's IP
    link = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
            "&creative=%s&click_id=%s&idfa=%s&gps_adid=%s"
            % (MARKER, gps, gps, gps))
    r = adb("shell", "curl -s -o /dev/null -w '%%{http_code}' -L '%s' "
                     "-H 'User-Agent: Mozilla/5.0 (Linux; Android 12; moto g42)'" % link)
    log("click/device", r.strip())

    # 3. mint the session with the lawful region
    now = time.time()
    val = {}
    val["store_name_from_system"] = "com.android.vending"
    val["gps_adid_attempt"] = "1"; val["api_level"] = "31"
    val["hardware_name"] = "S2SE32.28-28-4"; val["app_version"] = "3.13.9"
    val["app_token"] = "jut9tib0eeps"
    val["installed_at"] = plus0530(now - 2, 200)
    val["created_at"] = plus0530(now, 100); val["wait_total"] = "0.0"
    val["device_type"] = "phone"; val["language"] = "tr"; val["gps_adid"] = gps
    val["foreground"] = "1"; val["connectivity_type"] = "1"
    val["device_manufacturer"] = "motorola"; val["display_width"] = "1080"
    val["device_name"] = "moto g42"; val["needs_response_details"] = "1"
    val["os_build"] = "S2SE32.28-28-4"; val["updated_at"] = plus0530(now - 2, 200)
    val["cpu_type"] = "arm64-v8a"; val["retry_count"] = "0"
    val["screen_size"] = "normal"; val["screen_format"] = "long"
    val["last_error"] = "0"; val["gps_adid_src"] = "service"
    val["wait_time"] = "0.0"; val["os_version"] = "12"; val["first_error"] = "0"
    val["android_uuid"] = auid; val["sent_at"] = plus0530(now, 130)
    val["offline_mode_enabled"] = "0"; val["environment"] = "production"
    val["screen_density"] = "high"; val["attribution_deeplink"] = "1"
    val["session_count"] = "1"; val["display_height"] = "2237"
    val["package_name"] = "com.penti.app"
    val["initiating_package_name"] = "com.android.vending"
    val["os_name"] = "android"; val["ui_mode"] = "1"; val["enqueue_size"] = "0"
    val["tracking_enabled"] = "1"; val["activity_kind"] = "session"
    val["initiated_by"] = "sdk"
    val["adj_verification"] = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
    val["adj_signing_id"] = "1500000"; val["headers_id"] = "10"
    val["native_version"] = "5.0.0"; val["algorithm"] = "adj9"
    val["client_sdk"] = "android5.7.0"

    sec = int(now)
    d0, d2, d4 = synth_bytes()
    st, blob, desc, unp = F.make_signature_law(val, "session", second=sec,
                                               d0=d0, d2=d2, d4=d4)
    log("mint", "%s blob=%dB" % (st, len(blob)))

    # 4. send session FROM the DEVICE's IP (adb curl)
    p = {k: val[k] for k in PARAM_ORDER}
    q = urllib.parse.urlencode(p)
    auth = F.auth_header(blob)
    code = send_from_device(q, auth)
    log("session/device", str(code))

    # 5. read the verdict from the device
    su("am force-stop " + PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs /data/data/%s/databases" % (PKG, PKG, PKG))
    adb("shell", "am start -n %s/.ui.main.MainActivity" % PKG)
    log("app", "launched; waiting for verdict")

    verdict = None
    for k in range(8):
        time.sleep(12)
        raw = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null" % PKG)
        m = re.search(r'\{"tracker_token.*?\}', raw)
        if m:
            try: verdict = json.loads(m.group(0) + "}")
            except: pass
            break

    if verdict:
        log("verdict", "token=%s network=%s" % (verdict.get("tracker_token"), verdict.get("network")))
        if verdict.get("network") != "Organic":
            log("RESULT", "NON-ORGANIC BOOKED!")
        else:
            log("RESULT", "Organic")
    else:
        log("RESULT", "no verdict")

    json.dump(LOG, open(OUT, "w"), indent=1)
    print("\nsaved", OUT)

if __name__ == "__main__":
    main()