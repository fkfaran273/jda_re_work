"""hyp_lib.py - shared helpers for the hypothesis runner."""
import base64
import http.client
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from region_synth import synth_region, check

SERIAL = "ZD2228MY3X"
PKG = "com.penti.app"
GMS_XML = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
UA = "Mozilla/5.0 (Linux; Android 13; KB2001)"
CREATIVE = "cline_hyp"


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


def wipe_app():
    su("am force-stop %s" % PKG)
    su("rm -rf /data/data/%s/files /data/data/%s/shared_prefs /data/data/%s/databases"
       % (PKG, PKG, PKG))


def click(device, gps, marker=CREATIVE):
    url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
           "&creative=%s&click_id=%s&idfa=%s&gps_adid=%s"
           % (marker, gps, gps, gps))
    if device:
        r = adb("shell", "curl -s -o /dev/null -w 'C:%%{http_code} L:%%{redirect_url}' "
                         "-L '%s' -H 'User-Agent: Mozilla/5.0 (Linux; Android 13; KB2001)'" % url)
        m = re.search(r"adjust_reftag=([A-Za-z0-9+/=_-]+)", r or "")
        code = (re.search(r"C:(\d+)", r or "") or [None, "?"])[1]
        return code, (m.group(0) if m else None)
    q = url.split("?", 1)[1]
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=20)
    conn.putrequest("GET", "/1sd1lk6a?" + q, skip_accept_encoding=1)
    conn.putheader("User-Agent", UA)
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    m = re.search(r"adjust_reftag=([A-Za-z0-9+/=_-]+)", body + r.getheader("Location", ""))
    conn.close()
    return r.status, (m.group(0) if m else None)


def ws_bytes(words):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in words)


def synth_bytes():
    d0, d2, d4 = synth_region()
    assert check(d0, d4)
    return ws_bytes(d0), ws_bytes([d2]), ws_bytes(d4)


def app_read_verdict(gps):
    """H8-safe app oracle: set GAID, wipe, launch, parse the app's own verdict."""
    set_gaid(gps)
    wipe_app()
    adb("shell", "am start -n %s/.ui.main.MainActivity" % PKG)
    for _ in range(8):
        import time
        time.sleep(12)
        raw = su("cat /data/data/%s/files/AdjustAttribution 2>/dev/null" % PKG)
        m = re.search(r'\{"tracker_token.*?\}', raw)
        if m:
            try:
                return json.loads(m.group(0) + "}")
            except Exception:
                pass
    return None
