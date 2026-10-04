"""offline_test.py — THE fully-offline test.

Fresh GAID -> Python click -> Python minted session (faithful region) ->
Python attribution read with the same minted blob. Zero device involvement.
If the attribution returns non-organic => FULLY OFFLINE achieved.
"""
import base64, json, re, subprocess, sys, time, uuid, calendar

sys.path.insert(0, '.')
SER = "ZD2228MY3X"
PKG = "com.penti.app"
import urllib.parse
import http.client

import mint_pipeline as M


def adb(*a, t=90):
    r = subprocess.run(["adb", "-s", SER] + list(a), capture_output=True, timeout=t)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return adb("shell", '/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2)


def set_gaid(new):
    import base64 as B
    r = subprocess.run(["adb", "-s", SER, "exec-out",
                        "/debug_ramdisk/su", "-c",
                        "base64 /data/data/com.google.android.gms/shared_prefs/adid_settings.xml"],
                       capture_output=True)
    cur = B.b64decode(r.stdout).decode('utf-8', 'replace')
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    if not m:
        return None
    old = m.group(0)
    patched = cur.replace(old, new)
    b64 = B.b64encode(patched.encode()).decode()
    open('adid_patch.b64', 'w').write(b64)
    subprocess.run(["adb", "-s", SER, "push", "adid_patch.b64",
                    "/data/local/tmp/adid_patch.b64"], capture_output=True)
    su("base64 -d /data/local/tmp/adid_patch.b64 > /data/local/tmp/adid_p && "
       "cat /data/local/tmp/adid_p > /data/data/com.google.android.gms/shared_prefs/adid_settings.xml && "
       "am force-stop com.google.android.gms")
    return old


# ============ The app's canonical (captured, the winning claims shape) ============
CANON = open('clean_session_canon.txt', encoding='utf-8').read()

gps = str(uuid.uuid4())
auid = str(uuid.uuid4())
print("[OFF] fresh gps=%s auid=%s" % (gps, auid), flush=True)

# ============ STEP 1: set GAID on device (the ONLY device involvement) ============
subprocess.run(["adb", "-s", SER, "shell", "am", "force-stop", PKG], capture_output=True)
time.sleep(1)
old = set_gaid(gps)
print("[OFF] GAID: %s -> %s" % (old, gps), flush=True)
time.sleep(2)

# ============ STEP 2: click via device curl (real click, from the phone) ============
click_url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
             "&creative=penti_generic&click_id=" + gps + "&idfa=" + gps + "&gps_adid=" + gps)
r = adb("shell", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "-L", click_url,
        "-H", "User-Agent: Mozilla/5.0 (Linux; Android 12; moto g 42)", t=90)
print("[OFF] click:", r.strip()[-3:], flush=True)
t_click = time.time()

# ============ STEP 3: build the session params (the app's canonical + our identity) ============
params = {}
for k, v in re.findall(r'([a-z_0-9]+)=([^,\n]*)', CANON):
    params[k] = v
params['gps_adid'] = gps
params['android_uuid'] = auid
params['session_count'] = '1'
params['session_length'] = '0'
params['time_spent'] = '0'
params['subsession_count'] = '1'
# fresh timestamps
sec = int(time.time())
import adj9_full_chain as F
params['created_at'] = F.fmt(sec - 1, 928).decode()
params['sent_at'] = F.fmt(sec - 1, 942).decode()
ins = F.fmt(int(t_click) + 35, 774).decode()
params['installed_at'] = ins
params['updated_at'] = ins
params['adj_signing_id'] = '1500000'
params['adj_verification'] = 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI'
params['activity_kind'] = 'session'
params['client_sdk'] = 'android5.7.0'
params['headers_id'] = '10'
params['native_version'] = '5.0.0'
params['adj_verification'] = 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI'
params['activity_kind'] = 'session'
params['client_sdk'] = 'android5.7.0'

# ============ STEP 4: mint the blob (100% Python, faithful region) ============
print("[OFF] minting blob (kind=session, second=%d)..." % sec, flush=True)
t0 = time.time()
blob = M.mint_blob(params, sec, kind='session')
print("[OFF] minted %d B in %.0f s" % (len(blob), time.time() - t0), flush=True)
blob_b64 = base64.b64encode(blob).decode()
auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % blob_b64)

# ============ STEP 5: send the session via plain http.client ============
time.sleep(30)  # CTIT
print("[OFF] sending session via python http.client...", flush=True)
body = urllib.parse.urlencode(params).encode()
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)"
conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
conn.putrequest("POST", "/session", skip_host=1, skip_accept_encoding=1)
conn.putheader("Client-SDK", "android5.7.0")
conn.putheader("Authorization", auth)
conn.putheader("Content-Type", "application/x-www-form-urlencoded")
conn.putheader("User-Agent", UA)
conn.putheader("Host", "app.adjust.com")
conn.putheader("Connection", "Keep-Alive")
conn.putheader("Accept-Encoding", "gzip")
conn.putheader("Content-Length", str(len(body)))
conn.endheaders(body)
resp = conn.getresponse()
session_resp = resp.read().decode('utf-8', 'replace')
conn.close()
print("[OFF] SESSION: %d %s" % (resp.status, session_resp[:200]), flush=True)

# ============ STEP 6: attribution read via the same transport + same blob ============
time.sleep(5)
print("[OFF] reading attribution (genuine blob, python transport)...", flush=True)
attr_params = {
    'app_token': 'jut9tib0eeps',
    'gps_adid': gps,
    'android_uuid': auid,
    'activity_kind': 'attribution',
    'initiated_by': 'sdk',
    'needs_response_details': '1',
    'environment': 'production',
    'client_sdk': 'android5.7.0',
    'os_name': 'android',
    'os_version': '12',
    'device_name': 'moto g42',
    'device_manufacturer': 'motorola',
    'api_level': '31',
    'hardware_name': 'S2SE32.28-28-4',
    'os_build': 'S2SE32.28-28-4',
    'app_version': '3.14.0',
    'language': 'tr',
    'display_width': '1080',
    'display_height': '2237',
    'screen_density': 'high',
    'created_at': F.fmt(sec, 100).decode(),
    'sent_at': F.fmt(sec, 150).decode(),
}
attr_qs = urllib.parse.urlencode(attr_params)
conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
conn.putrequest("GET", "/attribution?" + attr_qs, skip_host=1, skip_accept_encoding=1)
conn.putheader("Client-SDK", "android5.7.0")
conn.putheader("Authorization", auth)
conn.putheader("User-Agent", UA)
conn.putheader("Host", "app.adjust.com")
conn.putheader("Connection", "Keep-Alive")
conn.putheader("Accept-Encoding", "gzip")
conn.endheaders()
resp2 = conn.getresponse()
attr_resp = resp2.read().decode('utf-8', 'replace')
conn.close()
print("[OFF] ATTRIBUTION: %d %s" % (resp2.status, attr_resp[:400]), flush=True)

# ============ THE VERDICT ============
print("=" * 60, flush=True)
try:
    a = json.loads(attr_resp).get('attribution', {})
    net = a.get('network', '?')
    tok = a.get('tracker_token', '?')
    if net != 'Organic':
        print("*** FULLY OFFLINE NON-ORGANIC — GOAL ACHIEVED ***", flush=True)
        print("*** network=%s tracker=%s ***" % (net, tok), flush=True)
    else:
        print("*** Organic — the python session did not join the click ***", flush=True)
except Exception:
    if 'ask_in' in attr_resp:
        print("*** ask_in received — recognized! ***", flush=True)
    else:
        print("*** Could not parse — see ATTRIBUTION above ***", flush=True)
print("=" * 60, flush=True)

json.dump({"gps": gps, "auid": auid, "second": sec,
           "session": [resp.status, session_resp[:300]],
           "attribution": [resp2.status, attr_resp[:1000]],
           "blob_hex": blob.hex()},
          open("offline_test_result.json", "w"), indent=1)
print("saved offline_test_result.json", flush=True)

# restore the device GAID
if old:
    set_gaid(old)
    print("[OFF] GAID restored to %s" % old, flush=True)
