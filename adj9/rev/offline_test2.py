"""offline_test2.py — fully offline: Python click + Python mint + Python session + Python read."""
import base64, json, re, sys, time, uuid, urllib.parse, http.client

sys.path.insert(0, '.')
import mint_pipeline as M
import adj9_full_chain as F
import run_funnel as RF

gps = str(uuid.uuid4())
auid = str(uuid.uuid4())
print("[OFF2] gps=%s" % gps, flush=True)

# ============ STEP 1: click via curl_cffi (Python, chrome impersonation) ============
print("[OFF2] firing click via curl_cffi...", flush=True)
dev = json.loads(RF.DEVICE_JSON)
from curl_cffi import requests as cr
s = cr.Session(impersonate="chrome131")
chrome_ua = ("Mozilla/5.0 (Linux; Android 12; moto g 42) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36")
click_url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
             "&creative=penti_generic&click_id=" + gps + "&idfa=" + gps + "&gps_adid=" + gps)
r = s.get(click_url, headers={"User-Agent": chrome_ua},
          allow_redirects=False, timeout=30)
print("[OFF2] click: %d" % r.status_code, flush=True)
# follow redirects to get the referrer
referrer = None
loc = r.headers.get("Location", "")
if "referrer=" in loc:
    referrer = urllib.parse.unquote(loc.split("referrer=", 1)[1])
print("[OFF2] referrer:", (referrer or "")[:80], flush=True)
t_click = time.time()

# ============ STEP 2: build session params (the app's canonical shape) ============
CANON = open('clean_session_canon.txt', encoding='utf-8').read()
params = {}
for k, v in re.findall(r'([a-z_0-9]+)=([^,\n]*)', CANON):
    params[k] = v
params.update({
    'gps_adid': gps,
    'android_uuid': auid,
    'session_count': '1', 'session_length': '0', 'time_spent': '0', 'subsession_count': '1',
    'adj_signing_id': '1500000', 'headers_id': '10', 'native_version': '5.0.0',
    'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
    'activity_kind': 'session', 'client_sdk': 'android5.7.0',
})
sec = int(time.time())
params['created_at'] = F.fmt(sec - 1, 928).decode()
params['sent_at'] = F.fmt(sec - 1, 942).decode()
ins = F.fmt(int(t_click) + 35, 774).decode()
params['installed_at'] = ins
params['updated_at'] = ins

# ============ STEP 3: mint the blob ============
print("[OFF2] minting blob (second=%d)..." % sec, flush=True)
blob = M.mint_blob(params, sec, kind='session')
print("[OFF2] minted %d B" % len(blob), flush=True)
blob_b64 = base64.b64encode(blob).decode()
auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % blob_b64)

# ============ STEP 4: send session + sdk_click via Python http.client ============
time.sleep(30)
print("[OFF2] sending session...", flush=True)
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
print("[OFF2] SESSION: %d %s" % (resp.status, session_resp[:200]), flush=True)

# sdk_click (with the real referrer)
if referrer:
    time.sleep(3)
    print("[OFF2] sending sdk_click...", flush=True)
    sdk_params = dict(params)
    sdk_params.update({
        'activity_kind': 'click', 'source': 'install_referrer',
        'referrer': referrer,
        'click_time': F.fmt(int(t_click), 0).decode(),
        'install_begin_time': F.fmt(int(t_click) + 30, 0).decode(),
    })
    body2 = urllib.parse.urlencode(sdk_params).encode()
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    conn.putrequest("POST", "/sdk_click", skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("Content-Type", "application/x-www-form-urlencoded")
    conn.putheader("User-Agent", UA)
    conn.putheader("Host", "app.adjust.com")
    conn.putheader("Content-Length", str(len(body2)))
    conn.endheaders(body2)
    resp2 = conn.getresponse()
    click_resp = resp2.read().decode('utf-8', 'replace')
    conn.close()
    print("[OFF2] SDK_CLICK: %d %s" % (resp2.status, click_resp[:200]), flush=True)

# ============ STEP 5: attribution read ============
time.sleep(5)
print("[OFF2] reading attribution...", flush=True)
attr_params = {
    'app_token': 'jut9tib0eeps', 'gps_adid': gps, 'android_uuid': auid,
    'activity_kind': 'attribution', 'initiated_by': 'sdk',
    'needs_response_details': '1', 'environment': 'production',
    'client_sdk': 'android5.7.0', 'os_name': 'android', 'os_version': '12',
    'device_name': 'moto g42', 'device_manufacturer': 'motorola',
    'api_level': '31', 'hardware_name': 'S2SE32.28-28-4',
    'os_build': 'S2SE32.28-28-4', 'app_version': '3.14.0', 'language': 'tr',
    'display_width': '1080', 'display_height': '2237', 'screen_density': 'high',
    'created_at': F.fmt(sec, 100).decode(), 'sent_at': F.fmt(sec, 150).decode(),
}
conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
conn.putrequest("GET", "/attribution?" + urllib.parse.urlencode(attr_params),
                skip_host=1, skip_accept_encoding=1)
conn.putheader("Client-SDK", "android5.7.0")
conn.putheader("Authorization", auth)
conn.putheader("User-Agent", UA)
conn.putheader("Host", "app.adjust.com")
conn.endheaders()
resp3 = conn.getresponse()
attr_resp = resp3.read().decode('utf-8', 'replace')
conn.close()
print("[OFF2] ATTRIBUTION: %d %s" % (resp3.status, attr_resp[:500]), flush=True)

print("=" * 60, flush=True)
try:
    a = json.loads(attr_resp).get('attribution', {})
    net = a.get('network', '?')
    if net != 'Organic':
        print("*** FULLY OFFLINE NON-ORGANIC — GOAL ***", flush=True)
        print("*** network=%s tracker=%s ***" % (net, a.get('tracker_token', '?')), flush=True)
    else:
        print("*** Organic — the gap remains in the booking session ***", flush=True)
except Exception:
    print("*** parse error — see ATTRIBUTION above ***", flush=True)
print("=" * 60, flush=True)

json.dump({"gps": gps, "second": sec, "blob_hex": blob.hex(),
           "session": [resp.status, session_resp[:300]],
           "attribution": [resp3.status, attr_resp[:1000]]},
          open("offline_test2_result.json", "w"), indent=1)
print("saved", flush=True)
