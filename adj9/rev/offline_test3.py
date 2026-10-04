"""offline_test3.py — fully offline with the CORRECT wire param set.

FIX: the POST body must NOT contain adj_signing_id, headers_id, native_version,
algorithm — these are Authorization-header-only fields. The genuine SDK puts
47 source fields + activity_kind + client_sdk + adj_verification in the body;
the other 4 go only in the header.
"""
import base64, json, re, sys, time, uuid, urllib.parse, http.client

sys.path.insert(0, '.')
import mint_pipeline as M
import adj9_full_chain as F
import run_funnel as RF

gps = str(uuid.uuid4())
auid = str(uuid.uuid4())
print("[OFF3] gps=%s" % gps, flush=True)

# ============ STEP 1: click via curl_cffi ============
from curl_cffi import requests as cr
s = cr.Session(impersonate="chrome131")
chrome_ua = ("Mozilla/5.0 (Linux; Android 12; moto g 42) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36")
click_url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
             "&creative=penti_generic&click_id=" + gps + "&idfa=" + gps + "&gps_adid=" + gps)
r = s.get(click_url, headers={"User-Agent": chrome_ua},
          allow_redirects=False, timeout=30)
print("[OFF3] click: %d" % r.status_code, flush=True)
referrer = None
loc = r.headers.get("Location", "")
if "referrer=" in loc:
    referrer = urllib.parse.unquote(loc.split("referrer=", 1)[1])
print("[OFF3] referrer:", (referrer or "")[:80], flush=True)
t_click = time.time()

# ============ STEP 2: build FULL params (for blob: all 50 fields) ============
CANON = open('clean_session_canon.txt', encoding='utf-8').read()
full_params = {}
for k, v in re.findall(r'([a-z_0-9]+)=([^,\n]*)', CANON):
    full_params[k] = v
full_params.update({
    'gps_adid': gps,
    'android_uuid': auid,
    'session_count': '1', 'session_length': '0', 'time_spent': '0', 'subsession_count': '1',
    'adj_signing_id': '1500000', 'headers_id': '10', 'native_version': '5.0.0',
    'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
    'activity_kind': 'session', 'client_sdk': 'android5.7.0',
    'app_version': '3.13.9',  # match the app's actual version
})
sec = int(time.time())
full_params['created_at'] = F.fmt(sec - 1, 928).decode()
full_params['sent_at'] = F.fmt(sec - 1, 942).decode()
ins = F.fmt(int(t_click) + 35, 774).decode()
full_params['installed_at'] = ins
full_params['updated_at'] = ins

# ============ STEP 3: mint the blob from FULL params ============
print("[OFF3] minting blob (second=%d)..." % sec, flush=True)
blob = M.mint_blob(full_params, sec, kind='session')
print("[OFF3] minted %d B" % len(blob), flush=True)
blob_b64 = base64.b64encode(blob).decode()
auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % blob_b64)

# ============ STEP 4: build WIRE params (body: WITHOUT header-only fields) ============
# The genuine SDK sends: 47 source fields + activity_kind + client_sdk + adj_verification
# It does NOT send: adj_signing_id, headers_id, native_version, algorithm
wire_params = {k: v for k, v in full_params.items()
               if k not in ('adj_signing_id', 'headers_id', 'native_version')}
print("[OFF3] wire params: %d fields (full: %d)" % (len(wire_params), len(full_params)), flush=True)

# ============ STEP 5: send session ============
time.sleep(30)
print("[OFF3] sending session...", flush=True)
body = urllib.parse.urlencode(wire_params).encode()
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
print("[OFF3] SESSION: %d %s" % (resp.status, session_resp[:200]), flush=True)

# ============ STEP 6: attribution read (also WITHOUT header-only fields) ============
time.sleep(5)
print("[OFF3] reading attribution...", flush=True)
attr_params = {
    'app_token': 'jut9tib0eeps', 'gps_adid': gps, 'android_uuid': auid,
    'activity_kind': 'attribution', 'initiated_by': 'sdk',
    'needs_response_details': '1', 'environment': 'production',
    'client_sdk': 'android5.7.0', 'os_name': 'android', 'os_version': '12',
    'device_name': 'moto g42', 'device_manufacturer': 'motorola',
    'api_level': '31', 'hardware_name': 'S2SE32.28-28-4',
    'os_build': 'S2SE32.28-28-4', 'app_version': '3.13.9', 'language': 'tr',
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
print("[OFF3] ATTRIBUTION: %d %s" % (resp3.status, attr_resp[:500]), flush=True)

print("=" * 60, flush=True)
try:
    a = json.loads(attr_resp).get('attribution', {})
    net = a.get('network', '?')
    if net != 'Organic':
        print("*** FULLY OFFLINE NON-ORGANIC — GOAL ***", flush=True)
        print("*** network=%s tracker=%s ***" % (net, a.get('tracker_token', '?')), flush=True)
    else:
        print("*** Organic ***", flush=True)
except Exception:
    print("*** parse error ***", flush=True)
print("=" * 60, flush=True)

json.dump({"gps": gps, "second": sec, "blob_hex": blob.hex(),
           "session": [resp.status, session_resp[:300]],
           "attribution": [resp3.status, attr_resp[:1000]]},
          open("offline_test3_result.json", "w"), indent=1)
print("saved", flush=True)
