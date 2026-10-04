"""final_test.py — the decisive fully-offline test with the app's REAL params.

Uses app_session_params_real.json (43 keys, from the WINNING un-instrumented
run) for every call, swapping only the identity/timestamps/referrer.
"""
import base64, json, re, struct, sys, time, uuid, urllib.parse, http.client
sys.path.insert(0, '.')
import mint_pipeline as M
import adj9_full_chain as F
import F as FP

# The app's real params (winning run)
REAL = json.load(open('app_session_params_real.json'))
print("[T] app params loaded: %d keys" % len(REAL), flush=True)

gps = str(uuid.uuid4()); auid = str(uuid.uuid4())

# ---------- click ----------
from curl_cffi import requests as cr
s = cr.Session(impersonate="chrome131")
cua = ("Mozilla/5.0 (Linux; Android 12; moto g 42) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36")
url = ("https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36"
       "&creative=penti_generic&click_id=" + gps + "&idfa=" + gps + "&gps_adid=" + gps)
r = s.get(url, headers={"User-Agent": cua}, allow_redirects=False, timeout=30)
loc = r.headers.get("Location", "")
referrer = urllib.parse.unquote(loc.split("referrer=", 1)[1]) if "referrer=" in loc else ""
print("[T] click %d  referrer=%s" % (r.status_code, referrer[:60]), flush=True)
t_click = time.time()

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)"
sec = int(time.time())

# ---------- build session params: app's real set, fresh identity/timestamps ----------
P = dict(REAL)
P['gps_adid'] = gps
P['android_uuid'] = auid
P['created_at'] = F.fmt(sec - 1, 928).decode()
P['sent_at'] = F.fmt(sec - 1, 942).decode()
P['installed_at'] = F.fmt(int(t_click) + 35, 774).decode()
P['updated_at'] = P['installed_at']
P['session_count'] = '1'

# law constants (appended by the signer to the canonical, NOT in the wire body)
L = dict(P)
L['adj_verification'] = 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI'
L['adj_signing_id'] = '1500000'
L['headers_id'] = '10'
L['native_version'] = '5.0.0'
L['activity_kind'] = 'session'
L['client_sdk'] = 'android5.7.0'

# ---------- mint ----------
print("[T] minting blob (second=%d)..." % sec, flush=True)
blob = M.mint_blob(L, sec, kind='session')
print("[T] blob %d B" % len(blob), flush=True)
b64 = base64.b64encode(blob).decode()
auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % b64)


def post(path, params):
    body = urllib.parse.urlencode(params).encode()
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    c.putrequest("POST", path, skip_host=1, skip_accept_encoding=1)
    c.putheader("Client-SDK", "android5.7.0")
    c.putheader("Authorization", auth)
    c.putheader("Content-Type", "application/x-www-form-urlencoded")
    c.putheader("User-Agent", UA)
    c.putheader("Host", "app.adjust.com")
    c.putheader("Connection", "Keep-Alive")
    c.putheader("Accept-Encoding", "gzip")
    c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    resp = c.getresponse()
    out = resp.read().decode('utf-8', 'replace')
    c.close()
    return resp.status, out


# ---------- session ----------
time.sleep(30)
print("[T] POST /session", flush=True)
st1, o1 = post("/session", P)
print("[T] SESSION: %d %s" % (st1, o1[:200]), flush=True)

# ---------- sdk_click ----------
time.sleep(3)
C = dict(P)
C.update({'activity_kind': 'click', 'source': 'install_referrer',
          'referrer': referrer, 'referrer_api': 'google',
          'click_time': F.fmt(int(t_click), 0).decode(),
          'install_begin_time': F.fmt(int(t_click) + 20, 0).decode()})
C['created_at'] = F.fmt(sec + 2, 928).decode()
C['sent_at'] = F.fmt(sec + 2, 942).decode()
LC = dict(C)
LC.update({'adj_verification': 'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
           'adj_signing_id': '1500000', 'headers_id': '10',
           'native_version': '5.0.0', 'client_sdk': 'android5.7.0'})
print("[T] POST /sdk_click", flush=True)
st2, o2 = post("/sdk_click", C)
print("[T] SDK_CLICK: %d %s" % (st2, o2[:200]), flush=True)

# ---------- attribution (FULL param set, like the app) ----------
time.sleep(5)
A = dict(P)
A.update({'activity_kind': 'attribution', 'initiated_by': 'sdk',
          'needs_response_details': '1'})
q = urllib.parse.urlencode(A)
c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
c.putrequest("GET", "/attribution?" + q, skip_host=1, skip_accept_encoding=1)
c.putheader("Client-SDK", "android5.7.0")
c.putheader("Authorization", auth)
c.putheader("User-Agent", UA)
c.putheader("Host", "app.adjust.com")
c.endheaders()
resp = c.getresponse()
attr = resp.read().decode('utf-8', 'replace')
c.close()
print("[T] ATTRIBUTION: %d %s" % (resp.status, attr[:500]), flush=True)

print("=" * 60, flush=True)
try:
    a = json.loads(attr).get('attribution', {})
    net = a.get('network', '?')
    print("VERDICT: network=%s tracker=%s engagement=%s" % (
        net, a.get('tracker_token', '?'), a.get('engagement_time', '?')), flush=True)
    if net != 'Organic':
        print("*** FULLY OFFLINE NON-ORGANIC — GOAL ***", flush=True)
    else:
        print("*** Organic ***", flush=True)
except Exception as e:
    print("parse error:", e, flush=True)
print("=" * 60, flush=True)
json.dump({"gps": gps, "second": sec, "blob_hex": blob.hex(),
           "session": [st1, o1[:300]], "click": [st2, o2[:300]],
           "attribution": [resp.status, attr[:1000]]},
          open('final_test_result.json', 'w'), indent=1)
print("saved final_test_result.json", flush=True)
