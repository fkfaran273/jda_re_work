"""_devref.py — poll the GENUINE creditsea device's GAID with our signer.
This is the reference: what did the REAL device earn?
Then we replay its exact record through our signature."""
import sys, os, json, time, base64, struct, gzip
import http.client, urllib.parse
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev\creditsea')
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj9\rev')
import desc10_58 as D
import signer_simple as sg
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
sg.WIN_PHASE = (0x2B,)          # the per-app head we brute-forced
_o = D.claims_for_law_58
def c58(val, kind):
    v = dict(val); v["client_sdk"] = "flutter5.8.0@android5.8.0"
    return _o(v, kind)
sg.claims_for_law = c58
GAID = "b9f64a28-7fd6-4cfd-a85a-2c272234b6e4"
AUID = "79457bcc-b9e1-4ac3-a463-f435727cd358"
ap = {"initiated_by":"backend","gps_adid_attempt":"1","api_level":"31",
      "app_version":"1.0.174","app_token":"i2n2e5kmcpvk","os_version":"12",
      "created_at":"2026-09-29T20:32:41.322Z+0530","device_type":"phone",
      "gps_adid":GAID,"foreground":"1","android_uuid":AUID,
      "sent_at":"2026-09-29T20:32:41.358Z+0530","offline_mode_enabled":"0",
      "device_name":"moto g42","environment":"production",
      "needs_response_details":"1","attribution_deeplink":"1",
      "package_name":"com.creditsea.app","os_name":"android","ui_mode":"1",
      "gps_adid_src":"service","tracking_enabled":"1"}
blob, sec, info = sg.sign_request(ap, "attribution")
auth = sg.auth_header(blob)
qs = urllib.parse.urlencode(ap, quote_via=urllib.parse.quote)
c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
c.putrequest("GET", "/attribution?"+qs, skip_host=1, skip_accept_encoding=1)
c.putheader("Client-SDK", "android5.8.0")
c.putheader("Authorization", auth)
c.putheader("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
c.putheader("Host", "app.adjust.com")
c.putheader("Connection", "Keep-Alive")
c.putheader("Accept-Encoding", "gzip")
c.endheaders()
r = c.getresponse(); raw = r.read()
if raw[:2] == b"\x1f\x8b":
    try: raw = gzip.decompress(raw)
    except Exception: pass
body = raw.decode('utf-8','replace')
print("HTTP", r.status)
try:
    a = json.loads(body).get('attribution') or {}
    for k in ('tracker_token','tracker_name','network','campaign','adgroup',
              'creative','engagement_time','installed_at','is_reattributed'):
        print('   %-18s = %s' % (k, a.get(k)))
except Exception as e:
    print('raw:', body[:300])
