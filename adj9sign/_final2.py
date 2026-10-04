"""_final2.py — does OUR signature even bind?  Poll the device's OWN gaids.

The exact-attribution replay returned installed_at 04:55:49Z = MY run's
install, not the device's 19:09:58Z.  So the record we read back is NOT the
device's stored non-organic -- it is our own install on that gaid.

Decisive control: take the attribution request body but send it with NO valid
change at all, and separately re-read the DEVICE's OWN file, and compare.
"""
import sys, json, time, urllib.parse, http.client, gzip
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import desc10_58 as D
import signer_simple as sg
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
sg.WIN_PHASE = (0x2B,)
_o = D.claims_for_law_58
sg.claims_for_law = lambda val, kind: _o(dict(val, client_sdk="flutter5.8.0@android5.8.0"), kind)
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
GA = "f4d61949-8330-4564-a449-5a221374ef60"
def poll(auth):
    ap = {"initiated_by":"backend","gps_adid_attempt":"1","api_level":"31",
          "app_version":"1.0.174","app_token":"i2n2e5kmcpvk","os_version":"12",
          "created_at":"2026-09-30T04:55:49.000Z+0530","device_type":"phone",
          "gps_adid":GA,"foreground":"1","android_uuid":"probe","sent_at":"2026-09-30T04:55:49.000Z+0530",
          "offline_mode_enabled":"0","device_name":"moto g42","environment":"production",
          "needs_response_details":"1","attribution_deeplink":"1",
          "package_name":"com.creditsea.app","os_name":"android","ui_mode":"1",
          "gps_adid_src":"service","tracking_enabled":"1"}
    qs = urllib.parse.urlencode(ap, quote_via=urllib.parse.quote)
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    c.putrequest("GET", "/attribution?"+qs, skip_host=1, skip_accept_encoding=1)
    c.putheader("Client-SDK", "android5.8.0")
    if auth: c.putheader("Authorization", auth)
    c.putheader("User-Agent", UA); c.putheader("Host", "app.adjust.com")
    c.putheader("Connection", "Keep-Alive"); c.endheaders()
    r = c.getresponse(); raw = r.read()
    if raw[:2] == b"\x1f\x8b":
        try: raw = gzip.decompress(raw)
        except Exception: pass
    return r.status, raw.decode('utf-8','replace')
ap2 = {"initiated_by":"backend","gps_adid_attempt":"1","api_level":"31",
       "app_version":"1.0.174","app_token":"i2n2e5kmcpvk","os_version":"12",
       "created_at":"2026-09-30T04:55:49.000Z+0530","device_type":"phone",
       "gps_adid":GA,"foreground":"1","android_uuid":"probe",
       "sent_at":"2026-09-30T04:55:49.000Z+0530","offline_mode_enabled":"0",
       "device_name":"moto g42","environment":"production","needs_response_details":"1",
       "attribution_deeplink":"1","package_name":"com.creditsea.app","os_name":"android",
       "ui_mode":"1","gps_adid_src":"service","tracking_enabled":"1"}
b,_,_ = sg.sign_request(ap2, 'attribution', second=int(time.time()))
for label, auth in (("OUR signature", sg.auth_header(b)), ("NO Authorization", None)):
    st, body = poll(auth)
    try:
        a = json.loads(body).get('attribution') or {}
        print('%-16s HTTP %d -> %s / %s / installed_at=%s'
              % (label, st, a.get('network'), a.get('tracker_token'), a.get('installed_at')))
    except Exception:
        print('%-16s HTTP %d -> %s' % (label, st, body[:110]))
