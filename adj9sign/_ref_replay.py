"""_ref_replay.py — THE PENTI CRITERION on the genuine creditsea non-organic.

creditsea_newapp_ct_adjust.saz holds a REAL non-organic install:
  network Tarsan1 / tracker 24pwlwrx / adid 36a34542e880202c11daeafd4e7b0e7a
  GAID d90d1b17-77f2-43b5-915d-ceaad451f1b7d  (Mi A3, api 30, Android 11)
Replay ITS EXACT /attribution request through OUR signer.  If our signature is
generic, the server returns that stored non-organic record.
"""
import sys, os, json, base64, gzip, time
import http.client, urllib.parse, zipfile
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import desc10_58 as D
import signer_simple as sg
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
sg.WIN_PHASE = (0x2B,)
_o = D.claims_for_law_58
sg.claims_for_law = lambda v, k: _o(dict(v, client_sdk="flutter5.8.0@android5.8.0"), k)

Z = zipfile.ZipFile('C:/Users/Apps/Downloads/creditsea_newapp_ct_adjust.saz')
c = Z.read('raw/3_c.txt').decode('utf-8', 'replace')
line = c.split('\r\n')[0]
qs = line.split('?', 1)[1]
params = dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))
# the genuine UA/Client-SDK from the capture
ua = re.search(r'User-Agent: ([^\r\n]+)', c) if (re := __import__('re')) else None
cs = re.search(r'Client-SDK: ([^\r\n]+)', c)
auth_gen = re.search(r'Authorization: ([^\r\n]+)', c)
print('genuine Client-SDK header :', cs.group(1) if cs else '?')
print('genuine User-Agent        :', ua.group(1) if ua else '?')
print('genuine GAID              :', params['gps_adid'])
print()
UA = ua.group(1) if ua else "Dalvik/2.1.0 (Linux; U; Android 11; Mi A3)"
CLIENT_SDK = cs.group(1) if cs else "android5.8.0"

def get(p, auth):
    q = urllib.parse.urlencode(p, quote_via=urllib.parse.quote)
    h = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    h.putrequest("GET", "/attribution?" + q, skip_host=1, skip_accept_encoding=1)
    h.putheader("Client-SDK", CLIENT_SDK)
    if auth: h.putheader("Authorization", auth)
    h.putheader("User-Agent", UA); h.putheader("Host", "app.adjust.com")
    h.putheader("Connection", "Keep-Alive"); h.putheader("Accept-Encoding", "gzip")
    h.endheaders()
    r = h.getresponse(); raw = r.read()
    if raw[:2] == b"\x1f\x8b":
        try: raw = gzip.decompress(raw)
        except Exception: pass
    return r.status, raw.decode('utf-8', 'replace')

blob, sec, info = sg.sign_request(params, 'attribution', second=int(time.time()))
ours = sg.auth_header(blob)
print('--- our signature on the EXACT genuine request ---')
st, body = get(params, ours)
print('HTTP', st)
print('   RAW BODY: %s' % body[:300])
try:
    a = json.loads(body).get('attribution') or {}
    net = a.get('network')
    print('   -> ' + ('*** NON-ORGANIC ***' if net and net != 'Organic' else '*** Organic ***'))
except Exception as e:
    print('   (not an attribution payload)')
print()
print('--- control: the ORIGINAL device signature ---')
st2, body2 = get(params, auth_gen.group(1) if auth_gen else None)
print('HTTP', st2)
try:
    a2 = json.loads(body2).get('attribution') or {}
    print('   network=%s tracker=%s' % (a2.get('network'), a2.get('tracker_token')))
except Exception:
    print('raw:', body2[:200])
print()
print('--- control: NO Authorization at all ---')
st3, body3 = get(params, None)
try:
    a3 = json.loads(body3).get('attribution') or {}
    print('   network=%s tracker=%s' % (a3.get('network'), a3.get('tracker_token')))
except Exception:
    print('raw:', body3[:200])
