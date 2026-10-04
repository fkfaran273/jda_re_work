"""_exactattr.py — replay the DEVICE's exact /attribution request through OUR
signature, exactly the penti criterion.

Penti criterion: take the device's own recorded request, re-sign it with our
signer, send it -> if the server honours our signature we get its stored
non-organic back.  That is what proved the penti signature generic.

Here: the device's REAL non-organic install is GAID f4d61949... / Tarsan1 /
tracker 2439ti22 (from its own AdjustAttribution file).  Replay ITS exact
attribution API request through our signer.
"""
import sys, os, re, json, time
import http.client, urllib.parse, gzip
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import desc10_58 as D
import signer_simple as sg
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
sg.WIN_PHASE = (0x2B,)
_o = D.claims_for_law_58
def c58(val, kind):
    v = dict(val); v["client_sdk"] = "flutter5.8.0@android5.8.0"
    return _o(v, kind)
sg.claims_for_law = c58
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"

# pull the genuine attribution map from the capture
b = open('adj9_cap_fresh.log','rb').read().decode('utf-8','replace')
gen_attr = None
for m in re.finditer(r'map_toString=\{', b):
    seg = b[m.end():m.end()+6000]; end = seg.find('}'); raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw)
    if k and k.group(1) == 'attribution':
        gen_attr = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
        break
if not gen_attr:
    print('no attribution map in the capture'); raise SystemExit(1)
print('genuine attribution request (from the DEVICE capture):')
for k, v in sorted(gen_attr.items()):
    print('   %-24s = %s' % (k, v[:60]))
print()

INT = {'activity_kind','adj_signing_id','adj_verification','algorithm',
       'client_sdk','headers_id','native_version'}
# use the device's REAL non-organic GAID
REAL_GAID = "f4d61949-8330-4564-a449-5a221374ef60"
ap = {k: v for k, v in gen_attr.items() if k not in INT}
ap['gps_adid'] = REAL_GAID
ap['created_at'] = "2026-09-29T20:32:41.322Z+0530"
ap['sent_at'] = "2026-09-29T20:32:41.358Z+0530"
print('replaying against device GAID %s' % REAL_GAID)
print('wire params: %d' % len(ap))

blob, sec, info = sg.sign_request(ap, 'attribution', second=int(time.time()))
auth = sg.auth_header(blob)
qs = urllib.parse.urlencode(ap, quote_via=urllib.parse.quote)
c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
c.putrequest("GET", "/attribution?"+qs, skip_host=1, skip_accept_encoding=1)
c.putheader("Client-SDK", "android5.8.0")
c.putheader("Authorization", auth)
c.putheader("User-Agent", UA); c.putheader("Host", "app.adjust.com")
c.putheader("Connection", "Keep-Alive"); c.putheader("Accept-Encoding", "gzip")
c.endheaders()
r = c.getresponse(); raw = r.read()
if raw[:2] == b"\x1f\x8b":
    try: raw = gzip.decompress(raw)
    except Exception: pass
body = raw.decode('utf-8','replace')
print()
print('HTTP', r.status)
try:
    j = json.loads(body)
    a = j.get('attribution') or {}
    for k in ('tracker_token','tracker_name','network','campaign','adgroup',
              'creative','engagement_time','installed_at','is_reattributed'):
        print('   %-18s = %s' % (k, a.get(k)))
    print()
    net = a.get('network')
    if net and net != 'Organic':
        print('*** NON-ORGANIC VIA OUR SIGNATURE: %s / %s ***' % (net, a.get('tracker_token')))
    else:
        print('*** Organic -- our signature did not return the stored record ***')
except Exception as e:
    print('raw:', body[:300])
