"""_poscontrol.py — the penti positive control, applied to creditsea.

PENTI proved the signature is GENERIC like this: take the DEVICE's own
recorded reftag, replay it through OUR signature on a FRESH gaid -> non-organic.
We never ran the equivalent for creditsea; every creditsea run used a reftag WE
generated.  The device's own proven-good click is:

  reftag   cvO88KFVr7tAh        (device GAID f4d61949-8330-4564-a449-5a221374ef60)
  earned   network Tarsan1 / tracker 2439ti22 / Clickgency_03 / CG_DSM_

Arms:
  A  fresh gaid + DEVICE reftag, our signature   <- the penti control
  B  device gaid + DEVICE reftag, our signature  <- same install, read-back
"""
import sys, os, re, json, time, uuid
import http.client, urllib.parse, gzip
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
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

b = open('C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/adj9_cap_fresh.log','rb').read().decode('utf-8','replace')
gen = {}
for m in re.finditer(r'map_toString=\{', b):
    seg = b[m.end():m.end()+6000]; end = seg.find('}'); raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw); k = k.group(1) if k else '?'
    d = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    if k in ('session','click') and k not in gen: gen[k] = d
INT = {'activity_kind','adj_signing_id','adj_verification','algorithm',
       'client_sdk','headers_id','native_version'}
DEV_REFTAG = 'adjust_reftag=cvO88KFVr7tAh'
print('DEVICE reftag from the genuine capture: %r' % DEV_REFTAG)

def stamp(ts, ms):
    import datetime
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc) + datetime.timedelta(minutes=330))
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z+0530")

def post(path, params, auth):
    body = urllib.parse.urlencode(params).encode()
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    c.putrequest("POST", path, skip_host=1, skip_accept_encoding=1)
    c.putheader("Client-SDK", "android5.8.0"); c.putheader("Authorization", auth)
    c.putheader("Content-Type", "application/x-www-form-urlencoded")
    c.putheader("User-Agent", UA); c.putheader("Host", "app.adjust.com")
    c.putheader("Connection", "Keep-Alive"); c.putheader("Accept-Encoding", "gzip")
    c.putheader("Content-Length", str(len(body))); c.endheaders(body)
    r = c.getresponse(); raw = r.read()
    if raw[:2] == b"\x1f\x8b":
        try: raw = gzip.decompress(raw)
        except Exception: pass
    return r.status, raw.decode('utf-8','replace')

def get(params, auth):
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    c.putrequest("GET", "/attribution?"+qs, skip_host=1, skip_accept_encoding=1)
    c.putheader("Client-SDK", "android5.8.0"); c.putheader("Authorization", auth)
    c.putheader("User-Agent", UA); c.putheader("Host", "app.adjust.com")
    c.putheader("Connection", "Keep-Alive"); c.putheader("Accept-Encoding", "gzip")
    c.endheaders()
    r = c.getresponse(); raw = r.read()
    if raw[:2] == b"\x1f\x8b":
        try: raw = gzip.decompress(raw)
        except Exception: pass
    return r.status, raw.decode('utf-8','replace')

def arm(tag, gps):
    auid = str(uuid.uuid4()); t = int(time.time())
    sess = {k:v for k,v in gen['session'].items() if k not in INT}
    sess.update({'gps_adid':gps,'android_uuid':auid,
                 'created_at':stamp(t+62,928),'sent_at':stamp(t+62,942),
                 'installed_at':stamp(t+7,774),'updated_at':stamp(t+7,774)})
    click = {k:v for k,v in gen['click'].items() if k not in INT}
    click.update({'gps_adid':gps,'android_uuid':auid,'referrer':DEV_REFTAG,
                  'created_at':stamp(t+62,961),'sent_at':stamp(t+62,970),
                  'click_time':stamp(t,0),'click_time_server':stamp(t-1,0),
                  'install_begin_time':stamp(t+5,0),
                  'install_begin_time_server':stamp(t+4,0),
                  'installed_at':stamp(t+25,774),'updated_at':stamp(t+25,774)})
    bs,_,_ = sg.sign_request(sess,'session',second=t)
    st, bd = post('/session', sess, sg.auth_header(bs))
    print('%s SESSION %d %s' % (tag, st, bd[:110]))
    time.sleep(3)
    bc,_,_ = sg.sign_request(click,'click',second=t+1)
    stc, bdc = post('/sdk_click', click, sg.auth_header(bc))
    print('%s SDK_CLICK %d %s' % (tag, stc, bdc[:110]))
    for w in (15, 45):
        time.sleep(w)
        ap = {'initiated_by':'backend','gps_adid_attempt':'1','api_level':'31',
              'app_version':'1.0.174','app_token':'i2n2e5kmcpvk','os_version':'12',
              'created_at':stamp(t+62,666),'device_type':'phone','gps_adid':gps,
              'foreground':'1','android_uuid':auid,'sent_at':stamp(t+62,696),
              'offline_mode_enabled':'0','device_name':'moto g42',
              'environment':'production','needs_response_details':'1',
              'attribution_deeplink':'1','package_name':'com.creditsea.app',
              'os_name':'android','ui_mode':'1','gps_adid_src':'service',
              'tracking_enabled':'1'}
        ba,_,_ = sg.sign_request(ap,'attribution',second=int(time.time()))
        sa, bda = get(ap, sg.auth_header(ba))
        try:
            a = json.loads(bda).get('attribution') or {}
            print('%s ATTR +%ds: %s / %s / %s' % (tag, w, a.get('network'),
                  a.get('tracker_token'), a.get('tracker_name')))
        except Exception:
            print('%s ATTR +%ds: %s' % (tag, w, bda[:140]))

arm('A(fresh+devreftag)', str(uuid.uuid4()))
arm('B(devgaid+devreftag)', 'f4d61949-8330-4564-a449-5a221374ef60')
