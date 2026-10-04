"""_genuine_replay.py — replay the GENUINE creditsea maps verbatim.

penti worked because we replayed the genuine 43/47 bodies.  For creditsea we
have been hand-building a profile, so any SEMANTIC value error (not just a
structural one) would survive byte-exactness -- the server can cross-check the
signed desc10 against the HTTP body.  This replays the captured creditsea
session+click maps verbatim, changing ONLY identity (fresh GAID/uuid) and the
timestamps, exactly as the penti recipe does.
"""
import sys, os, re, json, time, uuid, base64, struct, gzip
import http.client, urllib.parse
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
ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"

CAP = 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/adj9_cap_fresh.log'
b = open(CAP, 'rb').read().decode('utf-8', 'replace')
gen = {}
for m in re.finditer(r'map_toString=\{', b):
    seg = b[m.end():m.end()+6000]; end = seg.find('}'); raw = seg[:end]
    k = re.search(r'activity_kind=([^,]*)', raw); k = k.group(1) if k else '?'
    d = dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)', raw))
    if k in ('session','click') and k not in gen: gen[k] = d
INTERNAL = {'activity_kind','adj_signing_id','adj_verification','algorithm',
            'client_sdk','headers_id','native_version'}

def stamp(ts, ms):
    import datetime
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=330))
    return dt.strftime("%Y-%m-%dT%H:%M:%S." + "%03d" % ms + "Z+0530")

def post(path, params, auth):
    body = urllib.parse.urlencode(params).encode()
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    c.putrequest("POST", path, skip_host=1, skip_accept_encoding=1)
    c.putheader("Client-SDK", "android5.8.0")
    c.putheader("Authorization", auth)
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
    c.putheader("Client-SDK", "android5.8.0")
    c.putheader("Authorization", auth); c.putheader("User-Agent", UA)
    c.putheader("Host", "app.adjust.com"); c.putheader("Connection", "Keep-Alive")
    c.putheader("Accept-Encoding", "gzip"); c.endheaders()
    r = c.getresponse(); raw = r.read()
    if raw[:2] == b"\x1f\x8b":
        try: raw = gzip.decompress(raw)
        except Exception: pass
    return r.status, raw.decode('utf-8','replace')

# fresh identity, genuine click from the tracker's own link
gps = str(uuid.uuid4()); auid = str(uuid.uuid4())
import click_bind_chain as CBC, offline_funnel_freshregion as FFN
code, referrer, _ = CBC.tracker_click(CBC.expand(FFN.__dict__.get('LINK') or
    "https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic"
    "&click_id={click_id}&idfa={sub3}", gps), gps)
print('tracker click %s reftag=%s' % (code, (referrer or '')[:50]))

t = int(time.time())
sess = {k: v for k, v in gen['session'].items() if k not in INTERNAL}
sess.update({'gps_adid': gps, 'android_uuid': auid,
             'created_at': stamp(t+62, 928), 'sent_at': stamp(t+62, 942),
             'installed_at': stamp(t+7, 774), 'updated_at': stamp(t+7, 774)})
click = {k: v for k, v in gen['click'].items() if k not in INTERNAL}
click.update({'gps_adid': gps, 'android_uuid': auid, 'referrer': referrer,
              'created_at': stamp(t+62, 961), 'sent_at': stamp(t+62, 970),
              'click_time': stamp(t, 0), 'click_time_server': stamp(t-1, 0),
              'install_begin_time': stamp(t+5, 0),
              'install_begin_time_server': stamp(t+4, 0),
              'installed_at': stamp(t+25, 774), 'updated_at': stamp(t+25, 774)})
print('genuine session wire=%d  click wire=%d' % (len(sess), len(click)))
bs, _, _ = sg.sign_request(sess, 'session', second=t)
st, bd = post('/session', sess, sg.auth_header(bs))
print('SESSION %d %s' % (st, bd[:120]))
time.sleep(3)
bc, _, _ = sg.sign_request(click, 'click', second=t+1)
stc, bdc = post('/sdk_click', click, sg.auth_header(bc))
print('SDK_CLICK %d %s' % (stc, bdc[:120]))
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
    ba, _, _ = sg.sign_request(ap, 'attribution', second=int(time.time()))
    sa, bda = get(ap, sg.auth_header(ba))
    try:
        a = json.loads(bda).get('attribution') or {}
        print('ATTR +%ds: %s / %s  %s' % (w, a.get('network'), a.get('tracker_token'), a.get('tracker_name')))
    except Exception:
        print('ATTR +%ds: %s' % (w, bda[:150]))
