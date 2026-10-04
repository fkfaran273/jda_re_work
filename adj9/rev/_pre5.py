"""_pre2.py — standalone: poll the user's GAID with NO install sent."""
import base64, gzip, http.client, json, struct, sys, time, urllib.parse
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod

GAID = "66f65a9b-69ab-4680-9005-85579c8543c9"
ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
UA = "Dalvik/2.1.0 (Linux; U; Android 15; moto g64 5G Build/V1TD35H.83-20-5)"
import datetime
def fmt(ts, ms):
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=330))
    return dt.strftime("%%Y-%%m-%%dT%%H:%%M:%%S.%03dZ+0530" % ms).encode()

def get(params, auth):
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        c.putrequest("GET", "/attribution?" + qs, skip_host=1, skip_accept_encoding=1)
        c.putheader("Client-SDK", "android5.7.0")
        c.putheader("Authorization", auth)
        c.putheader("User-Agent", UA)
        c.putheader("Host", "app.adjust.com")
        c.putheader("Connection", "Keep-Alive")
        c.putheader("Accept-Encoding", "gzip")
        c.endheaders()
        r = c.getresponse(); raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            try: raw = gzip.decompress(raw)
            except Exception: pass
        return r.status, raw.decode("utf-8","replace")
    finally: c.close()

def mint(params, kind, sec):
    claims = dict(params)
    for k,v in (("adj_verification",ADJ_V),("adj_signing_id","1500000"),
                ("headers_id","10"),("native_version","5.0.0"),
                ("activity_kind",kind),("client_sdk","android5.7.0")):
        claims.setdefault(k,v)
    padded, unpadded = M.claims_for_law(claims, kind)
    d0w,d2w,d4w = Fmod.region(sec, M.DEFAULT_PID, 0, head=M.DEVICE_SELECTORS)
    by = {0:(36,b''.join(w.to_bytes(4,'big') for w in d0w)),
          9:(5,bytes.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd')),
          8:(4,bytes.fromhex('bffffffffffffd1f0007000000000000')),
          4:(8,b''.join(w.to_bytes(4,'big') for w in d4w)),
          2:(1,d2w.to_bytes(4,'big')), 7:(1,struct.pack('>I',unpadded)),
          10:(len(padded)//4,padded), 5:(1,b'\0'*4), 6:(1,b'\0'*4),
          1:(0,b''), 3:(0,b'')}
    blob,_ = M.finex_mint([(by[i][0],0,by[i][1]) for i in M.VA_ORDER], sec)
    return blob

def auth_of(b):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(b).decode(), ADJ_V))

gps = GAID
auid = 'aaaa1111-bbbb-4ccc-8ddd-eeee2222ffff'
print('PRE-POLL of %s -- no install sent' % gps, flush=True)
out = []
for n, w in enumerate((0, 6, 20)):
    if w: time.sleep(w)
    t = int(time.time())
    ap = {"initiated_by":"backend","gps_adid_attempt":"1","api_level":"35",
          "app_version":"3.13.9","app_token":"jut9tib0eeps","os_version":"15",
          "created_at":fmt(t,666).decode(),"device_type":"phone",
          "gps_adid":gps,"foreground":"1","android_uuid":auid,
          "sent_at":fmt(t,696).decode(),"offline_mode_enabled":"0",
          "device_name":"moto g64 5G","environment":"production",
          "needs_response_details":"1","attribution_deeplink":"1",
          "package_name":"com.penti.app","os_name":"android","ui_mode":"1",
          "gps_adid_src":"service","tracking_enabled":"1"}
    st, body = get(ap, auth_of(mint(ap,'attribution',t)))
    print('poll %d (+%ds): HTTP %d' % (n, w, st), flush=True)
    print('   %s' % body[:300], flush=True)
    out.append([st, body[:400]])
    if st == 200: break
json.dump(out, open('pre_poll4_result.json','w'), indent=1)
print('\nsaved pre_poll4_result.json')
