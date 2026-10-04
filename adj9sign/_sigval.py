"""_sigval.py — DOES Adjust validate the adj9 envelope for creditsea?

Send /session with (a) our valid signature, (b) a bit-flipped signature,
(c) 192 bytes of zeros, (d) no Authorization at all.  If the responses are
identical, the envelope is not a gate and a replay reading back Organic says
nothing about our signature.
"""
import sys, os, re, json, time, uuid, base64
import http.client, urllib.parse, gzip
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
sys.path.insert(0, 'C:/Users/Apps/Downloads/com.penti.app/adj9sign')
import desc10_58 as D
import signer_simple as sg
sg.DESC9 = bytes.fromhex("06f5ffcee0541608765407ab9e0180e7b1b7e7d0")
sg.WIN_PHASE = (0x2B,)
_o = D.claims_for_law_58
sg.claims_for_law = lambda v, k: _o(dict(v, client_sdk="flutter5.8.0@android5.8.0"), k)
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"

b = open('C:/Users/Apps/Downloads/com.penti.app/adj9/rev/creditsea/adj9_cap_fresh.log','rb').read().decode('utf-8','replace')
gs = None
for m in re.finditer(r'map_toString=\{', b):
    seg=b[m.end():m.end()+6000]; end=seg.find('}'); raw=seg[:end]
    k=re.search(r'activity_kind=([^,]*)',raw)
    if k and k.group(1)=='session': gs=dict(re.findall(r'(?:^|, )([A-Za-z_][A-Za-z0-9_]*)=([^,]*)',raw)); break
INT={'activity_kind','adj_signing_id','adj_verification','algorithm','client_sdk','headers_id','native_version'}

def stamp(ts, ms):
    import datetime
    dt=(datetime.datetime.fromtimestamp(ts,datetime.timezone.utc)+datetime.timedelta(minutes=330))
    return dt.strftime("%Y-%m-%dT%H:%M:%S."+"%03d"%ms+"Z+0530")

def post(auth):
    gps=str(uuid.uuid4())
    p={k:v for k,v in gs.items() if k not in INT}
    p.update({'gps_adid':gps,'android_uuid':str(uuid.uuid4()),
              'created_at':stamp(time.time()+62,928),'sent_at':stamp(time.time()+62,942),
              'installed_at':stamp(time.time()+7,774),'updated_at':stamp(time.time()+7,774)})
    blob,_,_=sg.sign_request(p,'session',second=int(time.time()))
    body=urllib.parse.urlencode(p).encode()
    c=http.client.HTTPSConnection("app.adjust.com",443,timeout=30)
    c.putrequest("POST","/session",skip_host=1,skip_accept_encoding=1)
    c.putheader("Client-SDK","android5.8.0")
    if auth=="ZERO":  c.putheader("Authorization", 'Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % base64.b64encode(b"\x00"*192).decode())
    elif auth=="NONE": pass
    elif auth=="FLIP":
        bb=bytearray(blob); bb[16]^=0x01
        c.putheader("Authorization", 'Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % base64.b64encode(bytes(bb)).decode())
    else: c.putheader("Authorization", sg.auth_header(blob))
    c.putheader("Content-Type","application/x-www-form-urlencoded")
    c.putheader("User-Agent",UA); c.putheader("Host","app.adjust.com")
    c.putheader("Connection","Keep-Alive"); c.putheader("Accept-Encoding","gzip")
    c.putheader("Content-Length",str(len(body))); c.endheaders(body)
    r=c.getresponse(); raw=r.read()
    if raw[:2]==b"\x1f\x8b":
        try: raw=gzip.decompress(raw)
        except Exception: pass
    return r.status, raw.decode('utf-8','replace')

for label in ("VALID","FLIP","ZERO","NONE"):
    st, body = post(label)
    try: adid=json.loads(body).get('adid')
    except Exception: adid=None
    print('%-6s HTTP %d  adid=%s' % (label, st, adid))
    time.sleep(1)
