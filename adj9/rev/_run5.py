"""_run4.py — install against the user's FRESH manual click (Redmi 23090RA98I).

Pre-poll already confirmed the clean baseline:
  400 {"error":"Attribution request failed (app is not installed)"}
so the click is registered and NO install exists.  This is the first install
for this GAID, which is the experiment every prior run failed to be.

Device: Xiaomi/Redmi 23090RA98I, Android 15, API 35, tr-TR, +0200 (120 min),
Turkcell mcc 286 / mnc 01, 1220x2712, 480dpi xxhdpi, LTE/WiFi.
Bodies built from the golden_saz base to the EXACT genuine key sets:
session 43/43, click 47/47.
Signature: device-verified head (0x2b, 0x48).
"""
import base64, datetime, gzip, http.client, json, struct, sys, time
import urllib.parse, uuid
sys.path.insert(0, '.')
import mint_pipeline as M
import F as Fmod

GAID = __import__('os').environ.get('ADJ_GAID', '648c7e4d-8520-4c90-bb88-cb171c5f62e2')
REFTAG = __import__("os").environ.get("ADJ_REFTAG",
    "adjust_reftag=cosRSXzfrRV0Y&utm_source=VKM+Digital+Yeni"
    "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic")
UA = "Dalvik/2.1.0 (Linux; U; Android 15; moto g64 5G Build/V1TD35H.83-20-5)"
ADJ_V = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
OFF = 330            # +0530 India
# Vocabulary-corrected after auditing Adjust's own value sets:
#   screen_density is Adjust's fixed vocabulary -> 'high' (only value in the
#     whole corpus, 1173 hits).  'xxhdpi' is the DEVICE's density_dpi string.
#   hardware_name is the SoC/platform, not the codename -> 'qcom', matching
#     the SAMSUNG/POCO/XIAOMI profiles already in adj9_full_chain.py.
# moto g64 5G (cancunf) -- en-IN, +0530 (330 min), Jio 405/863, 1080x2400.
# screen_density 'high' and hardware_name 'qcom' are Adjust's own vocabulary
# (audited: 'high' is the only screen_density value in the entire corpus).
DEV = {"api_level": "35", "os_version": "15", "device_name": "moto g64 5G",
       "device_manufacturer": "motorola", "hardware_name": "qcom",
       "os_build": "V1TD35H.83-20-5", "app_version": "3.13.9",
       "install_version": "3.13.9", "language": "en", "mcc": "405",
       "mnc": "863", "display_width": "1080", "display_height": "2400",
       "screen_density": "high"}
GOLD = json.load(open('golden_saz.json'))
S1P, S2P = GOLD['s1']['params'], GOLD['s2']['params']

def fmt(ts, ms):
    dt = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
          + datetime.timedelta(minutes=OFF))
    return dt.strftime("%%Y-%%m-%%dT%%H:%%M:%%S.%03dZ+0530" % ms).encode()

def req(method, path, params, auth):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    try:
        if method == "POST":
            body = urllib.parse.urlencode(params).encode()
            c.putrequest("POST", path, skip_host=1, skip_accept_encoding=1)
            c.putheader("Client-SDK", "android5.7.0")
            c.putheader("Authorization", auth)
            c.putheader("Content-Type", "application/x-www-form-urlencoded")
            c.putheader("User-Agent", UA); c.putheader("Host", "app.adjust.com")
            c.putheader("Connection", "Keep-Alive")
            c.putheader("Accept-Encoding", "gzip")
            c.putheader("Content-Length", str(len(body)))
            c.endheaders(body)
        else:
            qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            c.putrequest("GET", path + "?" + qs, skip_host=1, skip_accept_encoding=1)
            c.putheader("Client-SDK", "android5.7.0")
            c.putheader("Authorization", auth)
            c.putheader("User-Agent", UA); c.putheader("Host", "app.adjust.com")
            c.putheader("Connection", "Keep-Alive")
            c.putheader("Accept-Encoding", "gzip")
            c.endheaders()
        r = c.getresponse(); raw = r.read()
        if raw[:2] == b"\x1f\x8b":
            try: raw = gzip.decompress(raw)
            except Exception: pass
        return r.status, raw.decode("utf-8", "replace")
    finally: c.close()

def mint(params, kind, sec):
    claims = dict(params)
    for k, v in (("adj_verification", ADJ_V), ("adj_signing_id", "1500000"),
                 ("headers_id", "10"), ("native_version", "5.0.0"),
                 ("activity_kind", kind), ("client_sdk", "android5.7.0")):
        claims.setdefault(k, v)
    padded, unpadded = M.claims_for_law(claims, kind)
    d0w, d2w, d4w = Fmod.region(sec, M.DEFAULT_PID, 0, head=M.DEVICE_SELECTORS)
    by = {0: (36, b''.join(w.to_bytes(4,'big') for w in d0w)),
          9: (5, bytes.fromhex('fad0f10d60f93c17937b2f1eb6c09691ae7d74bd')),
          8: (4, bytes.fromhex('bffffffffffffd1f0007000000000000')),
          4: (8, b''.join(w.to_bytes(4,'big') for w in d4w)),
          2: (1, d2w.to_bytes(4,'big')), 7: (1, struct.pack('>I', unpadded)),
          10: (len(padded)//4, padded), 5: (1, b'\0'*4), 6: (1, b'\0'*4),
          1: (0, b''), 3: (0, b'')}
    blob, info = M.finex_mint([(by[i][0], 0, by[i][1]) for i in M.VA_ORDER], sec)
    return blob, info

def auth_of(b):
    return ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",adj_verification="%s"'
            % (base64.b64encode(b).decode(), ADJ_V))

gps = GAID; auid = str(uuid.uuid4())
t_click = int(time.time()); sec = t_click + 6
ins = fmt(sec - 55, 774).decode(); tb = sec - 62
rec = {"gps": gps, "reftag": REFTAG, "t_click": t_click}

sp = dict(S1P)
sp.update({"gps_adid": gps, "android_uuid": auid, **DEV,
           "store_name_from_system": "com.android.vending",
           "initiating_package_name": "com.android.vending",
           "created_at": fmt(sec-1, 928).decode(),
           "sent_at": fmt(sec-1, 942).decode(),
           "installed_at": ins, "updated_at": ins})
sp.pop('mcc', None); sp.pop('mnc', None); sp.pop('install_version', None)
rec['skeys'] = len(sp)

cp = {k: v for k, v in S2P.items()
      if k not in ('store_name_from_system','initiating_package_name','mcc','mnc')}
cp.update({"gps_adid": gps, "android_uuid": auid, **DEV,
           "installed_at": ins, "updated_at": ins, "referrer": REFTAG,
           "source": "install_referrer", "referrer_api": "google",
           "google_play_instant": "0",
           "created_at": fmt(sec, 961).decode(),
           "sent_at": fmt(sec, 970).decode(),
           "click_time": fmt(t_click, 0).decode(),
           "click_time_server": fmt(t_click - 2, 0).decode(),
           "install_begin_time": fmt(tb, 0).decode(),
           "install_begin_time_server": fmt(tb - 2, 0).decode()})
# **DEV re-adds mcc/mnc; the genuine non-organic bodies carry NEITHER.
cp.pop('mcc', None); cp.pop('mnc', None)
rec['ckeys'] = len(cp)

bs, isess = mint(sp, 'session', sec)
st, bd = req("POST", "/session", sp, auth_of(bs))
rec['session'] = [st, bd[:220]]
print("SESSION %d keys mint=%s -> %d %s" % (len(sp), isess.get('status'), st, bd[:160]), flush=True)
time.sleep(3)
bc, ic = mint(cp, 'click', sec)
stc, bdc = req("POST", "/sdk_click", cp, auth_of(bc))
rec['sdk_click'] = [stc, bdc[:220]]
print("SDK_CLICK %d keys mint=%s -> %d %s" % (len(cp), ic.get('status'), stc, bdc[:160]), flush=True)

for w in (15, 45):
    time.sleep(w)
    ap = {"initiated_by":"backend","gps_adid_attempt":"1","api_level":"35",
          "app_version":"3.13.9","app_token":"jut9tib0eeps","os_version":"15",
          "created_at":fmt(sec,666).decode(),"device_type":"phone",
          "gps_adid":gps,"foreground":"1","android_uuid":auid,
          "sent_at":fmt(sec,696).decode(),"offline_mode_enabled":"0",
          "device_name":"moto g64 5G","environment":"production",
          "needs_response_details":"1","attribution_deeplink":"1",
          "package_name":"com.penti.app","os_name":"android","ui_mode":"1",
          "gps_adid_src":"service","tracking_enabled":"1"}
    ba,_ = mint(ap,'attribution',int(time.time()))
    sa, bda = req("GET","/attribution",ap,R_auth := auth_of(ba))
    print("  ATTR +%ds: %s" % (w, bda[:260]), flush=True)
    rec['last'] = [sa, bda[:400]]
    try:
        a = json.loads(bda).get('attribution') or {}
        if a.get('network') and a['network'] != 'Organic':
            rec['verdict'] = "*** NON-ORGANIC: %s / %s ***" % (a.get('network'), a.get('tracker_token'))
            print("  *** NON-ORGANIC ***", flush=True); break
        rec['verdict'] = "ORGANIC (%s / %s)" % (a.get('network'), a.get('tracker_token'))
    except Exception as e:
        rec['verdict'] = "unparsed: %s" % bda[:120]
    print("  -> %s" % rec['verdict'], flush=True)
json.dump(rec, open('selfclick_result.json','w'), indent=1)
print("\n=== VERDICT: %s ===" % rec.get('verdict'))
