"""_run2.py — fire the user's manual click with EXACT 43/47-key bodies."""
import json, sys, time, uuid
sys.path.insert(0, '.')
import manual_click as MC
import nonorg_redrive as R
import _redrive2 as RD

GOLD = json.load(open('golden_saz.json'))
S1P, S2P = GOLD['s1']['params'], GOLD['s2']['params']

gps = MC.GAID
auid = str(uuid.uuid4())
t_click = int(time.time())
sec = t_click + 6
ins = MC.fmt(sec - 55, 774).decode()
tb = sec - 62
rec = {"gps": gps, "reftag": MC.REFTAG, "t_click": t_click,
       "head": [hex(x) for x in RD.M.DEVICE_SELECTORS]}

sp = dict(S1P)
sp.update({"gps_adid": gps, "android_uuid": auid,
           "store_name_from_system": "com.android.vending",
           "initiating_package_name": "com.android.vending",
           "api_level": "35", "os_version": "15", "device_name": "SM-A366E",
           "device_manufacturer": "samsung", "hardware_name": "a36xq",
           "os_build": "AP3A.240905.015.A2", "app_version": "3.13.9",
           "language": "en", "display_width": "1080",
           "display_height": "2340", "screen_density": "xxhdpi",
           "created_at": MC.fmt(sec-1,928).decode(),
           "sent_at": MC.fmt(sec-1,942).decode(),
           "installed_at": ins, "updated_at": ins})
sp.pop('mcc', None); sp.pop('mnc', None); sp.pop('install_version', None)
rec['skeys'] = len(sp)

cp = {k:v for k,v in S2P.items() if k not in ('store_name_from_system','initiating_package_name','mcc','mnc')}
cp.update({"gps_adid": gps, "android_uuid": auid, "api_level": "35",
           "os_version": "15", "device_name": "SM-A366E",
           "device_manufacturer": "samsung", "hardware_name": "a36xq",
           "os_build": "AP3A.240905.015.A2", "app_version": "3.13.9",
           "install_version": "3.13.9", "language": "en",
           "display_width": "1080", "display_height": "2340",
           "screen_density": "xxhdpi", "installed_at": ins,
           "updated_at": ins, "referrer": MC.REFTAG,
           "source": "install_referrer", "referrer_api": "google",
           "google_play_instant": "0",
           "created_at": MC.fmt(sec,961).decode(),
           "sent_at": MC.fmt(sec,970).decode(),
           "click_time": MC.fmt(t_click,0).decode(),
           "click_time_server": MC.fmt(t_click-2,0).decode(),
           "install_begin_time": MC.fmt(tb,0).decode(),
           "install_begin_time_server": MC.fmt(tb-2,0).decode()})
rec['ckeys'] = len(cp)

bs, isess = RD.mint(sp, 'session', sec)
st, bd = R.req("POST", "/session", sp, R.auth_of(bs))
rec['session'] = [st, bd[:200]]
print("SESSION %d keys  mint=%s  -> %d %s" % (len(sp), isess.get('status'), st, bd[:150]), flush=True)
time.sleep(3)
bc, ic = RD.mint(cp, 'click', sec)
stc, bdc = R.req("POST", "/sdk_click", cp, R.auth_of(bc))
rec['sdk_click'] = [stc, bdc[:200]]
print("SDK_CLICK %d keys mint=%s -> %d %s" % (len(cp), ic.get('status'), stc, bdc[:150]), flush=True)

for w in (10, 30, 60, 120, 180, 240):
    time.sleep(w)
    ap = {"initiated_by":"backend","gps_adid_attempt":"1","api_level":"35",
          "app_version":"3.13.9","app_token":MC.APP_TOKEN,"os_version":"15",
          "created_at":MC.fmt(sec,666).decode(),"device_type":"phone",
          "gps_adid":gps,"foreground":"1","android_uuid":auid,
          "sent_at":MC.fmt(sec,696).decode(),"offline_mode_enabled":"0",
          "device_name":"SM-A366E","environment":"production",
          "needs_response_details":"1","attribution_deeplink":"1",
          "package_name":"com.penti.app","os_name":"android","ui_mode":"1",
          "gps_adid_src":"service","tracking_enabled":"1"}
    ba,_ = RD.mint(ap,'attribution',int(time.time()))
    sa, bda = R.req("GET","/attribution",ap,R.auth_of(ba))
    v = R.score(sa, bda)
    print("  ATTR +%ds: %s" % (w, v), flush=True)
    rec['verdict'] = v; rec['last'] = [sa, bda[:400]]
    if 'NON-ORGANIC' in v: break
json.dump(rec, open('manual_click2_result.json','w'), indent=1)
print("\n=== VERDICT ===");print("  %s" % rec.get('verdict'))
