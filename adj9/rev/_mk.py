"""_mk.py — build the correct 43/47-key bodies for the Samsung manual click."""
import sys, json, time
sys.path.insert(0, '.')
import manual_click as MC
import nonorg_redrive as R
import adj9_full_chain as fc

GOLD = json.load(open('golden_saz.json'))
S1P, S2P = GOLD['s1']['params'], GOLD['s2']['params']
gps = MC.GAID
sec = int(time.time()) + 6
ins = MC.fmt(sec - 55, 774).decode()
tb = sec - 62
auid = 'aaaa1111-bbbb-4ccc-8ddd-eeee2222ffff'

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
# the genuine non-organic session has NO mcc/mnc
sp.pop('mcc', None); sp.pop('mnc', None)
sp.pop('install_version', None)
print('SESSION keys: %d' % len(sp))
gs = R.load('1_c.txt')
print('  genuine has: %d ; missing from ours: %s' % (len(gs), sorted(set(gs)-set(sp))))
print('  extra in ours: %s' % sorted(set(sp)-set(gs)))

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
           "click_time": MC.fmt(tb-210,0).decode(),
           "click_time_server": MC.fmt(tb-212,0).decode(),
           "install_begin_time": MC.fmt(tb,0).decode(),
           "install_begin_time_server": MC.fmt(tb-2,0).decode()})
print()
print('CLICK keys: %d' % len(cp))
gc = R.load('2_c.txt')
print('  genuine has: %d ; missing from ours: %s' % (len(gc), sorted(set(gc)-set(cp))))
print('  extra in ours: %s' % sorted(set(cp)-set(gc)))
