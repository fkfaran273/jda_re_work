"""_pre.py — poll the user's GAID BEFORE sending anything.

If the manual click already earned an attribution, it will be visible here.
Then we can tell 'our install created a join' apart from 'an attribution was
already sitting there'.
"""
import json, sys, time
sys.path.insert(0, '.')
import manual_click as MC
import nonorg_redrive as R
import _redrive2 as RD

gps = MC.GAID
print('polling GAID %s with NO install sent' % gps, flush=True)
rec = {"gps": gps, "reftag": MC.REFTAG, "polls": []}
for n, w in enumerate((0, 5, 15, 40)):
    if w: time.sleep(w)
    auid = 'aaaa1111-bbbb-4ccc-8ddd-eeee2222ffff'
    ap = {"initiated_by":"backend","gps_adid_attempt":"1","api_level":"35",
          "app_version":"3.13.9","app_token":MC.APP_TOKEN,"os_version":"15",
          "created_at":MC.fmt(int(time.time()),666).decode(),
          "device_type":"phone","gps_adid":gps,"foreground":"1",
          "android_uuid":auid,
          "sent_at":MC.fmt(int(time.time()),696).decode(),
          "offline_mode_enabled":"0","device_name":"SM-A366E",
          "environment":"production","needs_response_details":"1",
          "attribution_deeplink":"1","package_name":"com.penti.app",
          "os_name":"android","ui_mode":"1","gps_adid_src":"service",
          "tracking_enabled":"1"}
    ba,_ = RD.mint(ap,'attribution',int(time.time()))
    sa, bda = R.req("GET","/attribution",ap,R.auth_of(ba))
    v = R.score(sa, bda)
    print('  poll %d (+%ds): HTTP %d  %s' % (n, w, sa, v), flush=True)
    if sa == 200:
        try:
            a = json.loads(bda).get('attribution') or {}
            print('     adid        :', json.loads(bda).get('adid'))
            print('     network     :', a.get('network'))
            print('     tracker     :', a.get('tracker_token'))
            print('     tracker_name:', a.get('tracker_name'))
            print('     creative    :', a.get('creative'))
            print('     engagement  :', a.get('engagement_time'))
            print('     installed_at:', a.get('installed_at'))
            print('     reattributed:', a.get('is_reattributed'))
        except Exception as e:
            print('     parse err', e)
    rec['polls'].append([sa, bda[:400]])
    if 'NON-ORGANIC' in v: break
json.dump(rec, open('pre_poll_result.json','w'), indent=1)
print('\nsaved pre_poll_result.json')
