import json, struct, sys, time
sys.path.insert(0, r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev')
HERE = r'C:/Users/Apps/Downloads/com.penti.app/adj9/rev'
import adj9_full_chain as fc
fc.USE_PROXY = True  # direct egress hangs from this PC; route via MITM 8888

GPS = 'f476b3d4-e0b1-4707-bc43-6153d17f7f8c'
AUID = 'd773f47f-fc0e-4994-9cf7-7c3cf5bb6368'

sec = int(time.time())
st, steps, blob = fc.make_signature(
    sec, fc.fmt(sec - 1, 555), gps=GPS, auid=AUID,
    installed=b'2026-09-08T12:20:49.782Z+0200')
print('minted blob sec=', sec, 'status=', st, flush=True)

D = json.load(open(HERE + '/fin_descs.json'))
by = {d['build_idx']: (d['len_dw'], bytes.fromhex(d['data_hex']))
      for d in D['descs']}
t10 = by[10][1].replace(b'session', b'attribution', 1)
_ = t10  # kind only matters for VM input; we keep the minted one as-is

p = {"initiated_by": "sdk", "gps_adid_attempt": "1",
     "api_level": fc.DEV["api_level"], "app_version": fc.DEV["app_version"],
     "app_token": fc.APP_TOKEN, "os_version": fc.DEV["os_version"],
     "created_at": fc.fmt(sec - 1, 666).decode(), "device_type": "phone",
     "gps_adid": GPS, "foreground": "1", "android_uuid": AUID,
     "sent_at": fc.fmt(sec - 1, 696).decode(),
     "offline_mode_enabled": "0", "device_name": fc.DEV["device_name"],
     "environment": "production", "needs_response_details": "1",
     "attribution_deeplink": "1", "package_name": "com.penti.app",
     "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
     "tracking_enabled": "1"}

res = []
for i in range(3):
    code, body = fc.send('https://app.adjust.com/attribution', p, blob,
                         method='GET')
    short = body[:200].replace('\n', ' ')
    print(f'send#{i+1} st={code} body={short}', flush=True)
    res.append({'i': i + 1, 'st': code, 'body': body[:400]})
    if i < 2:
        time.sleep(25)
json.dump({'sec': sec, 'sends': res},
          open(HERE + '/resend_result.json', 'w'), indent=1)
print('RESEND DONE', flush=True)

