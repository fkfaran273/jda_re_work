"""auto_replay.py -- watch the saz; the moment a fresh booked attribution
ask appears, replay it with OUR signature (fresh times) within seconds."""
import zipfile, re, sys, time, os, urllib.parse
from datetime import datetime, timedelta, timezone

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
import adj7_pure as sg
from curl_cffi import requests as cr

SAZ = r'C:\Users\Apps\Downloads\payruki_again_new.saz'
CERT = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
CS = "android5.6.0"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
sg.CERT_SHA1 = CERT; sg.CLIENT_SDK = CS

seen = set()
print('watching for fresh attribution asks (Ctrl-C to stop)', flush=True)
deadline = time.time() + 2400
while time.time() < deadline:
    try:
        z = zipfile.ZipFile(SAZ)
        sids = sorted(set(re.match(r'raw/(\d+)_c\.txt', n).group(1) for n in z.namelist()
                          if re.match(r'raw/(\d+)_c\.txt', n)), key=int)
        for sid in sids:
            if sid in seen:
                continue
            seen.add(sid)
            try:
                c = z.read('raw/%s_c.txt' % sid)
                s = z.read('raw/%s_s.txt' % sid)
            except KeyError:
                continue
            line1 = c.split(b'\r\n', 1)[0].decode('latin1')
            if '/attribution?' not in line1:
                continue
            rbody = s.decode('latin1', 'replace').split('\r\n\r\n', 1)[-1]
            booked = '248wk8ym' in rbody
            print('[%s] NEW ask sid %s booked=%s' % (
                datetime.now().strftime('%H:%M:%S'), sid, booked), flush=True)
            if not booked:
                continue
            # THE REPLAY: the booked ask's fields, fresh times, OUR signature
            q = line1.split(' ', 1)[1].rsplit(' HTTP', 1)[0].split('?', 1)[1]
            FIELDS = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
            for delay in (0.0, 1.4):
                if delay:
                    time.sleep(delay)
                now = datetime.now(timezone(timedelta(hours=5, minutes=30)))
                stamp = now.strftime('%Y-%m-%dT%H:%M:%S.') + '%03d' % (now.microsecond // 1000) + 'Z+0530'
                FIELDS['created_at'] = stamp
                FIELDS['sent_at'] = stamp
                sec = int(now.timestamp())
                auth = sg.mint_adj7('attribution', FIELDS, unix_sec=sec,
                                    client_sdk=CS, include_block2=True)
                r = cr.get('https://app.adjust.com/attribution?' + urllib.parse.urlencode(FIELDS),
                           headers={'Client-SDK': CS, 'User-Agent': UA,
                                    'Authorization': auth, 'Accept-Encoding': 'gzip'},
                           timeout=30, impersonate='chrome131_android')
                hit = '248wk8ym' in r.text
                print('  REPLAY(+%.1fs) -> HTTP %d  %s' % (
                    delay, r.status_code,
                    'NON-ORGANIC ***' if hit else 'Organic'), flush=True)
                if hit:
                    print('  *** RULE PROVEN: our signature read the booked verdict ***', flush=True)
    except Exception as e:
        print('[watch err]', e, flush=True)
    time.sleep(2)
print('watch window ended', flush=True)
