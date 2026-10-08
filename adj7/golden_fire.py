import sys, os, re, json, time, calendar, urllib.parse, zipfile
sys.path.insert(0, '.'); sys.path.insert(0, 'oracle')
import adj7_pure as sg
from curl_cffi import requests as cr

env = {}
for line in open('preclick.env'):
    k, _, v = line.strip().partition('=')
    if k: env[k] = v
gaid = env['gaid']; referrer = env['referrer']; T = int(env['click_server_sec'])
au = 'ee7edd84-ad6d-4447-8e17-1b14d310ac1b'
pp = '{"payrupik_c_id":"7e3c72b5-e87a-4eb2-b402-0fdb897260a9"}'
CS = 'android5.6.0'; CERT = 'C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF'
UA = 'Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)'
sg.CERT_SHA1 = CERT; sg.CLIENT_SDK = CS

z = zipfile.ZipFile(r'C:\Users\Apps\Downloads\payruki_again_same_wifi.saz')
def tmpl(sid, kind):
    c = z.read('raw/%s_c.txt' % sid)
    line1 = c.split(b'\r\n',1)[0].decode('latin1')
    if kind == 'attribution':
        q = line1.split(' ',1)[1].rsplit(' HTTP',1)[0].split('?',1)[1]
        return dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    head, _, body = c.partition(b'\r\n\r\n')
    cl = int(re.search(rb'Content-Length: (\d+)', head).group(1))
    return dict(urllib.parse.parse_qsl(body[:cl].decode('latin1'), keep_blank_values=True))

gold_T0 = 1791363756  # the booked capture's click_time_server second
shift = T - gold_T0

def dyn(f):
    f = dict(f)
    f['gps_adid'] = gaid
    if 'android_uuid' in f: f['android_uuid'] = au
    if 'partner_params' in f: f['partner_params'] = pp
    if 'referrer' in f: f['referrer'] = referrer
    if 'callback_params' in f: f['callback_params'] = '{"google_adid":"' + gaid + '"}'
    return f

def stamp(sec, ms):
    from datetime import datetime, timezone, timedelta
    IST = timezone(timedelta(hours=5, minutes=30))
    dt = datetime.fromtimestamp(sec, IST)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ+0530' % ms

session = cr.Session(impersonate='chrome131_android')

# 1. SESSION
f_sess = tmpl('41', 'session')
for k in ('installed_at','created_at','sent_at','updated_at'):
    if k in f_sess:
        m = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})', f_sess[k])
        Y,Mo,Dd,h,mi,s,ms = m.groups()
        e = calendar.timegm((int(Y),int(Mo),int(Dd),int(h),int(mi),int(s))) + int(ms)/1000.0
        f_sess[k] = stamp(e + shift, int(ms))
f_sess = dyn(f_sess)
sec_s = int(time.time()) - 1
f_sess['created_at'] = stamp(sec_s, 555)
f_sess['sent_at'] = stamp(sec_s + 1, 123)
auth_s = sg.sign_request(f_sess, 'session', second=sec_s + 1, cert_sha1=CERT,
                         client_sdk=CS, include_block2=True, headers_id='8', native_version='3.62.0')
r = session.post('https://app.adjust.com/session', data=urllib.parse.urlencode(f_sess).encode(),
                 headers={'Client-SDK': CS, 'Authorization': auth_s, 'User-Agent': UA,
                          'Content-Type': 'application/x-www-form-urlencoded',
                          'Accept-Encoding': 'gzip'}, timeout=40)
print('session -> HTTP %d  %s' % (r.status_code, r.text[:130]), flush=True)
adid = ''
try: adid = r.json().get('adid', '')
except: pass

time.sleep(1.2)

# 2. SDK_CLICK
f_click = tmpl('42', 'sdk_click')
for k in ('installed_at','created_at','sent_at','updated_at','click_time','click_time_server',
          'install_begin_time','install_begin_time_server'):
    if k in f_click:
        m = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})', f_click[k])
        if m:
            Y,Mo,Dd,h,mi,s,ms = m.groups()
            e = calendar.timegm((int(Y),int(Mo),int(Dd),int(h),int(mi),int(s))) + int(ms)/1000.0
            f_click[k] = stamp(e + shift, int(ms))
f_click = dyn(f_click)
sec_c = int(time.time())
f_click['created_at'] = stamp(sec_c, 888)
f_click['sent_at'] = stamp(sec_c, 916)
auth_c = sg.sign_request(f_click, 'click', second=sec_c, cert_sha1=CERT,
                         client_sdk=CS, include_block2=True, headers_id='8', native_version='3.62.0')
r = session.post('https://app.adjust.com/sdk_click', data=urllib.parse.urlencode(f_click).encode(),
                 headers={'Client-SDK': CS, 'Authorization': auth_c, 'User-Agent': UA,
                          'Content-Type': 'application/x-www-form-urlencoded',
                          'Accept-Encoding': 'gzip'}, timeout=40)
print('sdk_click -> HTTP %d  %s' % (r.status_code, r.text[:130]), flush=True)

# 3. ATTRIBUTION ask#1
time.sleep(1.4)
f_attr = tmpl('43', 'attribution')
for k in ('created_at','sent_at'):
    m = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})', f_attr[k])
    Y,Mo,Dd,h,mi,s,ms = m.groups()
    e = calendar.timegm((int(Y),int(Mo),int(Dd),int(h),int(mi),int(s))) + int(ms)/1000.0
    f_attr[k] = stamp(e + shift, int(ms))
f_attr = dyn(f_attr)
sec_a = int(time.time())
f_attr['created_at'] = stamp(sec_a, 555)
f_attr['sent_at'] = stamp(sec_a, 568)
auth_a = sg.sign_request(f_attr, 'attribution', second=sec_a, cert_sha1=CERT,
                         client_sdk=CS, include_block2=True, headers_id='8', native_version='3.62.0')
r = session.get('https://app.adjust.com/attribution?' + urllib.parse.urlencode(f_attr),
                headers={'Client-SDK': CS, 'Authorization': auth_a, 'User-Agent': UA,
                         'Accept-Encoding': 'gzip'}, timeout=40)
print('attribution #1 -> HTTP %d  %s' % (r.status_code, r.text[:200]), flush=True)
try: v = r.json().get('attribution', {})
except: v = {}
if v.get('network') and v['network'] != 'Organic':
    print('*** NON-ORGANIC ***'); print(json.dumps(v, indent=1)); sys.exit(0)

# 4. ask#2 (+1.4s like the device)
time.sleep(1.4)
sec_a2 = int(time.time())
f_a2 = dict(f_attr)
f_a2['created_at'] = stamp(sec_a2, 813)
f_a2['sent_at'] = stamp(sec_a2, 823)
auth_a2 = sg.sign_request(f_a2, 'attribution', second=sec_a2, cert_sha1=CERT,
                          client_sdk=CS, include_block2=True, headers_id='8', native_version='3.62.0')
r = session.get('https://app.adjust.com/attribution?' + urllib.parse.urlencode(f_a2),
                headers={'Client-SDK': CS, 'Authorization': auth_a2, 'User-Agent': UA,
                         'Accept-Encoding': 'gzip'}, timeout=40)
print('attribution #2 -> HTTP %d  %s' % (r.status_code, r.text[:200]), flush=True)
try: v = r.json().get('attribution', {})
except: v = {}
if v.get('network') and v['network'] != 'Organic':
    print('*** NON-ORGANIC ***'); print(json.dumps(v, indent=1)); sys.exit(0)

# 5. polls [3, 8, 20]
for delay in (3, 8, 20):
    time.sleep(delay)
    sec_p = int(time.time())
    f_p = dict(f_attr)
    f_p['created_at'] = stamp(sec_p, 500)
    f_p['sent_at'] = stamp(sec_p, 513)
    auth_p = sg.sign_request(f_p, 'attribution', second=sec_p, cert_sha1=CERT,
                             client_sdk=CS, include_block2=True, headers_id='8',
                             native_version='3.62.0')
    r = session.get('https://app.adjust.com/attribution?' + urllib.parse.urlencode(f_p),
                    headers={'Client-SDK': CS, 'Authorization': auth_p, 'User-Agent': UA,
                             'Accept-Encoding': 'gzip'}, timeout=40)
    try: v = r.json().get('attribution', {})
    except: v = {}
    print('poll +%ds -> %s / %s' % (delay, v.get('network'), v.get('tracker_token')), flush=True)
    if v.get('network') and v['network'] != 'Organic':
        print('*** NON-ORGANIC ***'); print(json.dumps(v, indent=1)); break
else:
    print('Organic after all polls')
