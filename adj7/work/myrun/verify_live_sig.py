import urllib.parse, re, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from adj7_pure import mint_adj7
def load(folder, n):
    p = os.path.join(HERE, folder, '%02d_c.txt' % n)
    t = open(p, encoding='utf-8', errors='replace', newline='').read()
    head, _, body = t.partition('\r\n\r\n')
    return head, body.strip()
def parse_auth(head):
    for line in head.split('\r\n'):
        if 'Authorization' in line:
            return line.strip()
    return ''
def body_fields(body):
    return urllib.parse.parse_qsl(body, keep_blank_values=True)

CAMPAIGN = {"package_name":"in.hanafintech","app_version":"3.0.4","app_token":"smxi7gqwu39c","client_sdk":"android5.6.0","cert_sha1":"c1bfafcaffb84b805288b985fbe48e7f33d2c6df","adj_signing_id":"1300000","algorithm":"adj7","headers_id":"8","native_version":"3.62.0"}

for label, folder, n, kind in [('LIVE sdk_click','saz_live/raw',8,'click'),('MANUAL sdk_click','saz_new/raw',66,'click')]:
    head, body = load(folder, n)
    auth = parse_auth(head)
    fields = dict(body_fields(body))
    print('====', label)
    print(' referrer:', fields.get('referrer','')[:110])
    print(' gps:', fields.get('gps_adid'), 'uuid:', fields.get('android_uuid'))
    for k in ('click_time','click_time_server','install_begin_time','install_begin_time_server','installed_at','created_at','sent_at'):
        print('  %-26s %s' % (k, fields.get(k)))
    # re-mint check: derive sec from sent_at (local +0530 -> unix)
    from datetime import datetime, timezone
    import re as _re
    def to_sec(s):
        m = _re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z([+-]\d\d)(\d\d)', s)
        base = datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
        off = int(m.group(3))*3600 + int(m.group(4))*60
        return int(base - off)
    sec = to_sec(fields['sent_at'])
    # extract nonce? mint with random nonce can't match; instead verify attrs + lengths + header seed rule
    m = _re.search(r'signature="([0-9A-F]+)"', auth)
    blob = m.group(1)
    print('  blob 608?', len(blob)==608, 'attrs ok?', all(x in auth for x in ['1300000','adj7','headers_id="8"','native_version="3.62.0"']))
    # header first 16 bytes = first 32 hex chars; check session/click same-sec share header
    print('  header16:', blob[:32])

# structural diff live vs manual bodies
_, lb = load('saz_live/raw', 8); _, mb = load('saz_new/raw', 66)
lf = dict(body_fields(lb)); mf = dict(body_fields(mb))
print('\n==== field diff LIVE vs MANUAL sdk_click (non-dynamic must match) ===')
dyn = {'gps_adid','android_uuid','referrer','created_at','sent_at','installed_at','updated_at','click_time','click_time_server','install_begin_time','install_begin_time_server','partner_params','callback_params'}
for k in lf:
    if k not in mf: print('  EXTRA in live:', k); continue
    if k in dyn: continue
    if lf[k] != mf[k]: print('  VALDIFF', k, repr(lf[k]), '!=', repr(mf[k]))
print('  keys live', len(lf), 'manual', len(mf), 'order same?', list(lf.keys())==list(mf.keys()))
# encoded byte diff modulo dynamics
def mask(s, d):
    for k in d:
        if k in s: pass
    return s
import urllib.parse as up
le = up.urlencode(sorted(lf.items()))
me = up.urlencode(sorted(mf.items()))
print('  sorted-encoded equal modulo dyn?', all((lf[k]==mf[k] or k in dyn) for k in lf))
