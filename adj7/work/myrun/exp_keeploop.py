import os, sys, time, json, uuid, re
os.environ['FUNNEL_PROXY'] = ''
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_fiddler as R
R.PROXY = ''
# KEEP loop_id: monkeypatch the strip out by wrapping _get chain manually
orig_get = R._get
gaid = str(uuid.uuid4())
uuid_and = str(uuid.uuid4())
print('gaid', gaid, flush=True)
# manual chain keeping ip_address macro
url = R._fill_device_id(R._subst(R.LINK, gaid), gaid)
if 'gps_adid=' not in url: url += '&gps_adid=' + gaid
print('start', url[:160], flush=True)
st, hd, tx = R._get(url, use_browser=True)
loc = hd.get('Location') or hd.get('location') or ''
print('mobpine', st, 'loc', loc[:260], flush=True)
loc = R._fill_device_id(loc, gaid)  # NO loop_id strip
print('kept loop_id?', 'loop_id' in loc, flush=True)
st2, hd2, tx2 = R._get(loc, use_browser=True)
loc2 = hd2.get('Location') or hd2.get('location') or ''
print('adjust', st2, 'next', loc2[:200], flush=True)
ref = R._reftag_in(loc2)
print('reftag', ref, flush=True)
if not ref: sys.exit(1)
click_second = int(time.time()) - 1
wait = click_second + R.SESSION_AT - time.time()
if wait > 0: time.sleep(wait)
sec = R.signing_second()
sf = R.build_session_request(gaid, uuid_and, sec, click_sec=click_second)
st3, b3 = R.call('POST', '/session', sf, R.sign(sf, 'session', sec))
print('session', st3, b3[:200], flush=True)
time.sleep(0.35)
sec2 = R.signing_second()
cf = R.build_click_request(gaid, uuid_and, sec2, ref, click_sec=click_second)
st4, b4 = R.call('POST', '/sdk_click', cf, R.sign(cf, 'click', sec2))
print('sdk_click', st4, b4[:160], flush=True)
time.sleep(2.6)
sec3 = R.signing_second()
af = R.build_attribution_request(gaid, uuid_and, sec3)
st5, b5 = R.call('GET', '/attribution', af, R.sign(af, 'attribution', sec3))
print('attr1', st5, b5, flush=True)
