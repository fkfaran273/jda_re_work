import os, sys, time, json, uuid
os.environ['FUNNEL_PROXY'] = ''
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_fiddler as R
R.PROXY = ''
R.SESSION_AT = 300   # genuine 33_c style: first session ~minutes after installed
gaid = str(uuid.uuid4())
uuid_and = str(uuid.uuid4())
print('gaid', gaid, flush=True)
ref = R.open_click_link(gaid)
print('reftag', ref, flush=True)
if not ref: sys.exit(1)
click_second = int(time.time()) - 1
wait = click_second + R.SESSION_AT - time.time()
print('CTIT wait %.0fs' % max(0, wait), flush=True)
if wait > 0: time.sleep(wait)
sec = R.signing_second()
sf = R.build_session_request(gaid, uuid_and, sec, click_sec=click_second)
st, b = R.call('POST', '/session', sf, R.sign(sf, 'session', sec))
print('session', st, b[:200], flush=True)
time.sleep(0.35)
sec2 = R.signing_second()
cf = R.build_click_request(gaid, uuid_and, sec2, ref, click_sec=click_second)
st2, b2 = R.call('POST', '/sdk_click', cf, R.sign(cf, 'click', sec2))
print('sdk_click', st2, b2[:160], flush=True)
time.sleep(2.6)
sec3 = R.signing_second()
af = R.build_attribution_request(gaid, uuid_and, sec3)
st3, b3 = R.call('GET', '/attribution', af, R.sign(af, 'attribution', sec3))
print('attr1', st3, b3, flush=True)
open(os.path.join(HERE, 'cit300_attr1.json'), 'w').write(json.dumps({'gaid': gaid, 'reftag': ref, 'session': b, 'attr1': b3}, indent=1))
