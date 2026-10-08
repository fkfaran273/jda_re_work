import os, sys, time, json, uuid
os.environ['FUNNEL_PROXY'] = ''
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_fiddler as R
R.PROXY = ''
gaid = str(uuid.uuid4())
uuid_and = str(uuid.uuid4())
print('gaid', gaid, flush=True)
print('uuid', uuid_and, flush=True)
reftag = R.open_click_link(gaid)
print('reftag', reftag, flush=True)
if not reftag:
    print('NO REFTAG - stop'); sys.exit(1)
click_second = int(time.time()) - 1
target = click_second + R.SESSION_AT
wait = target - time.time()
print('CTIT wait %.0fs' % max(0, wait), flush=True)
if wait > 0: time.sleep(wait)
sec = R.signing_second()
sf = R.build_session_request(gaid, uuid_and, sec, click_sec=click_second)
auth = R.sign(sf, 'session', sec)
st, body = R.call('POST', '/session', sf, auth)
print('session', st, body[:220], flush=True)
time.sleep(0.35)
sec2 = R.signing_second()
cf = R.build_click_request(gaid, uuid_and, sec2, reftag, click_sec=click_second)
auth2 = R.sign(cf, 'click', sec2)
st2, body2 = R.call('POST', '/sdk_click', cf, auth2)
print('sdk_click', st2, body2[:160], flush=True)
time.sleep(2.6)
sec3 = R.signing_second()
af = R.build_attribution_request(gaid, uuid_and, sec3)
auth3 = R.sign(af, 'attribution', sec3)
st3, body3 = R.call('GET', '/attribution', af, auth3)
print('attr1', st3, body3, flush=True)
open(os.path.join(HERE, 'direct_attr1.json'), 'w').write(json.dumps({'gaid': gaid, 'uuid': uuid_and, 'reftag': reftag, 'session': body, 'attr1': body3}, indent=1))
