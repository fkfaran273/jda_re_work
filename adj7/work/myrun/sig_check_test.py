"""Does the server reject a garbage signature even when the session is throttled?

We got 400 on BOTH garbage and valid session here because this adid is throttled
('Ignoring too frequent session') -- the throttle check precedes signature.
To isolate the signature check, use a FRESH adid and a garbage Authorization."""
import os, sys, time, uuid, urllib.parse
os.environ['FUNNEL_PROXY'] = ''
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_hunch as H
import re

gaid = str(uuid.uuid4())
sec = H.signing_second()
sf = H.build_session(gaid, str(uuid.uuid4()), sec, int(time.time()) - 200)
auth = H.sign(sf, 'session', sec)
m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
b = m.group(1)
pos = 40 + 2
fb = b[:pos] + ('0' if b[pos] != '0' else '1') + b[pos+1:]
bad = auth.replace(b, fb)
st, body = H.call('POST', '/session', sf, bad)
print('GARBAGE-SIG fresh session ->', st, body[:200], flush=True)
st2, body2 = H.call('POST', '/session', sf, auth)
print('VALID-SIG   fresh session ->', st2, body2[:200], flush=True)
