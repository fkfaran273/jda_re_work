"""DECISIVE check: does the genuine hunch attribution response also contain
installed_at? Yes - from row 32: installed_at present.
And genuine row 29 session response's installed_at equals its own 2026-10-08T06:58:38Z which is slot.
What we DON'T know: what make sour session/click requests produce a PAID response,
i.e. whether our wire bytes are truly (in)distinguishable.
Next test perthe user's goal: send a GARBAGE signature on our exact body to see if
the SERVER treats it as an invalid-signature response (conclusive) vs Organic.
"""
import os, sys, time
os.environ['FUNNEL_PROXY'] = ''
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_hunch as H
import re

gaid = '9c9e82d0-9711-4030-9334-23bb871dd1fc'
sec = H.signing_second()
sf = H.build_session(gaid, '9c9e82d0-9711-4030-9334-23bb871dd1fc', sec, int(time.time()) - 200)
auth = H.sign(sf, 'session', sec)
# corrupt the blob hex: flip one byte in the body section
m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
b = m.group(1)
pos = 40 + 2  # byte 20 of body (after 16-B header)
fb = b[:pos] + ('0' if b[pos] != '0' else '1') + b[pos+1:]
bad = auth.replace(b, fb)
st, body = H.call('POST', '/session', sf, bad)
print('GARBAGE-SIG session ->', st, body[:200], flush=True)
# and a valid-signature control
auth_ok = H.sign(sf, 'session', sec)
st2, body2 = H.call('POST', '/session', sf, auth_ok)
print('VALID-SIG session ->', st2, body2[:200], flush=True)
