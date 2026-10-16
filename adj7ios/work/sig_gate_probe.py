# -*- coding: utf-8 -*-
"""sig_gate_probe.py -- is the berain app signature-gated?

Send each signed endpoint with a VALID / BROKEN / ABSENT Authorization and
compare the answers.  Gated = the server rejects a bad or missing signature
(4xx invalid-signature); not gated = every variant gets the same answer.
"""
import gzip
import json
import os
import re
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_berain as B

BASE = B.BASE
IDFA = (os.environ.get("PROBE_IDFA") or str(uuid.uuid4())).upper()
IDFV = str(uuid.uuid4()).upper()
DEDUPE = str(uuid.uuid4())
T0 = int(time.time())
B._IDFA, B._IDFV, B._DEDUPE = IDFA, IDFV, DEDUPE
B._STARTED, B._INSTALL = T0 - 1020, T0 - 29


def valid_auth(fields, kind):
    sec = B.signing_second()
    return B._sign(fields, kind, sec), sec


def broken_auth(auth):
    """Same shape, one body byte flipped."""
    m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
    b = m.group(1)
    i = 60                       # inside the record body
    return auth.replace(b, b[:i] + ('0' if b[i] != '0' else '1') + b[i + 1:])


def send(label, method, path, fields, auth):
    st, body = B._call(method, path, fields, auth)
    print("%-34s -> %s  %s" % (label, st, body[:150]), flush=True)
    return st, body


print("IDFA:", IDFA, "| base:", BASE)
print()

# ---------------- /session ----------------
sfields = B.build_session_request(B.signing_second())
good, _ = valid_auth(sfields, "session")
send("session  VALID", "POST", "/session", sfields, good)
send("session  BROKEN", "POST", "/session", sfields, broken_auth(good))
send("session  NO-AUTH (None)", "POST", "/session", sfields,
     'Signature signature="' + '00' * 304 +
     '",adj_signing_id="1300000",algorithm="adj7",headers_id="8",'
     'native_version="3.62.0"')
try:
    import requests as _r
    r = _r.post(BASE + "/session",
                data=urllib.parse.urlencode(sfields).encode(),
                headers={"Client-Sdk": B.CLIENT_SDK,
                         "User-Agent": B.APP_UA,
                         "Content-Type": "application/x-www-form-urlencoded"},
                timeout=30)
    print("%-34s -> %s  %s" % ("session  NO AUTH HEADER",
                               r.status_code, r.text[:150]))
except Exception as e:
    print("session  NO AUTH HEADER ERR %r" % (e,))
print()

# ---------------- /third_party_sharing ----------------
tfields = B.build_tps_request(B.signing_second())
tgood, _ = valid_auth(tfields, "third_party_sharing")
send("tps      VALID", "POST", "/third_party_sharing", tfields, tgood)
send("tps      BROKEN", "POST", "/third_party_sharing", tfields,
     broken_auth(tgood))
print()

# ---------------- /attribution ----------------
afields = B.build_attribution_request(B.signing_second())
agood, _ = valid_auth(afields, "attribution")
send("attrib   VALID", "GET", "/attribution", afields, agood)
send("attrib   BROKEN", "GET", "/attribution", afields,
     broken_auth(agood))
send("attrib   NO-AUTH (zeros)", "GET", "/attribution", afields,
     'Signature signature="' + '00' * 304 +
     '",adj_signing_id="1300000",algorithm="adj7",headers_id="8",'
     'native_version="3.62.0"')
print()

# ---------------- /sdk_click ----------------
cfields = B.build_click_request(B.signing_second(), None, T0 - 5)
cgood, _ = valid_auth(cfields, "click")
send("sdk_click VALID", "POST", "/sdk_click", cfields, cgood)
send("sdk_click BROKEN", "POST", "/sdk_click", cfields,
     broken_auth(cgood))
