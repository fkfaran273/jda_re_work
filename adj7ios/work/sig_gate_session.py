# -*- coding: utf-8 -*-
"""sig_gate_session.py -- clean session-side gate test: a FRESH idfa per
variant so the 20-minute session throttle cannot confound the answer."""
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

ZERO_AUTH = ('Signature signature="' + '00' * 304 +
             '",adj_signing_id="1300000",algorithm="adj7",headers_id="8",'
             'native_version="3.62.0"')


def flip(auth):
    m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
    b = m.group(1)
    i = 60
    return auth.replace(b, b[:i] + ('0' if b[i] != '0' else '1') + b[i + 1:])


def run(mode):
    idfa = str(uuid.uuid4()).upper()
    T0 = int(time.time())
    B._IDFA = idfa
    B._IDFV = str(uuid.uuid4()).upper()
    B._DEDUPE = str(uuid.uuid4())
    B._STARTED, B._INSTALL = T0 - 1020, T0 - 29
    f = B.build_session_request(B.signing_second())
    auth = B._sign(f, "session", B.signing_second())
    if mode == "broken":
        auth = flip(auth)
    elif mode == "none":
        auth = ZERO_AUTH
    st, body = B._call("POST", "/session", f, auth)
    print("%-8s idfa=%s  -> %s  %s" % (mode, idfa[:8], st, body[:120]),
          flush=True)
    return st, body


res = {}
for mode in ("valid", "broken", "none"):
    time.sleep(1.5)
    res[mode] = run(mode)

print()
ok = {m: res[m][0] for m in res}
print("statuses:", ok)
same = len(set(ok.values())) == 1
print("SIGNATURE GATED" if not same else
      "NOT SIGNATURE GATED (all variants answered alike)")
