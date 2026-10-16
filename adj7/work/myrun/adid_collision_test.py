# -*- coding: utf-8 -*-
"""adid_collision_test.py -- are our Android sessions device-unique?

Symptom: three consecutive Android sessions with three DIFFERENT
gps_adid / android_uuid values all resolved to ONE adid
(f81a2cff913db0d9dfc7a0a3c76cce3c) and answered 400 "request check interval
failed" -- a per-adid throttle.  So Adjust is keying the device on something
that does NOT vary between our runs (the fingerprint: hardware_name,
os_build, device_name, api_level are all constant).

A real SDK always sends primary_dedupe_token (the install dedupe token);
our Android builders never send it.  Test:

  S1  gaid A / android_uuid A                      (current shape)
  S2  gaid B / android_uuid B                      (current shape)
  S3  gaid C / android_uuid C + primary_dedupe_token C

Distinct adids and 200s mean the identity is finally device-unique.
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_bubble_android as A


def one(label, with_dedupe):
    gaid = uuid.uuid4().hex.upper()
    auuid = str(uuid.uuid4())
    sec = A.signing_second()
    sf = A.build_session(gaid, auuid, sec, int(time.time()) - 30)
    if with_dedupe:
        sf["primary_dedupe_token"] = str(uuid.uuid4())
    st, body = A.call("POST", "/session", sf, A.sign(sf, "session", sec))
    try:
        p = json.loads(body)
    except ValueError:
        p = {}
    print("%-34s gaid=%s.. adid=%s ask_in=%s  %s"
          % (label, gaid[:8], p.get("adid"), p.get("ask_in"),
             (p.get("error") or "OK")[:60]), flush=True)
    return p.get("adid"), st


if __name__ == "__main__":
    adids = []
    for i in range(2):
        adids.append(one("S%d current shape (no dedupe)" % (i + 1), False)[0])
        time.sleep(3)
    adids.append(one("S3 + primary_dedupe_token", True)[0])

    uniq = set(a for a in adids if a)
    print()
    print("adids:", adids)
    print("distinct adids: %d of %d" % (len(uniq), len([a for a in adids if a])))
    if len(uniq) > 1:
        print(">>> device identity is now UNIQUE -- the dedupe token fixed it")
    else:
        print(">>> still ONE device: identity is not the gps_adid either")