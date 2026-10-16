# -*- coding: utf-8 -*-
"""verify_berain_booking.py -- re-read the booked berain row with our fresh
signature (the ARM read): the stored booking must persist."""
import json
import os
import sys
import time
import urllib.parse
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_berain as B

lr = json.load(open(os.path.join(HERE, "last_run_berain.json")))
print("stored booking:", json.dumps(lr.get("attribution"))[:220])
print()

B._IDFA = os.environ.get("FUNNEL_IDFA") or lr["idfa"]
B._IDFV = lr["idfv"]
B._DEDUPE = lr["dedupe"]
B._STARTED = int(time.time()) - 1020
B._INSTALL = int(time.time()) - 29

sec = B.signing_second()
af = B.build_attribution_request(sec, "backend")
auth = B._sign(af, "attribution", sec)
st, body = B._call("GET", "/attribution", af, auth)
print("armed re-read ->", st)
print(body[:400])
v = json.loads(body).get("attribution") or {}
print()
print("network  :", v.get("network"))
print("tracker  :", v.get("tracker_token"), "|", v.get("tracker_name"))
print("campaign :", v.get("campaign"), "| adgroup:", v.get("adgroup"))
print("engaged  :", v.get("engagement_time"))
