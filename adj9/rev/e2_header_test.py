# e2_header_test.py - test whether each E1 mint's 16-B header equals
# Random3(second_i) for its OWN signing second (i.e., the header is fully
# deterministic given the second; the E1 "192/192 differ" may be second-only).
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import Random3, make_header

def load(p):
    raw = open(p, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        raw = raw.decode("utf-16").encode("utf-8")
    return json.loads(raw)

m1 = load(os.path.join(os.environ["TEMP"], "mo1.json"))
m2 = load(os.path.join(os.environ["TEMP"], "mo2.json"))
B1 = base64.b64decode(m1["blobB64"])
B2 = base64.b64decode(m2["blobB64"])
print("blob1 hdr", B1[:16].hex())
print("blob2 hdr", B2[:16].hex())
s1 = (m1.get("stamp") or (m1.get("mapPairs") or []))
print("stamp1", m1.get("stamp"), "stamp2", m2.get("stamp"))
print("stamps equal:", m1.get("stamp") == m2.get("stamp"))

import datetime, calendar
def stamp_to_sec(stamp):
    # 2026-09-17T17:04:14.525Z+0530 -> local wall clock in +0530
    dt = datetime.datetime.strptime(stamp[:23], "%Y-%m-%dT%H:%M:%S.%f")
    off = stamp[-5:]
    hrs, mins = int(off[1:3]), int(off[3:5])
    delta = datetime.timedelta(hours=hrs, minutes=mins)
    if off[0] == '+':
        dt_utc = dt - delta
    else:
        dt_utc = dt + delta
    return calendar.timegm(dt_utc.timetuple())

for name, m, B in (("b1", m1, B1), ("b2", m2, B2)):
    sec = stamp_to_sec(m["stamp"])
    hits = []
    for off in range(-3, 4):
        if make_header(sec + off) == B[:16]:
            hits.append(sec + off)
    print(name, "stamp-sec", sec, "Random3 hits(stamp±3):", hits,
          "| hdr", B[:16].hex(), "| expect", make_header(sec).hex())
print("bodies equal:", B1[16:] == B2[16:])
common = sum(1 for a, b in zip(B1, B2) if a == b)
print("common bytes:", common, "/192")
