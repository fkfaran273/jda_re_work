"""secmap2.py - recover EVERY wh4 blob's signing second via the header law.
FAST version: bound the search with the sign_input created_at (+0200 suffix
= UTC+2 wall clock of claim creation; signing follows within minutes/hours).
Search created_at-1h .. created_at+6h per blob instead of 400 days.
"""
import os
import json
import struct
import datetime
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from header_gen import make_header

W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))


def sec_of(blob, hint):
    for s in range(hint - 3600, hint + 6 * 3600):
        if make_header(s) == blob[:16]:
            return s
    return None


print("=== invert 8 wh4 headers -> seconds ===")
for i, n in enumerate(W["nsigns"]):
    blob = bytes.fromhex(n["hex"])
    si = W["sign_inputs"][i]
    m = si["order"]
    k = m.find("created_at\x01")
    created = m[k + 11:k + 36] if k >= 0 else "?"
    try:
        dt = datetime.datetime.strptime(created[:24], "%Y-%m-%dT%H:%M:%S.%f")
        hint = int(dt.replace(tzinfo=datetime.timezone.utc).timestamp()) - 7200
    except Exception:
        hint = 1789240512
    sec = sec_of(blob, hint)
    print("nsign%d head=%s created=%s -> sec=%s" % (i, blob[:8].hex(), created, sec))
print("done")
