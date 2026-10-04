"""valid_synth.py - offline gate: does a lawful region produce an exit-clean blob?"""
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_forge as F
from region_synth import synth_region, check


def ws(words):
    return b"".join(struct.pack(">I", w & 0xFFFFFFFF) for w in words)


W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
si = W["sign_inputs"][W["golden_sign_input_idx"]]
val = {}
for part in si["order"].split("\x02"):
    if "\x01" in part:
        k, v = part.split("\x01", 1)
        val[k] = v

d0, d2, d4 = synth_region()
assert check(d0, d4)
sec = int(time.time())
st, blob, desc, unp = F.make_signature_law(val, "session", second=sec,
                                           d0=ws(d0), d2=ws([d2]), d4=ws(d4))
print("status", st, "blob", len(blob), "B", "unpadded", unp, flush=True)
print("blob head", blob[:16].hex(), flush=True)
from header_gen import make_header
print("header law:", blob[:16] == make_header(sec), flush=True)
