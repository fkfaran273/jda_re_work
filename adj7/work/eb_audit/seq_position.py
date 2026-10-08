"""Pin seq's true pool position: mint one map with country + all tail keys,
enumerate insertion points of seq's value."""
import itertools
import json
import os
import re
import sys

WORK = r"C:\Users\Apps\Downloads\com.penti.app\adj7_work"
ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")

import adj7_pure as ap
from adj7_oracle import cbc_decrypt
import adj7s3_emu

EV = json.load(open(ADJ7 + r"\work\eb_audit\hook_truth2.json"))["4"]["nmap"]

m = {"activity_kind": "event", "client_sdk": "android5.6.0",
     "country": EV["country"], "seq": EV["seq"],
     "session_count": EV["session_count"], "session_length": EV["session_length"],
     "subsession_count": EV["subsession_count"], "time_spent": EV["time_spent"],
     "tracking_enabled": EV["tracking_enabled"]}

emu = adj7s3_emu.Emu(verbose=False)
emu.fixed_time = 1791271810
out = emu.run(payload=b"\x00" * 32, mapobj=m, arg4=8)
assert out and len(out) == 304
body = cbc_decrypt(out[16:272], out[:16])
rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
c40 = re.search(r'"c": "([^"]*)"', rec).group(1).encode("latin1")
d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
n12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
print("mint H:", H)

# parts without seq: profile [IN], id, tail [1,5,1,5,1], block2 [event, android5.6.0]
no_seq = ["IN", ap.ADJ_SIGNING_ID, "1", "5", "1", "5", "1", "event", "android5.6.0"]
seqv = "1"
found = []
# insert seq value at each gap of no_seq
for i in range(len(no_seq) + 1):
    cand = no_seq[:i] + [seqv] + no_seq[i:]
    cl = "".join(cand)
    if ap.commitment_digest(cl.encode("latin1"), n12, c40).hex().upper() == H:
        found.append(("insert@%d" % i, cl))
# also: seq REMOVED entirely (tail would lose one '1' - ambiguous, skip)
# also: seq replaces id / id removed variants with seq present
for cand in ([seqv] + no_seq[1:], no_seq, no_seq + [seqv], [seqv] + no_seq):
    cl = "".join(cand)
    if ap.commitment_digest(cl.encode("latin1"), n12, c40).hex().upper() == H:
        found.append(("special", cl))
print("matches:", found)
