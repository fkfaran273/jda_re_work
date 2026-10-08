"""Bisect the event-claims trigger with the mint oracle."""
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

HT = json.load(open(ADJ7 + r"\work\eb_audit\hook_truth2.json"))
EV = HT["4"]["nmap"]
CL = HT["2"]["nmap"]
SPLIT = ap.CLAIM_POOL.index("session_count")


def mint(mapobj, sec=1791271810):
    emu = adj7s3_emu.Emu(verbose=False)
    emu.fixed_time = sec
    out = emu.run(payload=b"\x00" * 32, mapobj=mapobj, arg4=8)
    assert out and len(out) == 304, "mint failed"
    body = cbc_decrypt(out[16:272], out[:16])
    rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
    H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
    c = re.search(r'"c": "([^"]*)"', rec).group(1).encode("latin1")
    d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
    a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
    return H, a.to_bytes(8, "little") + bytes.fromhex(d8), c


def pool_ok(tag, m):
    kind = m.get("activity_kind", "event")
    sdk = m.get("client_sdk", "android5.6.0")
    H, nonce12, cert40 = mint(m)
    for b2 in (True, False):
        claims = ap.build_claims(kind, m, client_sdk=sdk, include_block2=b2)
        if ap.commitment_digest(claims, nonce12, cert40).hex().upper() == H:
            print("%-40s POOL-LAW (block2=%s)" % (tag, b2))
            return True
    print("%-40s TRANSFORMED" % tag)
    return False


# A: event map with activity_kind flipped to click
mA = dict(EV); mA["activity_kind"] = "click"
pool_ok("event-map act=click", mA)

# E: click map with activity_kind flipped to event
mE = dict(CL); mE["activity_kind"] = "event"
pool_ok("click-map act=event", mE)

# C: event map, pool keys only (incl. activity_kind/client_sdk)
mC = {k: v for k, v in EV.items() if k in ap.CLAIM_POOL}
pool_ok("event-map pool-keys-only", mC)

# B: event map with activity_kind=session
mB = dict(EV); mB["activity_kind"] = "session"
pool_ok("event-map act=session", mB)
