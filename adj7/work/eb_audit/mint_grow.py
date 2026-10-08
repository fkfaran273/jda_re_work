"""Grow the minimal seq map one key at a time; report where pool law breaks."""
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


def pool_ok(m):
    kind = m.get("activity_kind", "event")
    sdk = m.get("client_sdk", "android5.6.0")
    H, n12, c40 = mint(m)
    for b2 in (True, False):
        claims = ap.build_claims(kind, m, client_sdk=sdk, include_block2=b2)
        if ap.commitment_digest(claims, n12, c40).hex().upper() == H:
            return "POOL-LAW(b2=%s)" % b2
    return "TRANSFORMED"


base = {"activity_kind": "event", "client_sdk": "android5.6.0", "seq": "1"}
pool_keys = [k for k in ap.CLAIM_POOL if k not in ("activity_kind", "client_sdk",
                                                   "seq") and EV.get(k)]
cands = ["event_token", "event_count", "callback_params", "created_at",
         "session_count", "session_length", "time_spent", "subsession_count",
         "tracking_enabled", "country", "gps_adid"]
for k in cands:
    m = dict(base)
    m[k] = EV[k]
    print("%-18s %s -> %s" % ("seq+" + k, EV[k][:40], pool_ok(m)), flush=True)
