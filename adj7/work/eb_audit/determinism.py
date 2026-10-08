"""Determinism probe: mint the SAME map several times; compare H/nonce;
also vary fixed_time."""
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
ID = ap.ADJ_SIGNING_ID
m = {"activity_kind": "event", "client_sdk": "android5.6.0",
     "seq": "1", "country": "IN"}
law = "IN" + ID + "1" + "eventandroid5.6.0"
print("pool-law claims:", law)


def mint(mapobj, sec):
    emu = adj7s3_emu.Emu(verbose=False)
    emu.fixed_time = sec
    out = emu.run(payload=b"\x00" * 32, mapobj=mapobj, arg4=8)
    assert out and len(out) == 304
    body = cbc_decrypt(out[16:272], out[:16])
    rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
    H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
    c40 = re.search(r'"c": "([^"]*)"', rec).group(1).encode("latin1")
    d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
    a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
    n12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
    ok = ap.commitment_digest(law.encode(), n12, c40).hex().upper() == H
    return H, n12, c40, ok


for trial, sec in enumerate([1791271810, 1791271810, 1791271810,
                             1791271800, 1791271900]):
    H, n12, c40, ok = mint(m, sec)
    print("trial %d sec=%d H=%s nonce=%s pool-law=%s"
          % (trial, sec, H[:24], n12.hex(), ok))
