"""Mint-oracle probe: pool-law check on mints of click vs event maps;
arg4 variants."""
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
EV = HT["4"]   # event
CL = HT["2"]   # click


def mint(mapobj, sec, arg4=8, payload=b"\x00" * 32):
    emu = adj7s3_emu.Emu(verbose=False)
    emu.fixed_time = sec
    out = emu.run(payload=payload, mapobj=mapobj, arg4=arg4)
    assert out and len(out) == 304, out
    body = cbc_decrypt(out[16:272], out[:16])
    rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
    H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
    cfield = re.search(r'"c": "([^"]*)"', rec).group(1)
    d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
    a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
    nonce12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
    return {"H": H, "nonce12": nonce12, "cert40": cfield, "blob": out,
            "rec": rec}


def pool_law_check(tag, m, minted, kind, sdk):
    nonce12, cert40 = minted["nonce12"], minted["cert40"].encode("latin1")
    for b2 in (True, False):
        claims = ap.build_claims(kind, m, client_sdk=sdk, include_block2=b2)
        H = ap.commitment_digest(claims, nonce12, cert40).hex().upper()
        if H == minted["H"]:
            print("%-28s POOL-LAW MATCH (block2=%s)" % (tag, b2))
            return True
    print("%-28s no pool-law match (mint H=%s...)" % (tag, minted["H"][:16]))
    return False


ev_map = EV["nmap"]
cl_map = CL["nmap"]

print("== event map, arg4=8 ==")
m1 = mint(ev_map, 1791271810, arg4=8)
print("   mint H:", m1["H"], " device H:", EV["H"], " eq:", m1["H"] == EV["H"])
print("   cert40 field:", repr(m1["cert40"]))
pool_law_check("event arg4=8", ev_map, m1, "event", "android5.6.0")

print("== click map, arg4=8 ==")
m3 = mint(cl_map, 1791271805, arg4=8)
print("   mint H:", m3["H"], " device H:", CL["H"], " eq:", m3["H"] == CL["H"])
pool_law_check("click arg4=8", cl_map, m3, "click", "android5.6.0")
