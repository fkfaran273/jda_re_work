"""Native mint oracle: run the REAL libsigner nSign (unicorn) on a map,
decrypt the blob, return (H, nonce12, cert40, blob)."""
import os
import re
import sys

WORK = r"C:\Users\Apps\Downloads\com.penti.app\adj7_work"
ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")

import json
import adj7_pure as ap
from adj7_oracle import cbc_decrypt

T = json.load(open(ADJ7 + r"\work\eb_audit\hook_truth2.json"))["4"]
nmap = T["nmap"]

import adj7s3_emu  # noqa: E402  (needs CWD=adj7_work)

emu = adj7s3_emu.Emu(verbose=False)
emu.fixed_time = 1791271810
out = emu.run(payload=bytes(32), mapobj=nmap)
if not out:
    print("MINT FAILED")
    sys.exit(1)
print("blob len:", len(out))
tag_ok = ap.verify_tag(out)
body = cbc_decrypt(out[16:272], out[:16])
rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
H = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
cert40 = re.search(r'"c": "([^"]*)"', rec).group(1)
d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
nonce12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
print("tag_ok:", tag_ok)
print("mint H     :", H)
print("device H   :", T["H"])
print("H MATCH    :", H == T["H"])
print("mint nonce :", nonce12.hex())
print("mint cert40:", cert40)
