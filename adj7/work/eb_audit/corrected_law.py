"""Corrected claims law: split at 'seq' (id pinned before seq). Verify vs:
A. full event map mint H   B. 13:00 device event H   C. dump130/134/138
D. pin seq-vs-session_count order   E. regression on all other requests."""
import json
import os
import re
import sys
import urllib.parse

WORK = r"C:\Users\Apps\Downloads\com.penti.app\adj7_work"
ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
os.chdir(WORK)
sys.path.insert(0, WORK)
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")

import adj7_pure as ap
from adj7_oracle import cbc_decrypt, parse_device_blob

IDX_SEQ = ap.CLAIM_POOL.index("seq")


def build_claims_v2(kind, params, client_sdk=None, include_block2=False):
    m = dict(params)
    if include_block2:
        m.setdefault("activity_kind", kind)
        m.setdefault("client_sdk", client_sdk or "")
    profile, tail, block2 = (ap.CLAIM_POOL[:IDX_SEQ], ap.CLAIM_POOL[IDX_SEQ:-2],
                             ap.CLAIM_POOL[-2:])
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
    parts.append(ap.ADJ_SIGNING_ID)
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in block2 if m.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")


print("== A. full event map mint ==")
EV = json.load(open(ADJ7 + r"\work\eb_audit\hook_truth2.json"))["4"]["nmap"]
claimsA = build_claims_v2("event", EV, client_sdk="android5.6.0",
                          include_block2=True)
HA = ap.commitment_digest(claimsA, bytes.fromhex("d666bf3444ddccca7eada76a"),
                          b"\x00" * 40).hex().upper()
print("   corrected:", HA, "mint H: 2E40D41AF54C67B17E983E69084A1BAE2B9A92F6E8FB4D9976BEF9D557C35044")
print("   MATCH:", HA == "2E40D41AF54C67B17E983E69084A1BAE2B9A92F6E8FB4D9976BEF9D557C35044")

print("== B. 13:00 device event (hook nSign map + device nonce/cert) ==")
T4 = json.load(open(ADJ7 + r"\work\eb_audit\hook_truth2.json"))["4"]
claimsB = build_claims_v2("event", T4["nmap"], client_sdk="android5.6.0",
                          include_block2=True)
HB = ap.commitment_digest(claimsB, bytes.fromhex(T4["nonce12"]),
                          T4["cert40"].encode()).hex().upper()
print("   corrected:", HB, "device:", T4["H"])
print("   MATCH:", HB == T4["H"])

print("== C. dump events 130/134/138 (wire maps) ==")
REQS = json.load(open(ADJ7 + r"\work\eb_audit\requests.json"))
for idx in (130, 134, 138):
    r = REQS[idx]
    f = dict(urllib.parse.parse_qsl(
        (r["target"].split("?", 1)[1] if r["method"] == "GET" and "?" in r["target"]
         else bytes.fromhex(r["body"]).decode("latin1")), keep_blank_values=True))
    dev = parse_device_blob(r["headers"]["Authorization"])
    claims = build_claims_v2("event", f, client_sdk="android5.6.0",
                             include_block2=True)
    H = ap.commitment_digest(claims, bytes.fromhex(dev["nonce12"]),
                             dev["device_cert40"].encode()).hex().upper()
    print("   idx %d: %s  device %s  MATCH: %s"
          % (idx, H[:24], dev["device_H"][:24], H == dev["device_H"]))

print("== D. pin seq vs session_count order (mint) ==")
import adj7s3_emu
mD = {"activity_kind": "event", "client_sdk": "android5.6.0",
      "seq": "1", "session_count": "7"}
emu = adj7s3_emu.Emu(verbose=False)
emu.fixed_time = 1791271810
out = emu.run(payload=b"\x00" * 32, mapobj=mD, arg4=8)
body = cbc_decrypt(out[16:272], out[:16])
rec = body.rstrip(b"\x10").rstrip(b"\x00").decode("latin1", "replace")
HD = re.search(r'"b": "([0-9A-F]{64})"', rec).group(1)
c40 = re.search(r'"c": "([^"]*)"', rec).group(1).encode("latin1")
d8 = re.search(r'"d": "([0-9A-F]{8})"', rec).group(1)
a = int(re.search(r'"a":\s*(\d+)', rec).group(1))
n12 = a.to_bytes(8, "little") + bytes.fromhex(d8)
for tag, cl in (("seq-then-sc", "1300000" + "1" + "7" + "eventandroid5.6.0"),
                ("sc-then-seq", "1300000" + "7" + "1" + "eventandroid5.6.0")):
    ok = ap.commitment_digest(cl.encode(), n12, c40).hex().upper() == HD
    print("   %-12s %s" % (tag, ok))

print("== E. regression: all session/click/attr requests (old dump 127-144) ==")
KINDS = {"/session": "session", "/sdk_click": "click", "/event": "event",
         "/attribution": "attribution"}
alls = []
for idx in range(127, 145):
    r = REQS[idx]
    path = r["target"].split("?")[0]
    kind = KINDS[path]
    sdk = r["headers"].get("Client-SDK", "")
    f = dict(urllib.parse.parse_qsl(
        (r["target"].split("?", 1)[1] if r["method"] == "GET" and "?" in r["target"]
         else bytes.fromhex(r["body"]).decode("latin1")), keep_blank_values=True))
    dev = parse_device_blob(r["headers"]["Authorization"])
    claims = build_claims_v2(kind, f, client_sdk=sdk, include_block2=True)
    H = ap.commitment_digest(claims, bytes.fromhex(dev["nonce12"]),
                             dev["device_cert40"].encode()).hex().upper()
    alls.append(H == dev["device_H"])
    print("   idx %d %-11s %s" % (idx, kind, "MATCH" if H == dev["device_H"] else "NO"))

print("== F. hook click/attr regression (v2) ==")
HT = json.load(open(ADJ7 + r"\work\eb_audit\hook_truth2.json"))
for n in ("2", "3"):
    T = HT[n]
    claims = build_claims_v2(T["kind"], T["nmap"], client_sdk="android5.6.0",
                             include_block2=True)
    H = ap.commitment_digest(claims, bytes.fromhex(T["nonce12"]),
                             T["cert40"].encode()).hex().upper()
    print("   SIGN#%s %-11s %s" % (n, T["kind"], "MATCH" if H == T["H"] else "NO"))
