"""Diagnostic on saz session row 17: parser diff, value-variant sweeps."""
import json, os, sys, zipfile, re
from urllib.parse import parse_qsl, unquote_plus

sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adj7_pure as ap
from rd_core import H_of

HERE = os.path.dirname(os.path.abspath(__file__))
rows = json.load(open(os.path.join(HERE, "rows_fresh.json")))
crypto = json.load(open(os.path.join(HERE, "crypto_report.json")))

r = rows[17]; c = crypto[17]
nonce12 = bytes.fromhex(c["_nonce"]); cert40 = bytes.fromhex(c["_cert"]); Hd = c["_H"]

z = zipfile.ZipFile(r"C:\Users\Apps\Downloads\payruki_again.saz")
raw32 = z.read("raw/32_c.txt")
hm = raw32.find(b"\r\n\r\n")
head, rest = raw32[:hm], raw32[hm + 4:]
mcl = re.search(rb"(?i)content-length:\s*(\d+)", head)
cl = int(mcl.group(1)) if mcl else len(rest)
body = rest[:cl].decode("latin1")
print("CL:", cl, "rest len:", len(rest), "trailing after body:", rest[cl:][:20])

f_parseqsl = dict(parse_qsl(body, keep_blank_values=True))
print("my keys == parse_qsl keys:", set(f_parseqsl) == set(r["fields"]))
diffs = [(k, f_parseqsl.get(k), r["fields"].get(k))
         for k in sorted(set(f_parseqsl) | set(r["fields"]))
         if f_parseqsl.get(k) != r["fields"].get(k)]
print("value diffs:", diffs)

for label, fields in (("mine", r["fields"]), ("parse_qsl", f_parseqsl)):
    claims = ap.build_claims("session", fields, client_sdk="android5.6.0",
                             include_block2=True)
    H = H_of(claims, nonce12, cert40).hex().upper()
    print(label, "H match:", H == Hd)

pairs_raw = [kv.split("=", 1) for kv in body.split("&") if "=" in kv]
rawmap = {unquote_plus(k): v for k, v in pairs_raw}
base = dict(r["fields"])
hit = None
for k in base:
    vf = dict(base); vf[k] = rawmap.get(k, base[k])
    claims = ap.build_claims("session", vf, client_sdk="android5.6.0",
                             include_block2=True)
    if H_of(claims, nonce12, cert40).hex().upper() == Hd:
        hit = k; print("RAW-VALUE HIT:", k)
print("single raw-value sweep hit:", hit)

claims = ap.build_claims("session", rawmap, client_sdk="android5.6.0",
                         include_block2=True)
print("all-raw H match:", H_of(claims, nonce12, cert40).hex().upper() == Hd)
