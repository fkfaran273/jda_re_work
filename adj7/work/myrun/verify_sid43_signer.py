"""verify_sid43_signer.py -- the precise "our signature gives non-organic"
check on today's captured paid install (payruki_again, row 43).

1. Decrypt the captured blob -> read nonce12, cert40 (real-device law).
2. Rebuild the URL query's wire map; compute clients claims with
   my generated signer (myrun/adj7_pure.py).
3. Re-mint with the same fields/nonce12/second/cert -> bytes must equal the
   captured Authorization blob (byte-exact).
4. One live replay of the MINTED Authorization header against the raw
   captured URL -> must return NON-ORGANIC 248wk8ym.
"""
import gzip
import http.client
import json
import os
import re
import sys
import urllib.parse

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun"
sys.path.insert(0, HERE)
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\adj7\work")
import adj7_pure as sg
from ks_inverse import cbc_dec  # exact inverse used by proven_audit

RAW = r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payruki_again\raw"


def load_row(idx):
    text = open(os.path.join(RAW, "%02d_c.txt" % idx), encoding="utf-8").read()
    sep = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
    head = text.split(sep, 1)[0]
    lines = head.replace("\r\n", "\n").split("\n")
    method, target, _ = lines[0].split(" ", 2)
    headers = {}
    for ln in lines[1:]:
        if ": " in ln:
            k, v = ln.split(": ", 1)
            headers[k] = v
    return method, target, headers


method, target, headers = load_row(43)
u = urllib.parse.urlsplit(target)
path = u.path + "?" + u.query
fields = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))

gen_auth = headers["Authorization"]
gen_blob = bytes.fromhex(
    re.search(r'signature="([0-9A-Fa-f]+)"', gen_auth).group(1))

# step 1: decrypt
rec = cbc_dec(gen_blob[16:272], gen_blob[:16])
s = rec.split(b"\x00")[0].decode("latin1")
A = re.search(r'"a":\s*(\d+)', s).group(1)
H = re.search(r'"b":\s*"([0-9A-Fa-f]+)"', s).group(1)
cert = re.search(r'"c":\s*"([^"]+)"', s).group(1)
D8 = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
nonce = int(A).to_bytes(8, "little") + bytes.fromhex(D8)
print("record's cert :", cert)
print("nonce12       :", nonce.hex())
print("record H      :", H)

ca = fields["created_at"].replace("Z+0530", "")
dt = __import__("datetime").datetime.strptime(ca.split(".")[0],
                                              "%Y-%m-%dT%H:%M:%S")
from datetime import timezone, timedelta
sec = int((dt - timedelta(hours=5, minutes=30)).replace(
    tzinfo=timezone.utc).timestamp())
print("created_at sec:", sec)

# step 2/3: re-mint byte-exact with our signer
our_auth = sg.sign_request(fields, "attribution", second=sec, nonce12=nonce,
                           cert_sha1=cert, client_sdk="android5.6.0",
                           include_block2=True, headers_id="8",
                           native_version="3.62.0")
our_blob = bytes.fromhex(
    re.search(r'signature="([0-9A-Fa-f]+)"', our_auth).group(1))
print("our == gen blob byte-identical:", our_blob == gen_blob)
print("header match:", sg.make_header(sec) == our_blob[:16])
print("tag ok:", sg.verify_tag(our_blob))

# step 4: replay the attribute row with our minted blob
c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
c.putheader("Client-SDK", "android5.6.0")
c.putheader("Authorization", our_auth)
c.putheader("User-Agent", headers["User-Agent"])
c.putheader("Host", "app.adjust.com")
c.putheader("Connection", "Keep-Alive")
c.putheader("Accept-Encoding", "gzip")
c.endheaders()
r = c.getresponse()
body = r.read()
if body[:2] == bytes((0x1F, 0x8B)):
    body = gzip.decompress(body)
c.close()
text = body.decode()
print("Replay of OUR-minted blob -> HTTP", r.status)
print(text[:300])
print("VERDICT:", "NON-ORGANIC" if "248wk8ym" in text else
      ("ORGANIC" if "g0bpyt5" in text else ("THROTTLED" if r.status == 400 else "other")))
