"""decisive: rebuild the genuine sid-44 attribution blob byte-exact from
its own fields/nonce/second/cert -- if it matches, adj7_pure is a faithful
reproduction and server-side handling of fresh requests is the question."""
import json, re, sys, urllib.parse
from datetime import datetime, timezone, timedelta

sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7')
sys.path.insert(0, r'C:\Users\Apps\Downloads\com.penti.app\adj7\cap')
import adj7_pure as sg
from decrypt_rec import cbc_decrypt

D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
e = next(x for x in D if str(x["sid"]) == "44")
auth = None
for k, v in e["request_headers"]:
    if k.lower() == "authorization":
        auth = v
blob = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1))
rec = cbc_decrypt(blob[16:272], blob[:16]).rstrip(b"\x10").rstrip(b"\x00")
a = re.search(rb'"a":\s+(\d+)', rec).group(1).decode()
d8 = re.search(rb'"d": "([0-9A-F]+)"', rec).group(1).decode()
cert = re.search(rb'"c": "([^"]+)"', rec).group(1).decode()
nonce12 = int(a).to_bytes(8, "little") + bytes.fromhex(d8)

fields = dict(urllib.parse.parse_qsl(e["url"].split("?", 1)[1], keep_blank_values=True))
ca = fields["created_at"]  # 2026-10-06T15:47:41.741Z+0530
u = ca.replace("Z+0530", "")
dt = datetime.strptime(u.split(".")[0], "%Y-%m-%dT%H:%M:%S")
sec = int((dt - timedelta(hours=5, minutes=30)).replace(tzinfo=timezone.utc).timestamp())
print("signing second:", sec, "| nonce:", nonce12.hex())

blob2, auth2 = sg.sign_request(
    fields, "attribution", second=sec, nonce12=nonce12, cert_sha1=cert,
    client_sdk="android5.6.0", include_block2=True,
    headers_id="8", native_version="3.62.0")
print("byte-exact vs genuine:", blob2 == blob)
print("ours   :", blob2.hex().upper()[:64])
print("genuine:", blob.hex().upper()[:64])
