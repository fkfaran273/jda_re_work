"""replay_attribution_check.py (my copy-area probe, originals untouched).

1. VERBATIM: genuine sid-44 URL + genuine Authorization from the SAZ raw,
   byte-exact, over http.client (same as booking_diff probe).
2. FRESH-MINT: same 22 fields, fresh created_at/sent_at + fresh nonce via
   our adj7_pure copy (with secret_id pool fix), capture-faithful tail.
3. NO-AUTH: verbatim URL, no Authorization header.
"""
import gzip
import http.client
import json
import re
import sys
import time
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun"
sys.path.insert(0, HERE)
import adj7_pure as sg

sg.CERT_SHA1 = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
sg.CLIENT_SDK = "android5.6.0"

SAZ = r"C:\Users\Apps\Downloads\payrupik_new_.saz"
z = zipfile.ZipFile(SAZ)
raw = z.open("raw/44_c.txt").read()
head, _, _ = raw.partition(b"\r\n\r\n")
lines = head.decode().split("\r\n")
target = lines[0].split(" ")[1]
sp = urllib.parse.urlsplit(target)
path = sp.path + "?" + sp.query
auth = re.search(r"Authorization: (.+)", head.decode()).group(1).strip()
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"

FIELDS = dict(urllib.parse.parse_qsl(sp.query, keep_blank_values=True))


def get(path, auth_val):
    c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    c.putheader("Client-SDK", "android5.6.0")
    if auth_val:
        c.putheader("Authorization", auth_val)
    c.putheader("User-Agent", UA)
    c.putheader("Host", "app.adjust.com")
    c.putheader("Connection", "Keep-Alive")
    c.putheader("Accept-Encoding", "gzip")
    c.endheaders()
    r = c.getresponse()
    body = r.read()
    if body[:2] == bytes((0x1F, 0x8B)):
        body = gzip.decompress(body)
    c.close()
    return r.status, body.decode()


def verdict_of(status, text):
    if status == 400:
        return "THROTTLED/ASK_IN"
    if "248wk8ym" in text:
        return "NON-ORGANIC ***"
    if "g0bpyt5" in text:
        return "Organic"
    return "other"


print("== 1. VERBATIM (genuine URL + genuine auth) ==")
s, t = get(path, auth)
print("HTTP", s, "->", verdict_of(s, t))
print(t[:300])
print()

print("== 2. FRESH-MINT (our signer, fresh times+nonce, faithful tail 8/3.62.0) ==")
now = datetime.now(timezone(timedelta(hours=5, minutes=30)))
stamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (now.microsecond // 1000) + "Z+0530"
f = dict(FIELDS)
f["created_at"] = stamp
f["sent_at"] = stamp
sec = int(time.time())
auth2 = sg.mint_adj7("attribution", f, unix_sec=sec,
                     client_sdk="android5.6.0", include_block2=True)
auth2 = re.sub(r'headers_id="[^"]*"', 'headers_id="8"', auth2)
auth2 = re.sub(r'native_version="[^"]*"', 'native_version="3.62.0"', auth2)
blob = bytes.fromhex(re.search(r'signature="([0-9A-Fa-f]+)"', auth2).group(1))
# sanity: tag + header laws on our own mint
tag_ok = __import__("hmac").new(sg.DK37, blob[16:272],
                                __import__("hashlib").sha256).digest() == blob[272:304]
print("mint 304B tag_ok=%s header_ok=%s" % (tag_ok, blob[:16] == sg.make_header(sec)))
q = urllib.parse.urlencode(f, quote_via=urllib.parse.quote)
s, t = get("/attribution?" + q, auth2)
print("HTTP", s, "->", verdict_of(s, t))
print(t[:300])
print()

print("== 3. NO-AUTH (verbatim URL, no signature) ==")
s, t = get(path, None)
print("HTTP", s, "->", verdict_of(s, t))
print(t[:300])
