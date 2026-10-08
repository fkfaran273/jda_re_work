"""probe_g_recheck.py (copies only): THE signature-rule check.
Mint sid-44 with OUR patched signer from the capture's own inputs
(fields + genuine nonce + genuine second + cert), confirm byte-identical
to the genuine blob offline, then replay the MINTED blob (not the genuine
bytes) against the verbatim URL -- exactly one live request.
"""
import gzip
import http.client
import re
import sys
import urllib.parse
import zipfile

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\myrun"
sys.path.insert(0, HERE)
import adj7_pure as sg

sg.CERT_SHA1 = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
sg.CLIENT_SDK = "android5.6.0"

SAZ = r"C:\Users\Apps\Downloads\payrupik_new_.saz"
raw = zipfile.ZipFile(SAZ).open("raw/44_c.txt").read()
head, _, _ = raw.partition(b"\r\n\r\n")
lines = head.decode().split("\r\n")
target = lines[0].split(" ")[1]
sp = urllib.parse.urlsplit(target)
path = sp.path + "?" + sp.query
genuine_auth = re.search(r"Authorization: (.+)", head.decode()).group(1).strip()
genuine_blob = bytes.fromhex(
    re.search(r'signature="([0-9A-Fa-f]+)"', genuine_auth).group(1))

FIELDS = dict(urllib.parse.parse_qsl(sp.query, keep_blank_values=True))
SEC = 1791281861  # created_at second of the capture
NONCE = bytes.fromhex("deb8d66011fc70a885006809")  # u64le(a)||hex(d) of record

ours_auth = sg.mint_adj7("attribution", FIELDS, unix_sec=SEC, nonce12=NONCE,
                         client_sdk="android5.6.0", include_block2=True)
ours_auth = re.sub(r'headers_id="[^"]*"', 'headers_id="8"', ours_auth)
ours_auth = re.sub(r'native_version="[^"]*"', 'native_version="3.62.0"', ours_auth)
ours_blob = bytes.fromhex(
    re.search(r'signature="([0-9A-Fa-f]+)"', ours_auth).group(1))

print("ours == genuine byte-identical:", ours_blob == genuine_blob,
      "(%d/%d B)" % (len(ours_blob), len(genuine_blob)))
print("ours tag_ok:", sg.verify_tag(ours_blob),
      "header_ok:", ours_blob[:16] == sg.make_header(SEC))
if ours_blob != genuine_blob:
    print("NOT identical -- refusing live replay (signer diverged)")
    sys.exit(2)

# ONE live replay of the blob OUR law produced
c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
c.putheader("Client-SDK", "android5.6.0")
c.putheader("Authorization", ours_auth)
c.putheader("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 "
                          "Build/S2SE32.28-28-4)")
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
print()
print("PROBE-G-RECHECK -> HTTP", r.status)
print(text[:400])
if "248wk8ym" in text:
    print(">> NON-ORGANIC *** (signature rule re-confirmed live)")
elif r.status == 400:
    print(">> THROTTLED (ask_in) -- no verdict readable right now")
else:
    print(">> Organic")
