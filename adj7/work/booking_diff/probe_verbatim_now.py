"""probe_verbatim_now.py -- is the golden capture's booked verdict STILL
alive right now?  Re-runs the documented VERBATIM probe (genuine blob +
byte-exact capture query) against GET /attribution.  If this answers
NON-ORGANIC at this hour, the server-side click record and tracker settings
are unchanged, and the funnel's fresh clicks are simply not joining.
If it answers Organic, the campaign/tracker state changed after 16:16.
"""
import gzip
import http.client
import json
import os
import re
import sys
import zipfile
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
sys.path.insert(0, ADJ7)
import adj7_pure as sg

sg.CERT_SHA1 = "C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
sg.CLIENT_SDK = "android5.6.0"

z = zipfile.ZipFile(r"C:\Users\Apps\Downloads\payrupik_new_.saz")
raw = z.open("raw/44_c.txt").read()
head, _, _ = raw.partition(b"\r\n\r\n")
lines = head.decode().split("\r\n")
target = lines[0].split(" ")[1]
sp = urllib.parse.urlsplit(target)
path = sp.path + "?" + sp.query          # the RAW capture query, verbatim

auth = re.search(r'Authorization: (.+)', head.decode()).group(1).strip()

c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
c.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
c.putheader("Client-SDK", "android5.6.0")
c.putheader("Authorization", auth)
c.putheader("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 "
                          "Build/S2SE32.28-28-4)")
c.putheader("Host", "app.adjust.com")
c.putheader("Connection", "Keep-Alive")
c.putheader("Accept-Encoding", "gzip")
c.endheaders()
r = c.getresponse()
body = r.read()
if body[:2] == bytes((0x1f, 0x8b)):
    body = gzip.decompress(body)
c.close()
print("HTTP", r.status)
print(body.decode())

# also the fresh-mint control with our own law at fresh times, fresh gaid
import uuid
gaid = str(uuid.uuid4())
from datetime import datetime, timezone
sec = int(time.time()) if False else __import__("time").time()
sec = int(sec)
tz = "+0530"
off = 5 * 3600 + 30 * 60
dt = datetime.fromtimestamp(sec + off, timezone.utc)
stamp = dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d" % (sec % 1000 * 0) + "0Z" + tz
stamp = dt.strftime("%Y-%m-%dT%H:%M:%S.") + dt.strftime("%f")[:3] + "Z" + tz
fields = {
    "initiated_by": "backend", "gps_adid_attempt": "1", "api_level": "31",
    "app_version": "3.0.4", "app_token": "smxi7gqwu39c", "os_version": "12",
    "created_at": stamp, "device_type": "phone", "gps_adid": gaid,
    "foreground": "1", "android_uuid": str(uuid.uuid4()),
    "sent_at": stamp, "offline_mode_enabled": "0",
    "device_name": "moto g42", "environment": "production",
    "needs_response_details": "1", "attribution_deeplink": "1",
    "package_name": "in.hanafintech", "os_name": "android", "ui_mode": "1",
    "gps_adid_src": "service", "tracking_enabled": "1",
}
auth2 = sg.mint_adj7("attribution", fields, unix_sec=sec,
                     include_block2=True,
                     campaign={"cert_sha1": sg.CERT_SHA1,
                               "client_sdk": "android5.6.0",
                               "adj_signing_id": "1300000",
                               "headers_id": "8",
                               "native_version": "3.62.0"})
q = urllib.parse.urlencode(fields, quote_via=urllib.parse.quote)
c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
c.putrequest("GET", "/attribution?" + q, skip_host=1,
             skip_accept_encoding=1)
c.putheader("Client-SDK", "android5.6.0")
c.putheader("Authorization", auth2)
c.putheader("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 "
                          "Build/S2SE32.28-28-4)")
c.putheader("Host", "app.adjust.com")
c.putheader("Connection", "Keep-Alive")
c.putheader("Accept-Encoding", "gzip")
c.endheaders()
r = c.getresponse()
body = r.read()
if body[:2] == bytes((0x1f, 0x8b)):
    body = gzip.decompress(body)
c.close()
print("\nFRESH-MINT CONTROL (fresh gaid, our signature):")
print("HTTP", r.status)
print(body.decode())
