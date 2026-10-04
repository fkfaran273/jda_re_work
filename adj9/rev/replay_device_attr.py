"""replay_device_attr.py - replay the DEVICE'S OWN /attribution request verbatim.

From the wire dump, the app's /attribution for gps 9abd2f3e:
  GET /attribution?initiated_by=backend&gps_adid_attempt=1&...&tracking_enabled=1
  with its own genuine signature.

We send THE SAME BYTES (verbatim) and see if the server answers non-organic
(the win) or organic (fallback). This proves whether the server recognises
byte-exact app-sent packages.
"""
import http.client
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "replay_device_attr.json")

# the EXACT /attribution request from the device wire dump
PATH = ("/attribution?initiated_by=backend&gps_adid_attempt=1&api_level=31"
        "&app_version=3.13.9&app_token=jut9tib0eeps&os_version=12"
        "&created_at=2026-09-14T17%3A39%3A08.195Z%2B0530&device_type=phone"
        "&gps_adid=9abd2f3e-cd24-47a9-a028-c17a138effcf&foreground=1"
        "&android_uuid=0ac8ea63-b876-46a4-8b79-4527c3049762"
        "&sent_at=2026-09-14T17%3A39%3A08.243Z%2B0530&offline_mode_enabled=0"
        "&device_name=moto%20g42&environment=production&needs_response_details=1"
        "&attribution_deeplink=1&package_name=com.penti.app&os_name=android"
        "&ui_mode=1&gps_adid_src=service&tracking_enabled=1")
SIG = ("E284JTI0ylwh4al/YJ70BgiH8oALFymArBwORXHQmu2u0oWOAQTkzCyrw9/UVJ21pVeGAJ5QeG6Ur1DzRlnYfY3Wv1R505u2qi7OYiRC1J050Xv6cY6/4D1twWKfGHs7G1eUS4rPSzcxvTAkwMjSrgEujPD7u+AV7iexH7MnnFEyw5H4xZIWGGM1K+eWSXoJNDtaIxjS0WX9WRJY06O5u1lGVpHykFT3RiS9ieRBRHcORdTo4SxBmIjPRP/8NwPB")
AUTH = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % SIG)
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"

conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=25)
conn.putrequest("GET", PATH, skip_host=0, skip_accept_encoding=1)
conn.putheader("Client-SDK", "android5.7.0")
conn.putheader("Authorization", AUTH)
conn.putheader("User-Agent", UA)
conn.putheader("Host", "app.adjust.com")
conn.putheader("Connection", "Keep-Alive")
conn.putheader("Accept-Encoding", "gzip")
conn.endheaders()
r = conn.getresponse()
body = r.read().decode("utf-8", "replace")
conn.close()
print("device's own /attribution replay:")
print("  status:", r.status)
print("  body:", body[:500])
json.dump({"status": r.status, "body": body}, open(OUT, "w"), indent=1)
print("saved", OUT)