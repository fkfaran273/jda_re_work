"""replay_genuine.py - control: replay a GENUINE device /attribution request verbatim.

From the wire dump, the app's own /attribution request for gps 9abd2f3e:
  - exact query (22 params, device order)
  - exact genuine blob
  - exact device headers
If genuine bytes return the TRUE verdict and our crafted ones return the Organic
fallback, that is the proof the server recognises the app's own bytes.
"""
import http.client
import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "replay_genuine_result.json")

# --- genuine request captured from the device (wire dump) -----------------
GEN_QUERY = (
    "initiated_by=backend&gps_adid_attempt=1&api_level=31&app_version=3.13.9"
    "&app_token=jut9tib0eeps&os_version=12"
    "&created_at=2026-09-14T17%3A39%3A08.195Z%2B0530&device_type=phone"
    "&gps_adid=9abd2f3e-cd24-47a9-a028-c17a138effcf&foreground=1"
    "&android_uuid=0ac8ea63-b876-46a4-8b79-4527c3049762"
    "&sent_at=2026-09-14T17%3A39%3A08.243Z%2B0530&offline_mode_enabled=0"
    "&device_name=moto%20g42&environment=production&needs_response_details=1"
    "&attribution_deeplink=1&package_name=com.penti.app&os_name=android"
    "&ui_mode=1&gps_adid_src=service&tracking_enabled=1")
GEN_B64 = ("E284JTI0ylwh4al/YJ70BgiH8oALFymArBwORXHQmu2u0oWOAQTkzCyrw9/UVJ21pVeGAJ5QeG6Ur1DzRlnYfY3Wv1R505u2qi7OYiRC1J050Xv6cY6/4D1twWKfGHs7G1eUS4rPSzcxvTAkwMjSrgEujPD7u+AV7iexH7MnnFEyw5H4xZIWGGM1K+eWSXoJNDtaIxjS0WX9WRJY06O5u1lGVpHykFT3RiS9ieRBRHcORdTo4SxBmIjPRP/8NwPB")
GEN_UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
AUTH = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
        'headers_id="10",native_version="5.0.0",'
        'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % GEN_B64)


def send(query, auth, tag):
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=25)
    conn.putrequest("GET", "/attribution?" + query, skip_host=0, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", GEN_UA)
    conn.putheader("Accept-Encoding", "identity")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    print("[%s] %s %s" % (tag, r.status, body[:400]), flush=True)
    return r.status, body


out = {}
s, b = send(GEN_QUERY, AUTH, "GENUINE verbatim")
out["genuine"] = [s, b[:400]]

# control: one dword of the blob changed -> must flip to fallback
import base64
raw = bytearray(base64.b64decode(GEN_B64))
raw[20] ^= 0x01
b64b = base64.b64encode(bytes(raw)).decode()
AUTH_B = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
          'headers_id="10",native_version="5.0.0",'
          'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % b64b)
s2, b2 = send(GEN_QUERY, AUTH_B, "1-BIT FLIP")
out["bitflip"] = [s2, b2[:400]]

json.dump(out, open(OUT, "w"), indent=1)
print("saved", OUT)