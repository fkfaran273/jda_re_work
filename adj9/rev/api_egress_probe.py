# api_egress_probe.py - can Python reach app.adjust.com at all from this PC?
# Gates the pure-Python booking test: if this hangs/404s, no crafted send can work.
import http.client
import json
import socket
import time
import urllib.parse

TRIES = [
    ("direct GET /attribution (app_token + gps_adid)", None,
     "/attribution?app_token=jut9tib0eeps&gps_adid=00000000-0000-4000-8000-000000000001"
     "&android_uuid=00000000-0000-4000-8000-000000000002&os_name=android&initiated_by=backend"),
]

for label, proxy, path in TRIES:
    t0 = time.time()
    try:
        if proxy:
            conn = http.client.HTTPSConnection("127.0.0.1", 8888, timeout=20)
            conn.set_tunnel("app.adjust.com", 443)
        else:
            conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=20)
        conn.putrequest("GET", path, skip_host=0, skip_accept_encoding=1)
        conn.putheader("Client-SDK", "android5.7.0")
        conn.putheader("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
        conn.putheader("Accept-Encoding", "identity")
        conn.endheaders()
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        print('%-46s HTTP %s (%.1fs)  %s' % (label, r.status, time.time() - t0,
                                             body[:180]))
        conn.close()
    except Exception as e:
        print('%-46s FAILED after %.1fs: %s: %s'
              % (label, time.time() - t0, type(e).__name__, str(e)[:120]))
