"""creditsea_gate_probe.py — ONE flipped-bit session after the 20m window.

If the flipped blob gets 200 -> creditsea endpoints don't verify signatures
(attribution decided by matching logic alone).
If 400 with a signature error  -> the gate IS active and a 5.8.0-specific
constant (claims law / D8) is failing.
"""
import json
import os
import sys
import time
import urllib.parse
import http.client

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_creditsea as RC            # noqa: E402
import signer_simple as sg            # noqa: E402
from signer_simple import auth_header  # noqa: E402

gaid, params, chrome_ua, dalvik_ua, stamp = RC.load_device("device_g64.json")
t = time.time()
session = dict(params)
session.update({"session_count": "1", "session_length": "0",
                "time_spent": "0", "subsession_count": "1",
                "created_at": stamp(t + 7, 61), "sent_at": stamp(t + 7, 68)})

blob, sec, info = sg.sign_request(session, "session")
print("[G] signed sec=%d st=%s" % (sec, info["status"]), flush=True)
bad = bytearray(blob)
bad[-1] ^= 0x01

body = urllib.parse.urlencode(session).encode()
conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
conn.putrequest("POST", "/session", skip_host=1, skip_accept_encoding=1)
conn.putheader("Client-SDK", RC.CLIENT_SDK)
conn.putheader("Authorization", auth_header(bytes(bad)))
conn.putheader("Content-Type", "application/x-www-form-urlencoded")
conn.putheader("User-Agent", dalvik_ua)
conn.putheader("Host", "app.adjust.com")
conn.putheader("Content-Length", str(len(body)))
conn.endheaders(body)
resp = conn.getresponse()
out = resp.read().decode("utf-8", "replace")
print("[G] FLIPPED /session -> %d %s" % (resp.status, out[:200]), flush=True)
conn.close()
verdict = ("GATE ABSENT (200 despite corrupt signature)"
           if resp.status == 200 else
           "GATE ACTIVE (corrupt signature rejected: %s)"
           % ("interval" if "interval" in out else "signature/other"))
print("[G] VERDICT: %s" % verdict, flush=True)
json.dump({"http": resp.status, "body": out[:400], "verdict": verdict},
          open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "creditsea_gate_result.json"), "w"), indent=1)
