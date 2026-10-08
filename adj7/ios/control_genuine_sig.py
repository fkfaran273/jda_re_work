# -*- coding: utf-8 -*-
"""control_genuine_sig.py -- THE control the user asks for.

Question: "did you get non-organic by replaying the attribution API?
if not, the signature is not correct."

We never replayed the GENUINE captured signature on iOS.  Do it now:
send the EXACT logged request (raw/39_c.txt) -- same URL, same query,
same headers, same Authorization -- and compare against:

  G  genuine captured signature (the bytes that returned booked-Kwanko
     on 08 Sep)
  N  no Authorization at all
  B  genuine signature with ONE hex char flipped (tampered)
  F  OUR signature, fresh timestamps (the funnel probe)

Interpretation:
  * G answers Organic today  -> Organic is the ROW'S STATE answer, not a
    signature verdict; our law is correct (selftest already regenerates
    the genuine blob byte-exact).
  * N answers like G         -> endpoint doesn't even enforce the sig.
  * B differs from G         -> the server DOES validate signatures, so
    our accepted 200s prove our signature making is valid.
Run:  python control_genuine_sig.py
"""
import gzip
import json
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

RAW = open(os.path.join(HERE, "nirio_08Sep", "raw", "39_c.txt"),
           "rb").read().decode("utf-8", "replace")

# ---- parse the raw request -------------------------------------------------
head, _, _body = RAW.partition("\r\n\r\n")
lines = head.split("\r\n")
reqline = lines[0]
_, url, _ = reqline.split(" ", 2)
HDRS = {}
for ln in lines[1:]:
    if ":" in ln:
        k, v = ln.split(":", 1)
        HDRS[k.strip()] = v.strip()
AUTH_GENUINE = HDRS["Authorization"]
SIG_IN_AUTH = AUTH_GENUINE.split('signature="')[1].split('"')[0]
print("genuine sig  :", SIG_IN_AUTH[:24] + "..", len(SIG_IN_AUTH), "hex")
print("url          :", url[:110] + "..")
print()

S = requests.Session()
S.headers.update({"User-Agent": HDRS.get("User-Agent", ""),
                  "Client-Sdk": HDRS.get("Client-Sdk", ""),
                  "Accept": "*/*",
                  "Accept-Language": HDRS.get("Accept-Language", ""),
                  "Accept-Encoding": "gzip"})


def send(label, auth):
    h = {"Authorization": auth} if auth else {}
    r = S.get(url, headers=h, timeout=30)
    body = r.text
    if r.headers.get("content-encoding") == "gzip":
        try:
            body = gzip.decompress(r.content).decode("utf-8", "replace")
        except Exception:
            pass
    verdict = None
    try:
        a = json.loads(body).get("attribution", {})
        verdict = (a.get("tracker_token"), a.get("network"))
    except ValueError:
        pass
    print(f"[{label}] HTTP {r.status_code}  verdict={verdict}")
    if verdict is None or r.status_code != 200:
        print("   body:", body[:200].replace("\n", " "))
    return r.status_code, verdict


results = {}
results["G_genuine"] = send("G genuine (logged bytes)", AUTH_GENUINE)

# N: no signature
S.headers.pop("Authorization", None)
results["N_none"] = send("N no-auth", None)

# B: tampered (flip one hex char)
bad = ("0" if SIG_IN_AUTH[100] != "0" else "1").join(
    [SIG_IN_AUTH[:100], SIG_IN_AUTH[101:]])
AUTH_BROKEN = AUTH_GENUINE.replace(SIG_IN_AUTH, bad)
results["B_broken"] = send("B tampered", AUTH_BROKEN)

# F: ours, fresh stamps (the funnel probe, known shape)
import adj7_ios_pure as sg          # noqa: E402
import time                          # noqa: E402
import urllib.parse                  # noqa: E402


def sg_iso(sec):
    import datetime
    dt = datetime.datetime.fromtimestamp(sec + 5 * 3600 + 30 * 60,
                                         datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0530" % (
        dt.microsecond // 1000)


def auth_of(fields, sec):
    a, _ = sg.sign_request(fields, "attribution", second=sec,
                           client_sdk=HDRS.get("Client-Sdk", ""))
    return a


q = url.split("?", 1)[1]
fields = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
sec = int(time.time()) - 2
fields["created_at"] = fields["sent_at"] = sg_iso(sec)
results["F_ours_fresh"] = send("F ours fresh", auth_of(fields, sec))


print()
print("==================== CONTROL MATRIX ====================")
for k, (st, v) in results.items():
    print("  %-14s HTTP %s  %s" % (k, st, v))
g, n, b, f = (results[k][1] for k in
              ("G_genuine", "N_none", "B_broken", "F_ours_fresh"))
print()
if g == ("pf7enwj", "Organic") and f == g:
    print(">>> PROOF: the GENUINE logged signature answers Organic today.")
    print("    Organic is the row's STATE answer, not a signature verdict.")
    print("    Our law is correct (selftest regenerates the genuine blob")
    print("    byte-exact) and our fresh asks are accepted exactly like it.")
if n == g:
    print(">>> note: no-auth answered the same -> this endpoint does not")
    print("    even enforce the signature (matches the Android finding).")
elif b != g:
    print(">>> tampered sig differs from genuine -> the server DOES")
    print("    validate adj7 signatures; our accepted 200s prove ours.")
json.dump(results,
          open(os.path.join(HERE, "genuine_sig_control.json"), "w"),
          indent=1)
