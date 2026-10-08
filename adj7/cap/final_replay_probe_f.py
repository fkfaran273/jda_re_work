"""final_replay_probe_f.py -- 6th and final network request.

Disambiguates the server's memory key after probes (a)-(e):
  (e) device nonce + ORIGINAL claims (H == device H)  -> BOOKED
  (d) fresh nonce  + fresh claims                     -> Organic
(f) DEVICE nonce + FRESH times/claims (H != device H):
    booked  -> server keys the stored verdict on the record's nonce (a/d)
    Organic -> the key binds the claims too (H / full record)
"""
import calendar
import datetime
import gzip
import http.client
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "oracle")))

import adj7_pure as S          # noqa: E402
import adj7_oracle as O        # noqa: E402

CAP = os.path.join(HERE, "payruki_again", "raw", "43_c.txt")


def created_sec(created):
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z([+-]\d{4})",
                 created)
    dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f")
    off = m.group(2)
    minutes = (1 if off[0] == "+" else -1) * (int(off[1:3]) * 60 + int(off[3:5]))
    return calendar.timegm(dt.timetuple()) - minutes * 60


raw = open(CAP, "rb").read().decode("utf-8", "replace")
lines = raw.replace("\r\n", "\n").split("\n")
headers = {}
for ln in lines[1:]:
    if not ln.strip() or ":" not in ln:
        break
    k, v = ln.split(":", 1)
    headers[k.strip().lower()] = v.strip()
client_sdk = headers["client-sdk"]
ua = headers["user-agent"]
params0 = dict(urllib.parse.parse_qsl(
    lines[0].split("?", 1)[1].split(" ")[0], keep_blank_values=True))
dev = O.parse_device_blob(headers["authorization"])
nonce12_dev = bytes.fromhex(dev["nonce12"])
cert40 = dev["device_cert40"].encode()

now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
p = dict(params0)
p["created_at"] = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z+0530"
p["sent_at"] = (now + datetime.timedelta(milliseconds=13)).strftime(
    "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z+0530"
q = urllib.parse.urlencode(p, quote_via=urllib.parse.quote)
sec = created_sec(p["created_at"])
claims = S.build_claims("attribution", p, client_sdk=client_sdk,
                        include_block2=True)
H = S.commitment_digest(claims, nonce12_dev, cert40).hex().upper()
blob = S.sign(sec, nonce12_dev, claims, cert40)
print("PROBE (f) FRESH times %s, DEVICE nonce %s, sec %d" % (p["created_at"], nonce12_dev.hex(), sec))
print("  H(fresh claims, device nonce) = %s  (device H = %s, differs: %s)"
      % (H, dev["device_H"], H != dev["device_H"]))

auth = ('Signature signature="%s",adj_signing_id="1300000",algorithm="adj7",'
        'headers_id="8",native_version="3.62.0"' % blob.hex().upper())
c = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
c.putrequest("GET", "/attribution?" + q, skip_host=1, skip_accept_encoding=1)
c.putheader("Client-SDK", client_sdk)
c.putheader("Authorization", auth)
c.putheader("User-Agent", ua)
c.putheader("Host", "app.adjust.com")
c.putheader("Accept-Encoding", "gzip")
c.endheaders()
r = c.getresponse()
body = r.read()
if body[:2] == b"\x1f\x8b":
    body = gzip.decompress(body)
body = body.decode("utf-8", "replace")
c.close()
at = json.loads(body)["attribution"]
tok, net = at.get("tracker_token"), at.get("network")
print("  -> HTTP %d tracker=%s network=%s booked=%s"
      % (r.status, tok, net, tok == "248wk8ym"))
print("  body: %s" % body[:220])
json.dump({"f_devnonce_freshclaims": {"booked": tok == "248wk8ym",
                                      "tracker": tok, "network": net,
                                      "H": H}},
          open(os.path.join(HERE, "final_replay_probe_f.json"), "w"), indent=1)
