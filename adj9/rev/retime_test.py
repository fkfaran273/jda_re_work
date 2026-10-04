r"""retime_test.py — genuine blob, request RETIMED to now (offline, no minting).

Facts so far:
  * byte-exact genuine request -> booked (400 ask_in = out-of-order/interval)
  * ANY change to the blob (1 bit) -> 200 Organic
  * our best crafted bodies (incl. genuine #0 + genuine H) -> 200 Organic
  => the booking gate requires the device-produced signature bytes.
The 400 for the exact replay is the ORDER/interval check, which uses the
request's own created_at/sent_at (all those units are older than the install's
last session). So: keep the genuine signature, move only created_at/sent_at to
now -> booked AND in-order -> should return the record's live verdict.

The device's record is VKM 24pxw9rl right now (fresh install, dev_ab.py).

Usage: python retime_test.py
"""
import base64
import http.client
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin"
OUT = os.path.join(HERE, "retime_test_result.json")


def corpus():
    d = open(DUMP, "rb").read().decode("utf-8", "replace")
    out = []
    for ch in re.split(r"(?=(?:POST|GET) /)", d):
        m = re.match(r"(POST|GET) (\S+) HTTP/1\.1\r\n(.*)", ch, re.DOTALL)
        if not m:
            continue
        method, path, rest = m.groups()
        if not path.startswith("/attribution"):
            continue
        h = dict(re.findall(r"^([\w-]+): (.*)$", rest, re.MULTILINE))
        sm = re.search(r'signature="([^"]+)"', h.get("Authorization", ""))
        if not sm:
            continue
        out.append({"path": path, "blob": base64.b64decode(sm.group(1)),
                    "ua": h.get("User-Agent", "").strip(),
                    "auid": urllib.parse.parse_qs(
                        urllib.parse.urlsplit(path).query)["android_uuid"][0]})
    return out


def stamp0530(sec, ms):
    import datetime
    dt = (datetime.datetime.fromtimestamp(sec, datetime.timezone.utc)
          + datetime.timedelta(hours=5, minutes=30))
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ+0530" % ms


def send(path, blob, ua):
    auth = ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    conn.putrequest("GET", path, skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", ua)
    conn.putheader("Host", "app.adjust.com")
    conn.putheader("Connection", "Keep-Alive")
    conn.putheader("Accept-Encoding", "gzip")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


def short(st, body):
    try:
        a = json.loads(body)["attribution"]
        return "%s / %s / eng=%s / inst=%s" % (
            a.get("tracker_token"), a.get("network"), a.get("engagement_time"),
            a.get("installed_at"))
    except Exception:
        return "HTTP %s %s" % (st, body[:120])


def retimed(path, sec, fresh_auid=None):
    q = urllib.parse.parse_qsl(urllib.parse.urlsplit(path).query)
    ca = stamp0530(sec - 1, 322)
    sa = stamp0530(sec - 1, 358)
    out = []
    for k, v in q:
        if k == "created_at":
            v = ca
        elif k == "sent_at":
            v = sa
        elif k == "android_uuid" and fresh_auid:
            v = fresh_auid
        out.append((k, v))
    return urllib.parse.urlsplit(path).path + "?" + urllib.parse.urlencode(out)


def main():
    items = corpus()
    sec = int(time.time())
    plan = [("unit09 retimed (was 400, newest unit)", items[9], None),
            ("unit01 retimed (was 400, the VKM unit)", items[1], None),
            ("unit01 retimed + fresh auid", items[1],
             "00000000-1111-2222-3333-444455556666"),
            ("unit06 retimed (was 200 Organic live)", items[6], None)]
    res = []
    for label, it, fresh in plan:
        p = retimed(it["path"], sec, fresh)
        st, body = send(p, it["blob"], it["ua"])
        v = short(st, body)
        print("[%s]\n    -> %s %s" % (label, st, v), flush=True)
        res.append({"label": label, "http": st, "verdict": v,
                    "body": body[:1200]})
        time.sleep(2)
    json.dump(res, open(OUT, "w"), indent=1)
    print("saved", OUT, flush=True)


if __name__ == "__main__":
    main()