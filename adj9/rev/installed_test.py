#!/usr/bin/env python3
"""installed_test.py — LAST param-matching theory: claims installed_at stamps.

F2-crafted claims carry stale 2026-09-08(+0200) install stamps while the
record's real install is 2026-09-15T16:20:21+0530. If the server cross-checks
claims-vs-record stamps, this variant (fresh +0530 stamps, ms guessed .782)
flips to TRUE. Same raw query / identity as fresh_ab F1 (record is VKM-TRUE).
I1 = fresh install stamps   I2 = control (stale stamps, expect Organic)"""
import os, sys, json, time, base64, datetime, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as A

_LOCK = os.path.join(HERE, "itest.pid")
try:
    open(_LOCK, "x").write(str(os.getpid()))
except FileExistsError:
    raise SystemExit("[guard] itest already ran/running")

FG = json.load(open(os.path.join(HERE, "fresh_genuine.json")))
RAW_Q = FG["query"]; HOST = "app.adjust.com"
Q = urllib.parse.parse_qs(RAW_Q)
GPS = Q["gps_adid"][0]; AUID = Q["android_uuid"][0]
print(f"record gps={GPS} auid={AUID}")
A.DEV.update(A.MOTO); A.DEV.pop("no_sim", None); A.UA = A.MOTO_UA

import ssl, socket, http.client
def _auth(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())

def tunneled_get(path, auth):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", 8888), timeout=30)
    raw.sendall(f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = raw.recv(4096)
        if not c: raise RuntimeError("no CONNECT reply")
        buf += c
    if b" 200 " not in buf.split(b"\r\n", 1)[0]:
        raise RuntimeError("CONNECT refused")
    tls = ctx.wrap_socket(raw, server_hostname=HOST)
    tls.sendall((f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
                 "Client-SDK: android5.7.0\r\n"
                 f"Authorization: {auth}\r\nUser-Agent: {A.UA}\r\n"
                 "Connection: close\r\nAccept-Encoding: identity\r\n\r\n").encode())
    resp = b""; tls.settimeout(30)
    while True:
        c = tls.recv(65536)
        if not c: break
        resp += c
    tls.close()
    head, _, body = resp.partition(b"\r\n\r\n")
    return int(head.split(b"\r\n")[0].split()[1]), body.decode("utf-8", "replace")

FRESH_INS = "2026-09-15T16:20:21.782Z+0530"
rows = []
for tag in ("I1", "I2"):
    sec = int(time.time())
    created = A.fmt(sec - 1, 666)
    if tag == "I2":
        st, n, blob = A.make_signature(sec, created, GPS, AUID, None)
    else:
        st, n, blob = A.make_signature(sec, created, GPS, AUID,
                                       FRESH_INS.encode())
    print(f"  {tag} craft st={st} steps={n}")
    try:
        st, txt = tunneled_get("/attribution?" + RAW_Q, _auth(blob))
    except Exception as e:
        st, txt = "ERR", f"{type(e).__name__}: {e}"[:120]
    try:
        j = json.loads(txt); att = j.get("attribution", {})
        out = {"st": st, "token": att.get("tracker_token", j.get("adid")),
               "network": att.get("network"),
               "eng": att.get("engagement_time", "")[:19]}
    except Exception:
        out = {"st": st, "token": txt[:80], "network": "?", "eng": "?"}
    out["tag"] = tag; rows.append(out)
    print(f"    -> {out}")
    time.sleep(8)
json.dump(rows, open(os.path.join(HERE, "installed_test_result.json"), "w"),
          indent=1)
print("saved installed_test_result.json")