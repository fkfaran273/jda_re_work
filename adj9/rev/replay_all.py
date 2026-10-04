#!/usr/bin/env python3
"""replay_all.py — replay ALL 10 captured genuine /attribution blobs (own raw query).
Discriminator: does ANY unconsumed genuine blob open the 200+verdict deep path,
or do all old blobs 400 (consumed) like unit #9 did in win4?"""
import json, os, sys, time, base64, socket, ssl

HERE = os.path.dirname(os.path.abspath(__file__))
_LOCK = os.path.join(HERE, "replay_all.pid")
try:
    if os.path.exists(_LOCK) and (time.time() - os.path.getmtime(_LOCK)) < 900:
        _old = open(_LOCK).read().strip()
        if _old and _old != str(os.getpid()):
            raise SystemExit("[guard] another replay_all running (%s)" % _old)
    open(_LOCK, "w").write(str(os.getpid()))
except SystemExit:
    raise
sys.stdout.reconfigure(line_buffering=True)

HOST = "app.adjust.com"
UA = ("Dalvik/2.1.0 (Linux; U; Android 12; moto g(40) Build/S1RDS31.16-42-8)")

def ask(blob, q):
    ctx = ssl.create_default_context(); ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", 8888), timeout=25)
    raw.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s\r\n\r\n" % (HOST, HOST)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = raw.recv(4096)
        if not c: raise RuntimeError("no CONNECT reply")
        buf += c
    if b" 200 " not in buf.split(b"\r\n", 1)[0]:
        raise RuntimeError("CONNECT refused")
    tls = ctx.wrap_socket(raw, server_hostname=HOST)
    auth = ('Authorization: Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())
    tls.sendall(("GET /attribution?" + q + " HTTP/1.1\r\nHost: " + HOST +
                 "\r\nClient-SDK: android5.7.0\r\n" + auth +
                 "\r\nUser-Agent: " + UA +
                 "\r\nConnection: close\r\n\r\n").encode())
    resp = b""; tls.settimeout(25)
    while True:
        c = tls.recv(65536)
        if not c: break
        resp += c
    tls.close()
    head, _, body = resp.partition(b"\r\n\r\n")
    return int(head.split(b"\r\n")[0].split()[1]), body.decode("utf-8", "replace")

def summarize(st, txt):
    tok = net = eng = "?"
    try:
        j = json.loads(txt); a = j.get("attribution", {})
        tok = str(a.get("tracker_token", j.get("adid", "?")))[:12]
        net = str(a.get("network", "?"))[:20]
        eng = str(a.get("engagement_time", "?"))[:19]
        txt = ""
    except Exception:
        txt = txt[:80]
    return {"status": st, "token": tok, "network": net, "eng": eng, "raw": txt}

U = json.load(open(os.path.join(HERE, "genuine_attr_reqs.json")))
rows = []
for i, g in enumerate(U):
    blob = bytes.fromhex(g["blob_hex"])
    q = g.get("raw_query") or open(os.path.join(HERE, "genuine_attr_raw_query.txt")).read().strip()
    auid8 = g["params"].get("android_uuid", "?")[:8]
    try:
        st, txt = ask(blob, q)
        r = summarize(st, txt)
    except Exception as e:
        r = {"status": "ERR", "token": "?", "network": "?", "eng": "?",
             "raw": "%s: %s" % (type(e).__name__, str(e)[:80])}
    r["idx"] = i; r["auid8"] = auid8
    rows.append(r)
    print(i, auid8, "->", r["status"], r["token"], r["network"], r["eng"], r["raw"], flush=True)
    time.sleep(5)

json.dump(rows, open(os.path.join(HERE, "replay_all_result.json"), "w"), indent=1)
print("saved replay_all_result.json")
