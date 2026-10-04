#!/usr/bin/env python3
"""fresh_ab.py — THE definitive A/B on a FRESH never-replayed genuine blob.
Same query bytes for all variants; only the Authorization blob differs.
  F1 verbatim fresh genuine   F1b repeat
  F2 crafted (maker)          F3 fresh + 1 bit flip      F0 no Authorization
Interpretation:
  F1 400 + F2/F3/F0 200-Organic  -> server content-checks the blob (deep path
     is valid-signature-only) and forged content silently gets Organic.
  F1 200-Organic like the rest   -> deep path was replay-consumption, not
     content; verdicts are state, signature not verdict-relevant."""
import base64, json, os, sys, time, datetime, socket, ssl, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
_LOCK = os.path.join(HERE, "fresh_ab.pid")
try:
    if os.path.exists(_LOCK) and (time.time() - os.path.getmtime(_LOCK)) < 900:
        _old = open(_LOCK).read().strip()
        if _old and _old != str(os.getpid()):
            raise SystemExit("[guard] another fresh_ab running (%s)" % _old)
    open(_LOCK, "w").write(str(os.getpid()))
except SystemExit:
    raise
sys.stdout.reconfigure(line_buffering=True)
sys.path.insert(0, HERE)
import adj9_full_chain as A

HOST = "app.adjust.com"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g(40) Build/S1RDS31.16-42-8)"

FG = json.load(open(os.path.join(HERE, "fresh_genuine.json")))
GEN_Q = FG["query"]                     # "/attribution?..." fresh from the app
GEN_BLOB = bytes.fromhex(FG["blob_hex"])
Q = urllib.parse.parse_qs(GEN_Q.split("?", 1)[1])
GPS = Q["gps_adid"][0]; AUID = Q["android_uuid"][0]
CREATED = urllib.parse.unquote(Q["created_at"][0])
G_SEC = int(datetime.datetime.strptime(CREATED[:19], "%Y-%m-%dT%H:%M:%S")
            .replace(tzinfo=datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
            .timestamp())
print("fresh genuine: gps=%s auid=%s created=%s hdr=%s"
      % (GPS[:8], AUID[:8], CREATED[:19], GEN_BLOB[:16].hex()))

A.DEV.update(A.MOTO); A.DEV.pop("no_sim", None); A.UA = A.MOTO_UA

def _auth(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())

def ask(auth):
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
    req = ("GET " + GEN_Q + " HTTP/1.1\r\nHost: " + HOST +
           "\r\nClient-SDK: android5.7.0\r\n")
    if auth:
        req += "Authorization: " + auth + "\r\n"
    req += ("User-Agent: " + UA + "\r\nConnection: close\r\n\r\n")
    tls.sendall(req.encode())
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

# crafted blob once, report its byte-similarity to the fresh genuine blob
st, n, crafted = A.make_signature(G_SEC, CREATED.encode(), GPS, AUID, None)
same = sum(1 for a, b in zip(crafted, GEN_BLOB) if a == b)
print("craft: %s steps=%s blob-vs-fresh %d/192 bytes" % (st, n, same))
FLIP = bytes([GEN_BLOB[16] ^ 0x01]) + GEN_BLOB[17:]

rows = []
for rnd in range(2):
    print("round %d t=%s" % (rnd + 1, time.strftime("%H:%M:%S")))
    for tag, auth in (("F1", _auth(GEN_BLOB)),
                      ("F1b", _auth(GEN_BLOB)),
                      ("F2", _auth(crafted)),
                      ("F3", _auth(FLIP)),
                      ("F0", None)):
        try:
            s, t = ask(auth)
            r = summarize(s, t)
        except Exception as e:
            r = {"status": "ERR", "token": "?", "network": "?", "eng": "?",
                 "raw": "%s: %s" % (type(e).__name__, str(e)[:80])}
        r["tag"] = tag; rows.append(r)
        print("  %-4s -> %s %s %s %s %s" % (tag, r["status"], r["token"],
                                            r["network"], r["eng"], r["raw"]),
              flush=True)
        time.sleep(7)

json.dump(rows, open(os.path.join(HERE, "fresh_ab_result.json"), "w"), indent=1)
print("saved fresh_ab_result.json")
