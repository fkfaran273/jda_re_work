#!/usr/bin/env python3
"""win4.py — THE decisive matrix (user hypothesis: server verifies signature content).

Record: genuine /attribution GET #9 (auid 4444dd1b, gps d016e7e4, 00:52:05 +0530).
ALL variants send the SAME identity + SAME wire params (raw captured query);
only the Authorization blob differs (R0 sends none). 3 interleaved rounds.

  R1/R1b  verbatim genuine blob   (raw captured query, byte-faithful)
  R2      crafted blob (maker)    (same identity+stamps; only blob content differs)
  R3      genuine blob, 1 bit flipped
  R0      NO Authorization header (tests '200 without signature')

Outcome key: if R1 returns the TRUE verdict while R2/R3 return the Organic
record -> the server content-checks the blob and crafted blobs silently fail
(user's hypothesis, proven). If ALL match -> verdict is server state, not crypto.
Stdlib only: http.client + CONNECT tunnel via Fiddler 127.0.0.1:8888."""
import os, sys, json, time, base64, datetime, http.client, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as A

# --- single-instance guard (leader writes its PID; losers exit) ---
_LOCK = os.path.join(HERE, "win4.pid")
try:
    if os.path.exists(_LOCK) and (time.time() - os.path.getmtime(_LOCK)) < 900:
        _old = open(_LOCK).read().strip()
        if _old and _old != str(os.getpid()):
            raise SystemExit(f"[guard] another win4.py (pid {_old}) is running - exiting")
    open(_LOCK, "w").write(str(os.getpid()))
except SystemExit:
    raise
sys.stdout.reconfigure(line_buffering=True)   # live tail despite stdout=file

USE = json.load(open(os.path.join(HERE, "genuine_attr_reqs.json")))
G = USE[9]                                   # auid 4444dd1b record
P = G["params"]                              # decoded params (extractor decodes %XX)
P = {k: urllib.parse.unquote(v) for k, v in P.items()}   # %3A -> ':' etc.
GPS = P["gps_adid"]; AUID = P["android_uuid"]
GEN_BLOB = bytes.fromhex(G["blob_hex"])
G_SEC = int(datetime.datetime.strptime(       # genuine request's epoch second
    P["created_at"][:19], "%Y-%m-%dT%H:%M:%S")
    .replace(tzinfo=datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
    .timestamp())
# moto claims/UA so the crafted blob is same-profile (only content varies)
A.DEV.update(A.MOTO); A.DEV.pop("no_sim", None)
A.UA = A.MOTO_UA
print(f"record: gps={GPS} auid={AUID} created={P['created_at']}")

HOST = "app.adjust.com"
RAW_Q = open(os.path.join(HERE, "genuine_attr_raw_query.txt")).read().strip()
URL = f"https://{HOST}/attribution?{RAW_Q}"

def _auth(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())

def tunneled_get(path, auth=None):
    """GET via CONNECT tunnel through Fiddler (stdlib, TLS verify off)."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = __import__("socket").create_connection(("127.0.0.1", 8888), timeout=30)
    raw.sendall(f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = raw.recv(4096)
        if not chunk:
            raise RuntimeError("no CONNECT reply")
        buf += chunk
    if b" 200 " not in buf.split(b"\r\n", 1)[0]:
        raise RuntimeError("CONNECT refused: " + buf[:80].decode("latin1"))
    tls = ctx.wrap_socket(raw, server_hostname=HOST)
    try:
        req = f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
        req += f"Client-SDK: android5.7.0\r\n"
        if auth:
            req += f"Authorization: {auth}\r\n"
        req += (f"User-Agent: {A.UA}\r\nConnection: close\r\n"
                "Accept-Encoding: identity\r\n\r\n")
        tls.sendall(req.encode())
        resp = b""
        tls.settimeout(30)
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            resp += chunk
    finally:
        tls.close()
    head, _, body = resp.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n")[0].split()[1])
    return status, body.decode("utf-8", "replace")

def summarize(st, txt):
    tok = net = eng = "?"
    try:
        j = json.loads(txt)
        att = j.get("attribution", {})
        tok = att.get("tracker_token", j.get("adid", "?"))
        net = att.get("network", "?")
        eng = att.get("engagement_time", "?")[:19]
        txt = ""
    except Exception:
        txt = txt[:100]
    print(f"    -> {st} token={tok} network={net} eng={eng} {txt}")
    return {"status": st, "token": str(tok), "network": str(net), "eng": str(eng)}

rows = []
for rnd in range(3):
    print(f"round {rnd+1}  t={time.strftime('%H:%M:%S')}")
    for tag, blob in (("R1", GEN_BLOB),
                      ("R1b", GEN_BLOB),
                      ("R2", "CRAFT"),
                      ("R3", bytes([GEN_BLOB[0] ^ 1]) + GEN_BLOB[1:]),
                      ("R0", None)):
        try:
            if tag == "R2":
                st, n, blob = A.make_signature(G_SEC, P["created_at"].encode(),
                                               GPS, AUID, None)
                same = sum(1 for a, b in zip(blob, GEN_BLOB) if a == b)
                print(f"  R2 craft {st} steps={n} blob-vs-genuine {same}/192 bytes")
                st, txt = tunneled_get("/attribution?" + RAW_Q, _auth(blob))
            elif tag == "R0":
                st, txt = tunneled_get("/attribution?" + RAW_Q, None)
            else:
                st, txt = tunneled_get("/attribution?" + RAW_Q, _auth(blob))
        except Exception as e:
            st, txt = "ERR", f"{type(e).__name__}: {e}"[:120]
        r = summarize(st, txt); r["tag"] = tag; rows.append(r)
        time.sleep(8)

json.dump(rows, open(os.path.join(HERE, "win4_result.json"), "w"), indent=1)
print("saved win4_result.json")