#!/usr/bin/env python3
"""h_test.py — does the server verify H (TEE-HMAC slot)?

Same fresh record + same raw query as fresh_ab.py (F1=TRUE / F2=Organic proof).
Variants (interleaved x2):
  H1  crafted body + CAPTURED genuine H (from fin_descs, whcap signing A)
  H2  crafted body + random H           (control, replicates F2 = Organic)
If H1 flips to the TRUE verdict -> H is the gate -> offline forging opens up.
If H1 stays Organic -> H alone is not the gate (or whole-package binding).
Stdlib only; Fiddler CONNECT tunnel; single-instance guard."""
import os, sys, json, time, base64, datetime, http.client, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj9_full_chain as A

_LOCK = os.path.join(HERE, "h_test.pid")
try:
    open(_LOCK, "x").write(str(os.getpid()))     # atomic create; fails if exists
except FileExistsError:
    if (time.time() - os.path.getmtime(_LOCK)) < 900:
        raise SystemExit(f"[guard] another h_test.py (pid "
                         f"{open(_LOCK).read().strip()}) running - exit")
    open(_LOCK, "w").write(str(os.getpid()))     # stale lock: take over
sys.stdout.reconfigure(line_buffering=True)

FG = json.load(open(os.path.join(HERE, "fresh_genuine.json")))
RAW_Q = FG["query"]
HOST = "app.adjust.com"
# identity for the crafted claims = the record's own ids (from the query)
Q = urllib.parse.parse_qs(RAW_Q)
GPS = Q["gps_adid"][0]; AUID = Q["android_uuid"][0]
GEN_BLOB = bytes.fromhex(FG["blob_hex"])
GEN_SEC = int(datetime.datetime.strptime(
    Q["created_at"][0][:19], "%Y-%m-%dT%H:%M:%S")
    .replace(tzinfo=datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
    .timestamp())
FD = json.load(open(os.path.join(HERE, "fin_descs.json")))
CAP_H = [d["data_hex"] for d in FD["descs"] if d["len_dw"] == 8][0]
print(f"record gps={GPS} auid={AUID} created={Q['created_at'][0]}")
print(f"captured H = {CAP_H[:24]}...  in-genuine-blob: {CAP_H in FG['blob_hex']}")

A.DEV.update(A.MOTO); A.DEV.pop("no_sim", None)
A.UA = A.MOTO_UA

def _auth(blob):
    return ('Signature signature="%s",adj_signing_id="1500000",'
            'algorithm="adj9",headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"'
            % base64.b64encode(blob).decode())

def tunneled_get(path, auth):
    import ssl, socket
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
    req = (f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
           "Client-SDK: android5.7.0\r\n"
           f"Authorization: {auth}\r\n"
           f"User-Agent: {A.UA}\r\nConnection: close\r\n"
           "Accept-Encoding: identity\r\n\r\n")
    tls.sendall(req.encode())
    resp = b""; tls.settimeout(30)
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
        j = json.loads(txt); att = j.get("attribution", {})
        tok = att.get("tracker_token", j.get("adid", "?"))
        net = att.get("network", "?")
        eng = att.get("engagement_time", "?")[:19]
        txt = ""
    except Exception:
        txt = txt[:100]
    print(f"    -> {st} token={tok} network={net} eng={eng} {txt}")
    return {"status": st, "token": str(tok), "network": str(net), "eng": str(eng)}

rows = []
for rnd in range(2):
    print(f"round {rnd+1} t={time.strftime('%H:%M:%S')}")
    for tag in ("H1", "H2"):
        sec = int(time.time())
        created = A.fmt(sec - 1, 666)
        A.HRAND = (tag == "H2")          # H1: keep captured H; H2: random
        st, n, blob = A.make_signature(sec, created, GPS, AUID, None)
        same = sum(1 for a, b in zip(blob, GEN_BLOB) if a == b)
        print(f"  {tag} craft st={st} steps={n} vs-genuine {same}/192 "
              f"(HRAND={A.HRAND})")
        try:
            st, txt = tunneled_get("/attribution?" + RAW_Q, _auth(blob))
        except Exception as e:
            st, txt = "ERR", f"{type(e).__name__}: {e}"[:120]
        r = summarize(st, txt); r["tag"] = tag; rows.append(r)
        A.HRAND = True                    # restore module default
        time.sleep(8)

json.dump(rows, open(os.path.join(HERE, "h_test_result.json"), "w"), indent=1)
print("saved h_test_result.json")