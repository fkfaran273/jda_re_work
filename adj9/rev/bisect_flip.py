#!/usr/bin/env python3
"""bisect_flip.py — map the server-verified region of the genuine blob.
For each 4-byte word (and each header byte) of the FRESH genuine blob:
send the blob with that word XORed 0xFFFFFFFF and record whether the
server still returns the TRUE verdict (24i5ummx VKM) or falls back to
Organic. Words whose flip kills the verdict are verified server-side."""
import base64, json, os, sys, time, socket, ssl

HERE = os.path.dirname(os.path.abspath(__file__))
_LOCK = os.path.join(HERE, "bisect_flip.pid")
try:
    if os.path.exists(_LOCK) and (time.time() - os.path.getmtime(_LOCK)) < 3600:
        _old = open(_LOCK).read().strip()
        if _old and _old != str(os.getpid()):
            raise SystemExit("[guard] another bisect_flip running (%s)" % _old)
    open(_LOCK, "w").write(str(os.getpid()))
except SystemExit:
    raise
sys.stdout.reconfigure(line_buffering=True)

HOST = "app.adjust.com"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g(40) Build/S1RDS31.16-42-8)"
FG = json.load(open(os.path.join(HERE, "fresh_genuine.json")))
GEN_Q = FG["query"]
GEN_BLOB = bytearray(bytes.fromhex(FG["blob_hex"]))
print("genuine hdr=%s len=%d" % (GEN_BLOB[:16].hex(), len(GEN_BLOB)))

def ask(blob):
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
            % base64.b64encode(bytes(blob)).decode())
    tls.sendall(("GET " + GEN_Q + " HTTP/1.1\r\nHost: " + HOST +
                 "\r\nClient-SDK: android5.7.0\r\n" + auth +
                 "\r\nUser-Agent: " + UA + "\r\nConnection: close\r\n\r\n").encode())
    resp = b""; tls.settimeout(25)
    while True:
        c = tls.recv(65536)
        if not c: break
        resp += c
    tls.close()
    head, _, body = resp.partition(b"\r\n\r\n")
    return int(head.split(b"\r\n")[0].split()[1]), body.decode("utf-8", "replace")

def verdict(st, txt):
    try:
        j = json.loads(txt); a = j.get("attribution", {})
        net = a.get("network", "?")
        return "TRUE" if "VKM" in str(net) else ("Organic" if net == "Organic" else str(net))
    except Exception:
        return "raw:%s" % txt[:40]

rows = []
import os as _os
_PROG = os.path.join(HERE, "bisect_flip_progress.jsonl")
if _os.path.exists(_PROG):
    for _l in open(_PROG, encoding="utf-8"):
        _l = _l.strip()
        if _l:
            rows.append(json.loads(_l))
DONE = {(r["kind"], r.get("w")) for r in rows}
def record(r):
    rows.append(r)
    with open(_PROG, "a", encoding="utf-8") as f:
        f.write(json.dumps(r) + "\n")
    json.dump(rows, open(os.path.join(HERE, "bisect_flip_result.json"), "w"), indent=1)

# control first
if ("ctrl", -1) not in DONE:
    try:
        st, txt = ask(GEN_BLOB)
        v = verdict(st, txt)
    except Exception as e:
        st, v = "ERR", "%s: %s" % (type(e).__name__, str(e)[:60])
    print("CTRL verbatim -> %s %s" % (st, v), flush=True)
    record({"w": -1, "kind": "ctrl", "st": st, "v": v})
    time.sleep(6)

# header bytes 0..15 (byte flips)
for b in range(16):
    if ("hdr_byte", b) in DONE:
        continue
    t = bytearray(GEN_BLOB); t[b] ^= 0x01
    try:
        st, txt = ask(t); v = verdict(st, txt)
    except Exception as e:
        st, v = "ERR", "%s: %s" % (type(e).__name__, str(e)[:60])
    print("HDR byte %2d -> %s %s" % (b, st, v), flush=True)
    record({"w": b, "kind": "hdr_byte", "st": st, "v": v})
    time.sleep(6)

# body words 16..191 step 4 (dword flips)
for w in range(16, 192, 4):
    if ("body_dw", (w - 16) // 4) in DONE:
        continue
    t = bytearray(GEN_BLOB)
    t[w:w+4] = bytes(x ^ 0xFF for x in t[w:w+4])
    try:
        st, txt = ask(t); v = verdict(st, txt)
    except Exception as e:
        st, v = "ERR", "%s: %s" % (type(e).__name__, str(e)[:60])
    print("BODY dw %2d (off %3d) -> %s %s" % ((w-16)//4, w, st, v), flush=True)
    record({"w": (w-16)//4, "off": w, "kind": "body_dw", "st": st, "v": v})
    time.sleep(6)

json.dump(rows, open(os.path.join(HERE, "bisect_flip_result.json"), "w"), indent=1)
print("saved bisect_flip_result.json")
