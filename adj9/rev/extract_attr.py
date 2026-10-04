#!/usr/bin/env python3
"""Extract the last genuine /attribution request (params + Authorization blob)
from the bridge dump, then re-craft its blob locally with the maker and diff.
Goal: settle 'server verifies signature content vs params' (user hypothesis)."""
import os, re, json, struct, base64, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin"

raw = open(DUMP, "rb").read()

def parse_requests(buf):
    """Split concatenated plaintext HTTP requests from the decrypted tunnel."""
    reqs = []
    for m in re.finditer(rb"(?:GET|POST) (\S+) HTTP/1\.1\r\n", buf):
        start = m.start()
        head_end = buf.find(b"\r\n\r\n", start)
        if head_end == -1:
            continue
        head = buf[start:head_end].decode("latin1")
        lines = head.split("\r\n")
        method, path = lines[0].split(" ")[0], lines[0].split(" ")[1]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = b""
        cl = headers.get("content-length")
        if cl:
            body = buf[head_end + 4: head_end + 4 + int(cl)]
        reqs.append({"off": start, "method": method, "path": path,
                     "headers": headers, "body": body})
    return reqs

reqs = parse_requests(raw)
attrs = [r for r in reqs if r["path"].startswith("/attribution")]
print("total requests:", len(reqs), " /attribution:", len(attrs))

def params_of(r):
    if r["method"] == "GET":
        q = r["path"].split("?", 1)[1] if "?" in r["path"] else ""
        return dict(p.split("=", 1) for p in q.split("&") if "=" in p)
    return dict(p.split("=", 1) for p in r["body"].decode("latin1").split("&")
                if "=" in p)

out = []
for i, r in enumerate(attrs):
    blob = None
    auth = r["headers"].get("authorization", "")
    m = re.search(r'signature="([^"]+)"', auth)
    if m:
        blob = base64.b64decode(m.group(1))
    p = params_of(r)
    out.append({"i": i, "method": r["method"], "params": p,
                "blob_hex": blob.hex() if blob else None,
                "blob_len": len(blob) if blob else 0,
                "auth": auth[:120]})
    auid = p.get("android_uuid", "?")[:8]
    gps = p.get("gps_adid", "?")[:8]
    print(f"#{i} {r['method']} auid={auid} gps={gps} "
          f"created={p.get('created_at')} blob={len(blob) if blob else 0}B")

with open(os.path.join(HERE, "genuine_attr_reqs.json"), "w") as f:
    json.dump(out, f, indent=1)
print("saved genuine_attr_reqs.json")