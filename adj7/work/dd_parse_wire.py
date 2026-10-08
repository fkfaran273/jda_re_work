"""dd_parse_wire.py v2 -- sequential walker for the dev2srv stream.
Requests are concatenated: request line, headers, CRLF CRLF, body cut
EXACTLY at Content-Length (POST) or nothing (GET), next request follows
immediately (no separator).
"""
import os
import re
import json
import urllib.parse

DUMP = r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "dd_wire_requests.json")

data = open(DUMP, "rb").read()
pos = 0
reqs = []
err = None
while pos < len(data):
    m = re.compile(rb"(POST|GET) (/[^ ]*) HTTP/1\.[01]\r\n").match(data, pos)
    if not m:
        err = (pos, data[pos:pos + 120])
        break
    meth, path = m.group(1).decode(), m.group(2).decode()
    pos = m.end()
    headers = []
    while True:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            err = (pos, "no CRLF")
            break
        line = data[pos:eol]
        pos = eol + 2
        if line == b"":
            break
        k, _, v = line.partition(b":")
        headers.append((k.decode("latin1").strip(),
                        v.decode("latin1").strip()))
    if err:
        break
    clen = None
    for k, v in headers:
        if k.lower() == "content-length":
            clen = int(v)
    body_raw = b""
    if meth == "POST":
        if clen is None:
            err = (pos, "POST without content-length")
            break
        body_raw = data[pos:pos + clen]
        pos += clen
    reqs.append({"method": meth, "path": path, "headers": headers,
                 "content_length": clen,
                 "body_raw": body_raw.decode("latin1")})

print("parsed %d requests; leftover err=%r" % (len(reqs), err))
if err:
    print("at pos %d: %r" % err[:1], err[1][:120] if len(err) > 1 else b"")

out = []
for r in reqs:
    path_only = r["path"].split("?")[0]
    rec = {"method": r["method"], "path": path_only,
           "headers": r["headers"], "content_length": r["content_length"]}
    if r["method"] == "POST":
        rec["body_pairs"] = urllib.parse.parse_qsl(r["body_raw"],
                                                   keep_blank_values=True)
    else:
        q = r["path"].split("?", 1)[1] if "?" in r["path"] else ""
        rec["query_pairs"] = urllib.parse.parse_qsl(q, keep_blank_values=True)
    out.append(rec)

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=1)

for i, r in enumerate(out):
    pairs = r.get("body_pairs") or r.get("query_pairs") or []
    d = dict(pairs)
    print("%2d %-5s %-22s app_token=%s fields=%d" % (
        i, r["method"], r["path"], d.get("app_token"), len(pairs)))
print("wrote", OUT)
