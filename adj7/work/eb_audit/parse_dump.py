"""Parse app.adjust.com_dev2srv.bin -> list of requests (headers + body).
Writes requests.json and prints a table."""
import json
import re
import sys

DUMP = r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin"
OUT = r"C:\Users\Apps\Downloads\com.penti.app\adj7\work\eb_audit\requests.json"

data = open(DUMP, "rb").read()

reqs = []
pos = 0
issues = []
while pos < len(data):
    eol = data.find(b"\r\n\r\n", pos)
    if eol < 0:
        issues.append("no header terminator at %d (tail %d B)" % (pos, len(data) - pos))
        # dump what's left
        reqs.append({"offset": pos, "raw_head": data[pos:pos + 400].decode("latin1", "replace"),
                     "truncated": True})
        break
    head = data[pos:eol].decode("latin1", "replace")
    lines = head.split("\r\n")
    m = re.match(r"([A-Z]+) (\S+) HTTP/([\d.]+)", lines[0])
    if not m:
        issues.append("bad request line at %d: %r" % (pos, lines[0][:120]))
        break
    method, target, ver = m.groups()
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    clen = None
    for k, v in headers.items():
        if k.lower() == "content-length":
            clen = int(v)
    body = b""
    bstart = eol + 4
    if clen is not None:
        body = data[bstart:bstart + clen]
        if len(body) != clen:
            issues.append("body short at offset %d (%s %s): want %d got %d"
                          % (pos, method, target.split("?")[0], clen, len(body)))
        pos = bstart + clen
    else:
        pos = bstart
        issues.append("no content-length at %d: %s %s" % (pos, method, target.split("?")[0]))
    reqs.append({"offset": pos - (len(body)) - len(head) - 4 if False else None,
                 "start": None, "method": method, "target": target,
                 "headers": headers, "body": body.hex(), "clen": clen})
    # fix start offset
    reqs[-1]["start"] = None

# recompute start offsets in a second pass
reqs2 = []
p = 0
for r in reqs:
    if r.get("truncated"):
        r["start"] = p
        reqs2.append(r)
        break
    headlen = len(("%s %s HTTP/%s" % (r["method"], r["target"], "1.1"))) + 2
    for k, v in r["headers"].items():
        headlen += len(k) + 2 + len(v) + 2
    headlen += 2
    r["start"] = p
    p = p + headlen + len(bytes.fromhex(r["body"]))
    reqs2.append(r)

# paths summary
print("%-4s %-10s %-14s %-6s %-8s %s" % ("#", "method", "path", "clen", "sdk", "auth-alg"))
for i, r in enumerate(reqs2):
    h = r.get("headers", {})
    sdk = h.get("Client-SDK", "?")
    auth = h.get("Authorization", "")
    alg = "?"
    mm = re.search(r'algorithm="([^"]+)"', auth)
    if mm:
        alg = mm.group(1)
    elif auth:
        alg = "auth-noalg"
    target = r["target"].split("?")[0]
    body = bytes.fromhex(r["body"]) if r.get("body") else b""
    print("%-4d %-10s %-14s %-6s %-8s %s body=%d" % (i, r["method"], target,
          r.get("clen"), sdk, alg, len(body)))

print()
print("ISSUES:" if issues else "no stream issues")
for x in issues:
    print(" -", x)
print("total requests:", len(reqs2), "consumed:", p, "of", len(data))

json.dump(reqs2, open(OUT, "w"))
