"""pair_attr.py - extract complete request/response pairs from the device wire dump."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = r"D:\advance_emu\ssl_interception\wire_dumps"
req = open(os.path.join(DUMP, "app.adjust.com_dev2srv.bin"), encoding="latin1").read()
rsp = open(os.path.join(DUMP, "app.adjust.com_srv2dev.bin"), encoding="latin1").read()

starts = [(m.start(), m.group(1), m.group(2))
          for m in re.finditer(r"(GET|POST) (/[^ \r]+) HTTP/1\.1", req)]
reqs = []
for i, (pos, method, path) in enumerate(starts):
    end = starts[i + 1][0] if i + 1 < len(starts) else len(req)
    block = req[pos:end]
    am = re.search(r"Authorization: (Signature [^\r]+)", block)
    reqs.append({"method": method, "path": path,
                 "auth": am.group(1) if am else None})

rstarts = [(m.start(), m.group(1)) for m in re.finditer(r"HTTP/1\.[01] (\d{3})", rsp)]
rsps = []
for i, (pos, code) in enumerate(rstarts):
    end = rstarts[i + 1][0] if i + 1 < len(rstarts) else len(rsp)
    block = rsp[pos:end]
    body = block.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in block else ""
    rsps.append({"code": code, "body": body.strip()})

print("requests: %d  responses: %d" % (len(reqs), len(rsps)))
attr = [r for r in reqs if r["path"].startswith("/attribution")]
print("session: %d  attribution: %d  sdk_click: %d  event: %d" % (
    len([r for r in reqs if r["path"].startswith("/session")]), len(attr),
    len([r for r in reqs if r["path"].startswith("/sdk_click")]),
    len([r for r in reqs if r["path"].startswith("/event")])))
print()
print("attribution request paths:")
for i, r in enumerate(attr):
    print("  [%d] %s" % (i, r["path"][:150]))
print()
print("responses:")
for i, r in enumerate(rsps):
    print("  [%2d] %s %s" % (i, r["code"], r["body"][:130].replace("\n", " ")))

json.dump({"reqs": reqs, "rsps": rsps},
          open(os.path.join(HERE, "wire_pairs.json"), "w"), indent=1)
print("saved wire_pairs.json")
