import re, json
from urllib.parse import unquote, urlparse, parse_qs

data = open(r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin","rb").read().decode("latin1")

# collect request lines and authorization lines in order
events = []
for m in re.finditer(r'(?m)^(POST|GET) (\S+) HTTP/1\.1\r?$', data):
    events.append((m.start(), "req", (m.group(1), m.group(2))))
for m in re.finditer(r'(?m)^Authorization: (.*)\r?$', data):
    events.append((m.start(), "auth", m.group(1).strip()))
events.sort(key=lambda e: e[0])

rows = []
cur = None
for off, typ, val in events:
    if typ == "req":
        cur = {"method": val[0], "path": val[1], "auth": None, "body_start": None}
    elif typ == "auth" and cur is not None:
        cur["auth"] = val
        # headers end = end of auth line
        eol = data.find("\n", off) + 1
        cur["body_start"] = eol
        # headers may continue past Authorization; find next request line as body end
        nxt = data.find("\nPOST ", off)
        nxt2 = data.find("\nGET ", off)
        cand = [x for x in (nxt, nxt2) if x != -1]
        end = min(cand) + 1 if cand else len(data)
        cur["body"] = data[cur["body_start"]:end]
        af = dict(re.findall(r'(\w+)="([^"]*)"', val))
        cur["af"] = af
        rows.append(cur)
        cur = None

out = []
for r in rows:
    af = r.get("af", {})
    if af.get("algorithm") != "adj7": continue
    body = r["body"]
    url = r["path"]
    fields = {}
    try: fields.update({k: v[0] for k, v in parse_qs(urlparse(url).query).items()})
    except Exception: pass
    b = body.strip()
    if b.startswith("{"):
        try: fields.update(json.loads(b))
        except Exception: pass
    for kv in body.split("&"):
        if "=" in kv and "\n" not in kv and "\r" not in kv:
            k, v = kv.split("=", 1)
            fields[unquote(k)] = unquote(v)
    out.append({"src": "wire", "file": "app.adjust.com_dev2srv.bin", "path": url.split("?")[0],
                "kind": fields.get("activity_kind", url.strip("/").split("?")[0].split("_")[-1]),
                "app_token": fields.get("app_token",""), "package_name": fields.get("package_name",""),
                "created_at": fields.get("created_at",""), "sent_at": fields.get("sent_at",""),
                "sig": af.get("signature",""), "body": body})

seen = {}
for r in out:
    seen.setdefault(r["sig"], []).append(r)
print("wire adj7:", len(out), "unique:", len(seen))
for s, rs in seen.items():
    r = rs[0]
    print(r["path"], r["kind"], r["app_token"], r["package_name"], "| created:", r["created_at"], "| sent:", r["sent_at"])
json.dump(out, open("wire_rows2.json","w"), indent=1)
