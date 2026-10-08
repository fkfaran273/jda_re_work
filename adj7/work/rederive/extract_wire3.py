import re, json
from urllib.parse import unquote, urlparse, parse_qs

data = open(r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin","rb").read().decode("latin1")

events = []
for m in re.finditer(r'(POST|GET) (/[^ ]*) HTTP/1\.1', data):
    events.append((m.start(), "req", (m.group(1), m.group(2))))
for m in re.finditer(r'Authorization: (\S.*)\r?\n', data):
    events.append((m.start(), "auth", m.group(1).strip()))
events.sort(key=lambda e: e[0])
print("requests:", sum(1 for e in events if e[1]=="req"), "auths:", sum(1 for e in events if e[1]=="auth"))

rows = []
cur = None
for off, typ, val in events:
    if typ == "req":
        if cur is not None:
            rows.append(cur)  # request with no auth
        cur = {"method": val[0], "path": val[1], "req_off": off, "auth": None}
    elif typ == "auth":
        if cur is not None:
            cur["auth"] = val
            cur["auth_off"] = off
            rows.append(cur)
            cur = None
if cur: rows.append(cur)

out = []
for r in rows:
    af = dict(re.findall(r'(\w+)="([^"]*)"', r.get("auth") or ""))
    if af.get("algorithm") != "adj7": continue
    # body: from end of the auth line to next request match
    eol = data.find("\n", r["auth_off"]) + 1
    nxt = [e[0] for e in events if e[0] > eol and e[1] == "req"]
    end = min(nxt) if nxt else len(data)
    seg = data[eol:end]
    # strip remaining headers (up to first \r\n\r\n or \n\n if present)
    hm = re.search(r'\r?\n\r?\n', seg)
    body = seg[hm.end():] if hm else seg
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
    out.append({"src": "wire", "req_off": r["req_off"], "path": url.split("?")[0],
                "kind": fields.get("activity_kind", url.strip("/").split("?")[0].split("_")[-1]),
                "app_token": fields.get("app_token",""), "package_name": fields.get("package_name",""),
                "created_at": fields.get("created_at",""), "sent_at": fields.get("sent_at",""),
                "sig": af.get("signature",""), "body": body})

seen = {}
for r in out: seen.setdefault(r["sig"], []).append(r)
print("wire adj7 rows:", len(out), "unique sigs:", len(seen))
for s, rs in seen.items():
    r = rs[0]
    print(f'{r["path"]:16s} kind={r["kind"]:10s} {r["app_token"]} {r["package_name"]:20s} created={r["created_at"]} sent={r["sent_at"]}')
json.dump(out, open("wire_rows3.json","w"), indent=1)
