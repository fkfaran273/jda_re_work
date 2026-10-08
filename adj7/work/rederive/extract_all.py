import json, re, os, glob
from urllib.parse import unquote, urlparse, parse_qs

SOURCES = []
for p in [r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json",
          r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\hunchdate\hunchdate_adjust.json",
          r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\burger\burger_adjust.json"]:
    if os.path.exists(p):
        SOURCES.append((p, os.path.basename(p).replace("_adjust.json","")))

def fields_of(body):
    out = {}
    for kv in body.split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[unquote(k)] = unquote(v)
    return out

def get_ts(url, body):
    out = {}
    try:
        q = parse_qs(urlparse(url).query)
        for k in ("created_at", "sent_at"):
            if k in q: out[k] = q[k][0]
    except Exception: pass
    b = body.strip()
    if b.startswith("{"):
        try:
            j = json.loads(b)
            for k in ("created_at", "sent_at", "activity_kind", "app_token", "package_name"):
                if k in j: out[k] = j[k]
        except Exception: pass
    if b and "=" in b and "\n" not in b[:200]:
        f = fields_of(body)
        for k in ("created_at", "sent_at", "activity_kind", "app_token", "package_name"):
            if f.get(k): out[k] = f[k]
    return out

def auth_fields(auth):
    return dict(re.findall(r'(\w+)="([^"]*)"', auth))

rows = []
for path, label in SOURCES:
    entries = json.load(open(path, encoding="utf-8", errors="replace"))
    for i, e in enumerate(entries):
        auth = None
        for k, v in (e.get("request_headers") or []):
            if k.lower() == "authorization":
                auth = v
        if not auth or "Signature" not in auth: continue
        af = auth_fields(auth)
        if af.get("algorithm") != "adj7": continue
        sig = af.get("signature", "")
        body = e.get("body")
        if isinstance(body, dict): body = json.dumps(body)
        body = body or ""
        f = fields_of(body) if not body.strip().startswith("{") else {}
        ts = get_ts(e.get("url",""), body)
        kind = ts.get("activity_kind") or f.get("activity_kind") or "?"
        at = ts.get("app_token") or f.get("app_token") or ""
        pn = ts.get("package_name") or f.get("package_name") or ""
        rows.append({"src": label, "entry": i, "path": e.get("url"), "kind": kind,
                     "app_token": at, "package_name": pn,
                     "created_at": ts.get("created_at",""), "sent_at": ts.get("sent_at",""),
                     "sig": sig, "auth": auth, "body": body})

# wire dump
data = open(r"D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin","rb").read().decode("latin1")
reqs = [(m.start(), m.group(1), m.group(2)) for m in re.finditer(r'(?m)^(POST|GET) (\S+) HTTP/1\.1', data)]
for idx, (off, meth, p) in enumerate(reqs):
    end = reqs[idx+1][0] if idx+1 < len(reqs) else len(data)
    seg = data[off:end]
    am = re.search(r'(?m)^Authorization: (.*)$', seg)
    if not am: continue
    auth = am.group(1).strip()
    af = auth_fields(auth)
    if af.get("algorithm") != "adj7": continue
    bm = seg.find("\r\n\r\n")
    body = seg[bm+4:] if bm >= 0 else ""
    f = fields_of(body)
    ts = get_ts(p, body)
    rows.append({"src": "wire_dev2srv", "entry": idx, "path": p,
                 "kind": f.get("activity_kind","?"), "app_token": f.get("app_token",""),
                 "package_name": f.get("package_name",""),
                 "created_at": ts.get("created_at",""), "sent_at": ts.get("sent_at",""),
                 "sig": af.get("signature",""), "auth": auth, "body": body})

for i, r in enumerate(rows):
    print(i, r["src"], r["kind"], r["app_token"], r["package_name"], "len", len(r["sig"]),
          "| created", r["created_at"], "| sent", r["sent_at"])
json.dump(rows, open("adj7_rows.json","w"), indent=1)
print("TOTAL:", len(rows))
