import glob, re, json, os
from urllib.parse import unquote, urlparse, parse_qs

files = sorted(set(glob.glob(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\**\raw\*_c.txt", recursive=True)))
rows = []
for f in files:
    t = open(f, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r'signature="([0-9A-Fa-f]{608})"', t):
        sig = m.group(1)
        # find enclosing request: split by request line
        # locate the request start before this match
        start = 0
        for rm in re.finditer(r'(?m)^(POST|GET) (\S+) HTTP/1\.1\r?\n', t[:m.start()]):
            start = rm.start()
        seg = t[start:]
        # headers end
        hm = re.search(r'\r?\n\r?\n', seg)
        head, body = (seg[:hm.start()], seg[hm.end():]) if hm else (seg, "")
        line = head.splitlines()[0]
        auth = next((l for l in head.splitlines() if l.lower().startswith("authorization:")), "")
        af = dict(re.findall(r'(\w+)="([^"]*)"', auth))
        if af.get("algorithm") != "adj7": continue
        # parse fields: form body or JSON body or query
        url = line.split(" ")[1]
        fields = {}
        try:
            fields.update({k: v[0] for k, v in parse_qs(urlparse(url).query).items()})
        except Exception: pass
        b = body.strip()
        if b.startswith("{"):
            try: fields.update(json.loads(b))
            except Exception: pass
        for kv in body.split("&"):
            if "=" in kv and "\n" not in kv:
                k, v = kv.split("=", 1)
                fields[unquote(k)] = unquote(v)
        src = os.path.basename(os.path.dirname(os.path.dirname(f)))
        rows.append({"src": src, "file": os.path.basename(f), "path": url.split("?")[0],
                     "kind": fields.get("activity_kind", url.split("?")[0].strip("/").split("_")[-1]),
                     "app_token": fields.get("app_token",""), "package_name": fields.get("package_name",""),
                     "created_at": fields.get("created_at",""), "sent_at": fields.get("sent_at",""),
                     "sig": sig, "body": body})

print("raw rows:", len(rows))
uniq = {}
for r in rows:
    uniq.setdefault(r["sig"], []).append(r)
print("unique sigs:", len(uniq))
for s, rs in uniq.items():
    r = rs[0]
    print(r["src"], r["file"], r["path"], "kind:", r["kind"], r["app_token"], r["package_name"],
          "| created:", r["created_at"], "| sent:", r["sent_at"])
json.dump(rows, open("raw_rows.json","w"), indent=1)
