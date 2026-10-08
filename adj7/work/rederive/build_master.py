import json, glob, re, os
from urllib.parse import unquote, urlparse, parse_qs

master = {}

def add(src, r):
    sig = r["sig"].upper()
    if sig in master:
        master[sig]["srcs"].add(src)
        return
    master[sig] = {"srcs": {src}, **r, "sig": sig}

# 1. raw txt files (have kind/app_token/created_at)
for f in sorted(set(glob.glob(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\**\raw\*_c.txt", recursive=True))):
    t = open(f, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r'signature="([0-9A-Fa-f]{608})"', t):
        start = 0
        for rm in re.finditer(r'(POST|GET) (/\S*) HTTP/1\.1', t[:m.start()]):
            start = rm.start()
        seg = t[start:]
        hm = re.search(r'\r?\n\r?\n', seg)
        head, body = (seg[:hm.start()], seg[hm.end():]) if hm else (seg, "")
        auth = next((l for l in head.splitlines() if l.lower().startswith("authorization:")), "")
        af = dict(re.findall(r'(\w+)="([^"]*)"', auth))
        if af.get("algorithm") != "adj7": continue
        url = head.splitlines()[0].split(" ")[1]
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
        path = url.split("?")[0].rstrip("/")
        kind = fields.get("activity_kind") or path.split("/")[-1]
        add("raw:" + os.path.basename(os.path.dirname(os.path.dirname(f))), {
            "sig": af.get("signature",""),
            "file": os.path.basename(f), "path": path, "kind": kind,
            "app_token": fields.get("app_token",""), "package_name": fields.get("package_name",""),
            "created_at": fields.get("created_at",""), "sent_at": fields.get("sent_at",""),
        })

# 2. wire dump
for r in json.load(open("wire_rows3.json")):
    add("wire_dev2srv", {"sig": r["sig"],
        "file": "app.adjust.com_dev2srv.bin@%d" % r["req_off"],
        "path": r["path"], "kind": r["kind"], "app_token": r["app_token"],
        "package_name": r["package_name"], "created_at": r["created_at"], "sent_at": r["sent_at"]})

rows = []
for sig, r in master.items():
    r["srcs"] = sorted(r["srcs"])
    rows.append(r)

rows.sort(key=lambda r: (r.get("created_at") or "9999", r.get("path","")))
for i, r in enumerate(rows):
    print(i, "+".join(r["srcs"]), r["path"], r["kind"], r["app_token"], r.get("package_name",""),
          "created:", r["created_at"])
json.dump(rows, open("master_rows.json","w"), indent=1)
print("TOTAL UNIQUE:", len(rows))
