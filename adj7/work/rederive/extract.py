import json, re

SOURCES = [
    (r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json", "payrupik_new"),
    (r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\hunchdate\hunchdate_adjust.json", "hunchdate"),
]

rows = []
for path, label in SOURCES:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        entries = json.load(f)
    n = 0
    for i, e in enumerate(entries):
        hdrs = e.get("request_headers") or []
        auth = None
        for k, v in hdrs:
            if k.lower() == "authorization":
                auth = v
        if not auth or "Signature" not in auth:
            continue
        m = re.search(r'signature="([0-9A-Fa-f]+)"', auth)
        if not m:
            continue
        sig = m.group(1)
        body = e.get("body")
        if isinstance(body, dict):
            body = json.dumps(body)
        elif body is None:
            body = ""
        rm = re.search(r'method=([A-Za-z]+)', body)
        kind = rm.group(1) if rm else "?"
        rows.append({
            "src": label, "entry": i, "sig": sig, "auth": auth, "body": body,
            "url": e.get("url"), "done": e.get("done"),
        })
        n += 1
    print(label, "entries with signature:", n, "total entries:", len(entries))

with open("sig_rows_raw.json", "w") as f:
    json.dump(rows, f)
print("saved", len(rows))
