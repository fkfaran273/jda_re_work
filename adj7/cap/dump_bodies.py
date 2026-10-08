import json
D = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\adj7\cap\payrupik_new\payrupik_new__adjust.json"))
for e in D:
    if e["method"] != "POST":
        continue
    print("=== sid", e["sid"], e["url"])
    for k, v in e["request_headers"]:
        if k.lower() in ("client-sdk", "user-agent", "content-type"):
            print("   hdr", k, v)
    b = e["body"]
    if isinstance(b, dict):
        for k, v in b.items():
            print("   body", k, "=", str(v)[:80])
    else:
        print("   body", str(b)[:400])
