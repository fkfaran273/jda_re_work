"""Build event targets: dump 130/134/138 + payrupik_new sid45 + burger/hunch
sibling values.  Saves event_targets.json"""
import json
import re
import sys
import urllib.parse

ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")
from adj7_oracle import parse_device_blob

REQS = json.load(open(ADJ7 + r"\work\eb_audit\requests.json"))


def fields_of(r):
    target = r["target"]
    body = bytes.fromhex(r["body"]) if r.get("body") else b""
    qs = target.split("?", 1)[1] if (r["method"] == "GET" and "?" in target) \
        else body.decode("latin1", "replace")
    return dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))


targets = {}
for idx in (130, 134, 138):
    r = REQS[idx]
    f = fields_of(r)
    dev = parse_device_blob(r["headers"].get("Authorization", ""))
    targets["dump%d" % idx] = {"idx": idx, "fields": f, "dev": dev,
                               "sdk": r["headers"].get("Client-SDK")}

# payrupik_new sid 45 event + sid 42/43 siblings
cap = json.load(open(ADJ7 + r"\cap\payrupik_new\payrupik_new__adjust.json"))
for x in cap:
    sid = str(x.get("sid"))
    if x.get("method") == "POST" and "app.adjust.com/event" in str(x.get("url", "")):
        f = x["body"] if isinstance(x["body"], dict) else \
            dict(urllib.parse.parse_qsl(x.get("body") or "", keep_blank_values=True))
        auth = dict(x["request_headers"]).get("Authorization", "")
        dev = parse_device_blob(auth)
        targets["payru45"] = {"idx": "sid45", "fields": f, "dev": dev,
                              "sdk": dict(x["request_headers"]).get("Client-SDK")}
    if sid in ("42", "43"):
        f = x["body"] if isinstance(x["body"], dict) else \
            dict(urllib.parse.parse_qsl(x.get("body") or "", keep_blank_values=True))
        targets.setdefault("siblings", {})[sid] = f

json.dump(targets, open(ADJ7 + r"\work\eb_audit\event_targets.json", "w"),
          indent=1)

# report
for name in ("dump130", "dump134", "dump138", "payru45"):
    t = targets.get(name)
    if not t:
        print(name, "MISSING")
        continue
    f = t["fields"]
    print("=" * 90)
    print(name, "sdk=", t["sdk"], "nfld=", len(f), "dev=", t["dev"])
    for k in ("created_at", "sent_at", "event_token", "session_count",
              "session_length", "time_spent", "subsession_count", "event_count",
              "seq", "gps_adid", "installed_at", "updated_at"):
        print("   %-20s %s" % (k, f.get(k)))

# are dump130 and dump134 the same body?
b130 = REQS[130]["body"]; b134 = REQS[134]["body"]; b138 = REQS[138]["body"]
print("\nbodies: 130==134?", b130 == b134, " 130==138?", b130 == b138)
# auth blobs?
a130 = REQS[130]["headers"].get("Authorization")
a134 = REQS[134]["headers"].get("Authorization")
print("auth 130==134?", a130 == a134)
print("targets saved. siblings keys:", list(targets.get("siblings", {}).keys()))
