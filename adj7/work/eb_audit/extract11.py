"""Extract the last 11 requests (h_*, b_*, s_*), decrypt device blobs,
verify claims.  Diagnose burger."""
import json
import re
import sys
import urllib.parse

ADJ7 = r"C:\Users\Apps\Downloads\com.penti.app\adj7"
sys.path.insert(0, ADJ7)
sys.path.insert(0, ADJ7 + r"\oracle")

import adj7_pure as ap
from adj7_oracle import parse_device_blob, cbc_decrypt  # noqa

REQS = json.load(open(ADJ7 + r"\work\eb_audit\requests.json"))

NAMES = {134: "h_event", 135: "h_sess", 136: "h_click", 137: "h_attr",
         138: "b_event", 139: "b_sess", 140: "b_click", 141: "b_attr",
         142: "s_sess", 143: "s_click", 144: "s_attr"}

out = {}
for idx, name in sorted(NAMES.items()):
    r = REQS[idx]
    target = r["target"]
    path = target.split("?")[0]
    headers = r["headers"]
    auth = headers.get("Authorization", "")
    body = bytes.fromhex(r["body"]) if r.get("body") else b""
    if r["method"] == "GET" and "?" in target:
        qs = target.split("?", 1)[1]
    else:
        qs = body.decode("latin1", "replace")
    pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True)
    fields = dict(pairs)
    dev = parse_device_blob(auth)
    out[name] = {"idx": idx, "method": r["method"], "path": path,
                 "headers": headers, "fields": fields,
                 "n_fields": len(fields), "dev": dev}
    print("=" * 100)
    print(name, idx, r["method"], path, "client_sdk_hdr=", headers.get("Client-SDK"))
    print("  fields(%d):" % len(fields))
    for k, v in fields.items():
        print("    %-32s %s" % (k, v[:120]))
    print("  device blob:", json.dumps(dev, indent=2)[:600] if dev else None)

json.dump(out, open(ADJ7 + r"\work\eb_audit\last11.json", "w"), indent=1)
print("\nsaved last11.json")
