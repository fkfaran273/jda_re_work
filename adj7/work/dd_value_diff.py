"""dd_value_diff.py -- exhaustive value-level diff: our funnel bodies vs the
device hunch flow (reqs 142/143/144 of dd_wire_requests.json)."""
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ADJ7 = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ADJ7)
sys.path.insert(0, HERE)

import run_install as ri  # noqa: E402

reqs = json.load(open(os.path.join(HERE, "dd_wire_requests.json"),
                      encoding="utf-8"))
dev_sess = dict(reqs[142]["body_pairs"])
dev_click = dict(reqs[143]["body_pairs"])
dev_attr = dict(reqs[144]["query_pairs"])

# plausible identity + seconds (click 210 s before the session, as the
# device's hunch flow ran: 205 s click_server -> session created_at)
gaid = "e7ababf5-88cc-4991-ae51-bf191dcd240a"   # use the device's gaid so
# value comparisons are direct; shapes are checked independently too
android_uuid = "009049a6-20d9-4511-9f25-705bced12ee5"
sec = int(time.time())
click_sec = sec - 210
ref = dev_click["referrer"]

our_sess = ri.build_session_request(gaid, android_uuid, sec, click_sec=click_sec)
our_click = ri.build_click_request(gaid, android_uuid, sec, ref,
                                   click_sec=click_sec)
our_attr = ri.build_attribution_request(gaid, android_uuid, sec)

pairs = [("session", dev_sess, our_sess, reqs[142]),
         ("click", dev_click, our_click, reqs[143]),
         ("attribution", dev_attr, our_attr, reqs[144])]

report = {}
for name, dev, ours, raw in pairs:
    dk, ok = set(dev), set(ours)
    rec = {"n_dev": len(dev), "n_our": len(ours),
           "dev_only": sorted(dk - ok), "our_only": sorted(ok - dk),
           "shared": sorted(dk & ok), "shapes": {}, "dev_order":
           [k for k, _ in (raw["body_pairs"] if "body_pairs" in raw
                           else raw["query_pairs"])],
           "our_order": list(ours.keys())}
    for k in sorted(dk & ok):
        dv, ov = dev[k], str(ours[k])
        # shape normalisation: digits->9, uuids->U, stamps->T
        def shape(v):
            v = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z[+-]\d{4}",
                       "<STAMP>", v)
            v = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                       r"[0-9a-f]{12}", "<UUID>", v)
            v = re.sub(r"[0-9a-f]{16,}", "<HEX16+>", v)
            v = re.sub(r"\d+", "9", v)
            return v
        rec["shapes"][k] = {"dev": dv, "our": ov,
                            "shape_match": shape(dv) == shape(ov),
                            "equal": dv == ov}
    report[name] = rec

print(json.dumps({n: {k: v for k, v in r.items() if k != "shapes"}
                  for n, r in report.items()}, indent=1))
print()
for n, r in report.items():
    print("== %s: dev %d fields, ours %d fields" % (n, r["n_dev"], r["n_our"]))
    if r["dev_only"]:
        print("   DEV-ONLY keys:", r["dev_only"])
    if r["our_only"]:
        print("   OUR-ONLY keys:", r["our_only"])
    print("   value-equal shared keys:")
    for k in r["shared"]:
        s = r["shapes"][k]
        tag = "EQ " if s["equal"] else ("SHM" if s["shape_match"] else "DIFF")
        print("     %-4s %-28s dev=%-58s our=%s" % (tag, k, s["dev"][:58],
                                                    s["our"][:58]))
    print()

# wire order of our urlencoded body vs the device's (visible over the wire)
for name, dev, ours, raw in pairs:
    dev_order = [k for k, _ in (raw["body_pairs"] if "body_pairs" in raw
                                else raw["query_pairs"])]
    our_order = list(ours.keys())
    print("%s body order identical: %s" % (name, dev_order == our_order))
    if dev_order != our_order:
        print("   dev :", dev_order)
        print("   our :", our_order)

# save for the report writer
with open(os.path.join(HERE, "dd_value_report.json"), "w",
          encoding="utf-8") as f:
    json.dump({"report": report,
               "our_sess": our_sess, "our_click": our_click,
               "our_attr": our_attr, "dev_sess": dev_sess,
               "dev_click": dev_click, "dev_attr": dev_attr,
               "sec": sec, "click_sec": click_sec}, f, indent=1)
print("saved dd_value_report.json")
