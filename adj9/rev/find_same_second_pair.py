"""find_same_second_pair.py - find two signings with SAME claims + SAME second but
DIFFERENT regions. Their blobs will show which words the server can verify."""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
d = json.load(open(os.path.join(HERE, "desc_det_result.json"), encoding="utf-8"))

print("all entries:")
for i, e in enumerate(d):
    print("  [%d] kind=%-10s sec=%s d2=%08x d7=%-4s d10=%-4s d0[0]=%08x d0[1]=%08x" % (
        i, e.get("kind"), e.get("sec"), e["d2"], e["d7"], e["d10"],
        e["d0"][0], e["d0"][1]))

# group by (sec, d7, d10) -> same claims same second
groups = {}
for i, e in enumerate(d):
    key = (e.get("sec"), e.get("d7"), e.get("d10"), e.get("kind"))
    groups.setdefault(key, []).append(i)

print()
print("groups with >1 signing (same sec+claims+kind):")
for k, v in groups.items():
    if len(v) > 1:
        print("  %s -> entries %s" % (k, v))
        for i in v:
            e = d[i]
            print("     [%d] d2=%08x d0[1]=%08x d4[6]=%08x" % (
                i, e["d2"], e["d0"][1], e["d4"][6]))
