"""als_probe.py - what exactly is in all_signings.json (10 signings with d0..d10)?

If each entry carries its #10 (the signed claim string = the map) AND its region
(d0/d2/d4), we have a 10-sample labelled dataset to fit region = f(map, second).
This probe prints the schema, one full entry, and the per-entry summary."""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
ALS = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
print("entries: %d" % len(ALS))
print("keys: %s" % sorted(ALS[0].keys()))
print("\n=== entry 0 (truncated) ===")
e = ALS[0]
for k, v in e.items():
    if isinstance(v, list) and len(v) > 12:
        print("  %-4s list[%d]  head=%s" % (k, len(v), v[:6]))
    elif isinstance(v, str) and len(v) > 90:
        print("  %-4s str[%d]   %s…" % (k, len(v), v[:90]))
    else:
        print("  %-4s %r" % (k, v))

print("\n=== per-signing summary ===")
print("%-3s %-6s %-24s %-10s %-34s %s" % ("#", "d10len", "d10 head", "d2",
                                          "d4", "d0 head"))
for i, e in enumerate(ALS):
    d10 = e.get("d10") or ""
    if isinstance(d10, list):
        d10h = "".join("%08x" % x for x in d10[:3])
        n = len(d10) * 4
    else:
        d10h = str(d10)[:24]
        n = len(str(d10)) // 2
    d0 = e.get("d0") or ""
    print("%-3d %-6s %-24s %-10s %-34s %s"
          % (i, n, d10h, e.get("d2"), (e.get("d4") or "")[:32],
             (str(d0))[:32]))

# recover printable text from d10 to identify the kind / created_at
import re
print("\n=== d10 decoded (kind / created_at) ===")
for i, e in enumerate(ALS):
    d10 = e.get("d10")
    if isinstance(d10, list):
        b = b"".join(struct.pack(">I", x) for x in d10)
    else:
        try:
            b = bytes.fromhex(str(d10))
        except Exception:
            continue
    m = re.search(rb"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\+\d{4})", b)
    k = re.search(rb"(session|click|attribution|event)\x00*$", b)
    print("  als[%d] created_at=%s kind=%s len=%d"
          % (i, m.group(1).decode() if m else None,
             k.group(1).decode() if k else "?", len(b)))
print("done")