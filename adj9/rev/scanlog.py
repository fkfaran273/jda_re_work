"""scanlog.py - discover how nsign output blobs are recorded in adj9_wh*.log."""
import re
t = open(r"..\device\adj9_wh4.log", encoding="utf-8", errors="replace").read(800000)
m = re.search(r"nsign ", t)
print(repr(t[m.start():m.start() + 500]) if m else "no bare 'nsign '")
# b64 signature fields
sigs = re.findall(r'signature="([A-Za-z0-9+/]{256})"', t)
print("b64 signature fields:", len(sigs))
for s in sorted(set(sigs)):
    print("  ", s[:40])
