import base64
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(HERE, "dev_m1.json"), encoding="utf-8"))
B = json.load(open(os.path.join(HERE, "dev_m2.json"), encoding="utf-8"))
xa = base64.b64decode(A["blobB64"])
xb = base64.b64decode(B["blobB64"])
diff = [i for i in range(192) if xa[i] != xb[i]]
print("equal bytes: %d/192" % (192 - len(diff)))
print("diff byte positions:", diff)
runs, start, prev = [], diff[0], diff[0]
for p in diff[1:] + [999]:
    if p == prev + 1:
        prev = p
        continue
    runs.append((start, prev))
    start, prev = p, p
print("diff runs (start-end):", runs)
print("first8 A/B:", xa[:8].hex(), xb[:8].hex())
print("last8  A/B:", xa[-8:].hex(), xb[-8:].hex())
amean = sum(xa[i] for i in diff) / max(1, len(diff))
bmean = sum(xb[i] for i in diff) / max(1, len(diff))
print("diff-byte mean A=%.1f B=%.1f" % (amean, bmean))