# compare_mints.py - THE offline-determinism answer, straight from the device's own
# two piggyback mints (main.js E1/E2: same map, same wall-clock second, same live
# signer, same keystore key). Results are pulled to rev/dev_m1.json / dev_m2.json.
import base64
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(HERE, "dev_m1.json"), encoding="utf-8"))
B = json.load(open(os.path.join(HERE, "dev_m2.json"), encoding="utf-8"))

for tag, d in (("mint1", A), ("mint2", B)):
    print("%s: ok=%s blobLen=%s stamp=%s canonical=%s"
          % (tag, d.get("ok"), d.get("blobLen"), d.get("stamp"),
             "yes" if d.get("canonical") else "NO"))
    mp = d.get("mapPairs") or []
    print("   mapPairs=%d  first=%s  last=%s"
          % (len(mp), mp[:1], mp[-2:]))

ba, bb = A.get("blobB64"), B.get("blobB64")
print("\nblobB64 lengths: %d vs %d" % (len(ba or ""), len(bb or "")))
print("BLOBS IDENTICAL:", ba == bb)
if ba and bb:
    x, y = base64.b64decode(ba), base64.b64decode(bb)
    print("decoded: %d B vs %d B" % (len(x), len(y)))
    print("  header A: %s" % x[:16].hex())
    print("  header B: %s" % y[:16].hex())
    print("  header identical: %s" % (x[:16] == y[:16]))
    d = [i for i in range(min(len(x), len(y)) // 4)
         if x[i * 4:i * 4 + 4] != y[i * 4:i * 4 + 4]]
    print("  body dwords differing: %d/44  %s" % (len(d), d[:12]))
    if len(x) == 192 and len(y) == 192:
        w = struct.unpack(">48I", x)
        v = struct.unpack(">48I", y)
        print("  A dwords 0..7 : %s" % " ".join("%08x" % t for t in w[:8]))
        print("  B dwords 0..7 : %s" % " ".join("%08x" % t for t in v[:8]))
        print("  A dwords 40..47: %s" % " ".join("%08x" % t for t in w[40:]))
        print("  B dwords 40..47: %s" % " ".join("%08x" % t for t in v[40:]))

mapA = {k: v for k, v in (A.get("mapPairs") or [])}
mapB = {k: v for k, v in (B.get("mapPairs") or [])}
print("\nmapPairs identical: %s (%d vs %d keys)"
      % (mapA == mapB, len(mapA), len(mapB)))
if mapA != mapB:
    for k in set(mapA) | set(mapB):
        if mapA.get(k) != mapB.get(k):
            print("   DIFF %-24s %r vs %r" % (k, mapA.get(k), mapB.get(k)))
authA = A.get("auth") or ""
authB = B.get("auth") or ""
print("auth header identical: %s" % (authA == authB))