# e1_check.py - the E1/E2 answer: are TWO mints of the SAME map in the SAME second
# byte-identical? (main.js ran this on the device; the results are already on disk.)
#
#   identical  => deterministic given (map, second) => an offline signer is possible
#   different  => random/counter input => offline replication impossible
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
for f in ("mint_e1_live.json", "minted4.json", "mint_out1_dev.json",
          "mint_out2_dev.json", "mint1.json", "mint2.json"):
    p = os.path.join(HERE, f)
    if not os.path.exists(p):
        continue
    d = json.load(open(p, encoding="utf-8"))
    print("== %s" % f)
    if isinstance(d, dict):
        for k, v in d.items():
            s = json.dumps(v)
            print("   %-16s %s" % (k, s[:220]))
    else:
        print(json.dumps(d, indent=1)[:1200])
    print()

# explicit comparison of any two blobs present
blobs = {}
for f in ("mint_out1_dev.json", "mint_out2_dev.json", "minted4.json",
          "mint_e1_live.json", "mint_out1.json", "mint_out2.json"):
    p = os.path.join(HERE, f)
    if not os.path.exists(p):
        continue
    t = open(p, encoding="utf-8", errors="replace").read()
    for k in ("blobB64", "blob_hex", "blobHex", "blob"):
        i = t.find('"%s"' % k)
        if i >= 0:
            blobs[f] = t[i:i + 120]
print("=== blob fields found ===")
for f, v in blobs.items():
    print("  %-20s %s" % (f, v))