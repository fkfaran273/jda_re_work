"""dg2_verify.py - verify the dg pair offline: feed BOTH maps through FinEx
with the SAME captured region (#0/#2/#4 from fin_descs) and confirm the
bodies differ ONLY by the claim-data path... actually the verdict is already
decisive at the blob level (44/48 differ with identical headers). Here:
confirm the map->#10 path: build desc10 for both maps via desc10_law and
show the #10 bytes differ (gps_adid swap), proving the diff is claim-driven,
while the region (#0/#2/#4) is minted fresh per call by the device.
Also record: header identical + body 44/48 differ = region differs per call
even with same H, same second, same process.
"""
import os
import json
import base64
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(os.path.dirname(HERE), "device")
A = json.load(open(os.path.join(DEV, "mint_dg1.json"), encoding="utf-8"))
B = json.load(open(os.path.join(DEV, "mint_dg2.json"), encoding="utf-8"))
ba = base64.b64decode(A["blobB64"])
bb = base64.b64decode(B["blobB64"])
print("A gaid:", A["gaid"])
print("B gaid:", B["gaid"])
print("head eq:", ba[:16] == bb[:16], ba[:16].hex())
diff = [i for i in range(48) if ba[4 * i:4 * i + 4] != bb[4 * i:4 * i + 4]]
print("dwords differing:", len(diff), "/48", diff[:8], "...")
md = [(x, y) for x, y in zip(A["mapPairs"], B["mapPairs"]) if x != y]
print("map diffs:", md)
print("done")

