"""d2d4_fit.py - what are #2 and #4? Test small-integer / structural models.

#2 = 1 dword. #4 = 8 dwords with rising popcount (2,4,5,8,9,13,12,18).
Candidates:
  a) #2 = len/unpadded-len/ndesc/checksum-of-#10? (360/387/388/503/504/529..)
  b) #2 = low32(H)? first/last dword of H? (#4[?] vs H bytes?)
  c) #4 = HMAC(key2, something)? No: slice 103 killed #4==H, but #4 could be a
     DIFFERENT keyed MAC (different key/msg). Test #4 vs HMAC(key=H, msg)?
  d) #4 structural: bytes matching small constants (lengths/indices)?
"""
import json
import struct
import hashlib
import hmac

HERE = "C:\\Users\\Apps\\Downloads\\com.penti.app\\adj9\\rev\\"
import os
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
Hs = [bytes.fromhex(x["hex"]) for x in W["mac_doFinal"]]

print("=== #2 vs small ints ===")
for s in A:
    d2 = int(s["d2"], 16)
    d10len = len(bytes.fromhex(s["d10"]))
    print("  d2=0x%08x (%10d) d10len=%d d10len*?=%s"
          % (d2, d2, d10len, d2 % max(d10len, 1) == 0))

print("\n=== #4 vs H: any 4-byte window of #4 in H, or vice versa? ===")
for i, s in enumerate(A):
    d4 = bytes.fromhex(s["d4"])
    hits = 0
    for H in Hs:
        for o in range(0, 29):
            if H[o:o + 4] in d4:
                hits += 1
                break
    print("  als%d d4-vs-H 4B-window hits: %d/8" % (i, hits))

print("\n=== #4 byte histogram (structured vs uniform)? ===")
allb = b"".join(bytes.fromhex(s["d4"]) for s in A)
from collections import Counter
c = Counter(allb)
print("  zero bytes: %d/320  distinct: %d" % (c[0], len(c)))
print("  top bytes:", c.most_common(8))
print("done")
