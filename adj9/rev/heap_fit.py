"""heap_fit.py - test the HEAP-POINTER model for #0's words.

#0 = [W0][C1][C2][C3][W1][C1][C2][C3]x8. Model: W/C are low32 of heap object
addresses (malloc'd buffers: map nodes? descriptor structs? HMAC ctx?).
Predictions:
  a) words of one signing should lie in a FEW tight clusters (one heap arena):
     check max-min spread of the 5 distinct dwords.
  b) C1..C3 repeat 8x = the SAME three pointers reused (a struct triple).
  c) W0 != W1 but both in MTE-tag range per slice 100 (top byte b4/tagged):
     check top bytes.
  d) det[0] vs det[2] (same payload, same second-ish): different heaps ->
     different words, but SAME structure (1+1+3 pattern). CONFIRMED by shape.
"""
import json
import struct

HERE = "C:\\Users\\Apps\\Downloads\\com.penti.app\\adj9\\rev\\"
import os
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))
D = json.load(open(os.path.join(HERE, "det_full.json"), encoding="utf-8"))

rows = []
for s in A:
    w = struct.unpack(">36I", bytes.fromhex(s["d0"]))
    rows.append(("als-" + s["d2"], w))
for s in D:
    w = struct.unpack(">36I", bytes.fromhex(s["d0"]))
    d2 = "%08x" % s["d2"] if isinstance(s["d2"], int) else s["d2"]
    rows.append(("det-" + d2, w))

for tag, w in rows:
    u = sorted(set(w))
    spread = max(u) - min(u)
    tops = sorted(set((x >> 24) & 0xFF for x in u))
    # structure check: w[0],w[4] distinct; w[1:4]==w[5:8]==...?
    pat = (w[1] == w[5] == w[9], w[1:4] == w[5:8], w[0] != w[4])
    print("%-12s distinct=%d spread=0x%x topbytes=%s struct131=%s w0=0x%08x w4=0x%08x"
          % (tag, len(u), spread, [hex(t) for t in tops], pat, w[0], w[4]))
print("done")
