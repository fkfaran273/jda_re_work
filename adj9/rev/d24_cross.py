"""d24_cross.py - relations across the 10 signings: is #2 derived from #0/#4?
is #4's head a function of (#0, #2)? Print full table + test:
  #2 vs w0/w4/xor/sum, #4w0 vs w0&mask, #4 tail vs HMAC candidates (no key).
Also: #4 popcount profile per signing (does the rising-density shape hold?).
"""
import os
import json
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
A = json.load(open(os.path.join(HERE, "all_signings.json"), encoding="utf-8"))

print("tag        | d2       | w0       | w4       | d4head16             | d4pop")
for s in A:
    w = struct.unpack(">36I", bytes.fromhex(s["d0"]))
    d4 = bytes.fromhex(s["d4"])
    dw = struct.unpack(">8I", d4)
    pop = [bin(x).count("1") for x in dw]
    print("%-10s | %s | %08x | %08x | %s | %s"
          % (s["d2"], s["d2"], w[0], w[4],
             d4[:8].hex(), pop))
print("\n=== #2 vs w0/w4 arithmetic ===")
for s in A:
    w = struct.unpack(">36I", bytes.fromhex(s["d0"]))
    d2 = int(s["d2"], 16)
    print("d2=%08x w0=%08x w4=%08x xor=%08x sum=%08x d2^w0=%08x d2^w4=%08x"
          % (d2, w[0], w[4], w[0] ^ w[4], (w[0] + w[4]) & 0xFFFFFFFF,
             d2 ^ w[0], d2 ^ w[4]))
print("done")
