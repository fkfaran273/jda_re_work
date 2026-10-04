# movk_repeat.py - which 16-bit halves repeat across the nSign frame prologue:
# the per-call tag set (arrival slice) vs the per-value (kind) set.
import collections
import re

s = open("nsign_fn.log", encoding="utf-8", errors="replace").read()
halves = collections.Counter(re.findall(r"movk\s+\S+,\s*#(0x[0-9a-f]+)", s))
print("distinct movk halves:", len(halves))
print("halves seen 2+ times:", sorted((v, k) for k, v in halves.items() if v > 1))
print("0xa11a:", halves.get("0xa11a"), "0x13d4:", halves.get("0x13d4"),
      "0x7801:", halves.get("0x7801"), "0x692:", halves.get("0x692"),
      "0xb031:", halves.get("0xb031"))
print("str xzr:", len(re.findall(r"str\s+xzr", s)),
      " str wzr:", len(re.findall(r"str\s+wzr", s)))
print("done")