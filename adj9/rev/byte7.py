# byte7.py - are the .data qword second-halves constant 0xff (= tag bytes of the
# EMIT sinks)? Group .data qwords by byte[7]; report the top groups.
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

SO = (r"C:/Users/Apps/Downloads/com.penti.app/extracted/arm64/lib/arm64-v8a"
      r"/libsigner.so")
E = ELF(SO)
d = E.data
s = E.byname[".data"]
wins = collections.defaultdict(list)
for i in range(s["size"] // 8):
    wins[d[s["offset"] + i * 8 + 7]].append(i * 8)
print("top byte7 values:", [(hex(k), len(v)) for k, v in
                             sorted(wins.items(), key=lambda kv: -len(kv[1]))[:12]])
print("0xff count:", len(wins.get(0xFF, [])))
print("done")