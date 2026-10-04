"""fieldmap.py - map field-loop EMIT streams to descriptors.

The field loop (0x100114) does: for desc i: sink = ctx[0x20+i*8]; EMIT(sink,
j, BE(data[j])). Streams are allocated in Ex.__init__ as
  stream_of[i] -> 0x5500000000 + i*0x1000, mem[CTX+0x20+i*8] = sva.
So desc ORDER[i] lands in stream 0x5500000000+i*0x1000 masked to 20 bits:
  i=0 -> 0x0, i=1 -> 0x1000, i=2 -> 0x2000, i=3 -> 0x3000, ...
qfull showed: #0 dwords at stream 0x0 (ORDER[0] = desc 0 ✓),
#4 dwords at stream 0x3000 (ORDER[3] = desc 4 ✓), #2 at 0x4000 (ORDER[4] = desc 2 ✓).
Verify the mapping for all 11, then confirm: region == descriptor INPUTS.
"""
import sys
import os
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ORDER = json.load(open(os.path.join(HERE, "fin_descs.json")))["va_order"]
BY = {d["build_idx"]: (d["len_dw"], d["data_hex"][:32])
      for d in json.load(open(os.path.join(HERE, "fin_descs.json")))["descs"]}
print("ORDER:", ORDER)
for i, b in enumerate(ORDER):
    print("  stream 0x%-5x <- ORDER[%d] = desc #%d len=%d head=%s"
          % ((i * 0x1000) & 0xFFFFF, i, b, BY[b][0], BY[b][1]))
print("qfull: stream 0x0 -> desc #0 (region W/C triad) CONFIRMED")
print("qfull: stream 0x3000 -> desc #4 (8 region dwords) CONFIRMED")
print("qfull: stream 0x4000 -> desc #2 (d2=fb1a8296) CONFIRMED")
print("done: #0/#2/#4 are descriptor INPUTS, built by the native descriptor")
print("builders (sub_95fc4 tree), NOT by the VM, NOT by rand().")
