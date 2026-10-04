"""drawmap.py - find WHERE the 8 OP_RAND draws go: which queue slots / EMIT
positions receive rand() output. If rand feeds ONLY the 16-B header, the 8
draws land in blob[0:4] (as 4 XOR pairs). Then #0/#2/#4 are NOT rand-derived
at all -> they come from the descriptor builders (sub_95fc4/sub_bb548 tree).

Method: FinEx run with _calls logging + emit_trace; locate the 8 OP_RAND
return PCs, then find which PUSH consumed each (next PUSH after each RAND),
and which EMIT positions those queue slots reach in the blob stream.
"""
import sys
import os
import json
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

BY = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
      for d in json.load(open(os.path.join(HERE, "fin_descs.json")))["descs"]}
ORDER = json.load(open(os.path.join(HERE, "fin_descs.json")))["va_order"]
SECOND = 1789240512

ex = FinEx(SECOND, [(BY[i][0], 0, BY[i][1]) for i in ORDER])
status = ex.run()
print("status:", status, "steps:", ex.steps, "nrand:", ex.nrand)
calls = ex.__dict__.get("_calls", [])
rands = [(pc, regs, st) for (pc, tgt, regs, st) in calls if "48d10" in tgt]
print("OP_RAND calls logged: %d" % len(rands))
for pc, regs, st in rands[:12]:
    print("  %s regs=%s step=%d" % (pc, regs, st))
print("done")
