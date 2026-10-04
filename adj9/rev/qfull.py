"""qfull.py - FULL queue-flow trace of the golden run: every PUSH/POP/EMIT with
values, to find WHERE #0/#2/#4 dwords ENTER the queue system.

The field loop EMITs desc data into streams; the queue program merges streams
into the blob. Region dwords must ENTER via one of: field-loop EMIT of desc
#0/#2/#4 (=> they are INPUTS, built by sub_95fc4 tree) or OP_RAND (=> PRNG).
Log every EMIT (stream va, n, value) and every PUSH value during the golden
run; report first-appearance of each region dword.
"""
import sys
import os
import json
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vm_final as V
from fin_vm2 import FinEx
from header_gen import make_header

BY = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
      for d in json.load(open(os.path.join(HERE, "fin_descs.json")))["descs"]}
ORDER = json.load(open(os.path.join(HERE, "fin_descs.json")))["va_order"]
SECOND = 1789240512

REGION = [0x13271271, 0xDB50F44C, 0xB63798CC, 0xDAB7F51A, 0xB7D0992B,
          0xFB1A8296, 0x00100400, 0x04144000, 0x8000C440, 0x88104C05,
          0x0025C852, 0xCC6E00B1, 0x01E76C80, 0x427BF58E]
RSET = set(REGION)

ex = FinEx(SECOND, [(BY[i][0], 0, BY[i][1]) for i in ORDER])
ex.__dict__["_storelog"] = []
status = ex.run(max_steps=4000000)
print("status:", status, "steps:", ex.steps, "nrand:", ex.nrand)
print("emit_trace entries:", len(ex.emit_trace))
first = {}
for idx, (s, n, v) in enumerate(ex.emit_trace):
    if v in RSET and v not in first:
        first[v] = (idx, s & 0xFFFFF, n)
print("first EMIT appearance of each region dword (trace_idx, stream, n):")
for v in REGION:
    print("  0x%08x -> %s" % (v, first.get(v)))
print("done")
