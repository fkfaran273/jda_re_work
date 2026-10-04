"""emit_order.py - WHERE does the VM emit the per-call region? Run FinEx on the
golden descriptors and find which emission-stream slots carry region dwords.

emit_trace entries are (stream_va, n, value). We find the output blob stream
S0 (the one whose first 4 dwords == make_header(second)), then report which
blob positions hold region dwords. Then: marker-mode pinpoints the SOURCE
descriptor of every dword (field loop copies desc data verbatim), so a region
dword in the blob that came from desc #0/#2/#4 verbatim = the region is an
INPUT, while a region dword computed mid-queue = derived inside the VM.
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

REGION = {0x13271271, 0xB7D0992B, 0xDB50F44C, 0xB63798CC, 0xDAB7F51A,
          0xFB1A8296, 0x00100400, 0x04144000, 0x8000C440, 0x88104C05,
          0x0025C852, 0xCC6E00B1, 0x01E76C80, 0x427BF58E}

ex = FinEx(SECOND, [(BY[i][0], 0, BY[i][1]) for i in ORDER])
status = ex.run()
print("status:", status, "steps:", ex.steps, "nrand:", ex.nrand)
out = {}
for (s, n, v) in ex.emit_trace:
    out[(s, n)] = v
# find blob stream: first 4 dwords == header
hdr = struct.unpack(">4I", make_header(SECOND))
S0 = None
for (s, n), v in out.items():
    if n == 0 and v == hdr[0]:
        if all(out.get((s, k), -1) == hdr[k] for k in range(4)):
            S0 = s
            break
print("blob stream S0=0x%x" % (S0 or 0))
blob = [out.get((S0, k), 0) for k in range(48)]
print("blob dwords that are region values:")
for k, v in enumerate(blob):
    if v in REGION:
        print("  blob[%2d] = 0x%08x" % (k, v))
print("done")
