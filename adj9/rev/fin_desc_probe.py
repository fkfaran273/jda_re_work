"""fin_desc_probe.py - assignment-independent question:

Run FinEx on the GOLDEN descriptor set (fin_descs.json + golden second, known to
reproduce the golden blob) and inspect its emit_trace:

  * are the descriptor data words emitted into streams (EMIT) ?
  * or are descriptors only *read* (LENQ) from pre-filled streams?

This decides whether the slice-118 captured EMIT plane IS the descriptor plane.
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
from fin_vm2 import FinEx
from header_gen import make_header

SEC = 1789240512
d = json.load(open(os.path.join(HERE, "fin_descs.json"), encoding="utf-8"))
ORDER = json.load(open(os.path.join(HERE, "adj9_material.json")))["va_order"]
by = {}
for x in d["descs"]:
    by[x["build_idx"]] = (x["len_dw"], bytes.fromhex(x["data_hex"]))
print("descriptors:", {k: (v[0], len(v[1])) for k, v in sorted(by.items())})
descs = [(by[i][0], 0, by[i][1]) for i in ORDER]
print("ORDER:", ORDER)

ex = FinEx(SEC, descs)
st = ex.run(max_steps=20_000_000)
print("status:", st, "steps:", ex.steps, "emits:", len(ex.emit_trace))

out = {}
for (s_, n, v) in ex.emit_trace:
    out[(s_, n)] = v
hdr = struct.unpack(">4I", make_header(SEC))
stream = None
for (s_, n) in out:
    if tuple(out.get((s_, k), 0) for k in range(4)) == hdr:
        stream = s_
        break
got = b""
if stream is not None:
    got = b"".join(struct.pack(">I", out.get((stream, k), 0)) for k in range(48))
print("reproduced blob:", got.hex())
print("header law OK:", make_header(SEC) == got[:16] if got else None)

# --- does the trace contain the descriptor words? --------------------------
emitted = set(v for _, _, v in ex.emit_trace)
print()
print("--- descriptor-word presence in emit_trace ---")
for i in ORDER:
    ln, data = by[i]
    words = list(struct.unpack("<%dI" % ln, data)) if ln else []
    hits = sum(1 for w in words if w in emitted)
    print("  build_idx %-2d len_dw=%-3d words=%-3d present_in_emit=%d/%d" %
          (i, ln, len(words), hits, len(words)))
    if hits and hits < len(words):
        print("      missing:", ["%08x" % w for w in words if w not in emitted][:6])

# --- stream census of the trace --------------------------------------------
byq = {}
for (s_, n, v) in ex.emit_trace:
    byq.setdefault(s_, {})[n] = v
print()
print("--- FinEx streams (va, slots) ---")
for s_ in sorted(byq, key=lambda x: -len(byq[x])):
    m = byq[s_]
    print("  va=%#x slots=%-4d n=%d..%d" % (s_, len(m), min(m), max(m)))