"""_inv2_win.py — raw op window around the first diag-2 round, all wire ops."""
import gzip
import json
import sys

fn = sys.argv[1] if len(sys.argv) > 1 else "_inv2_row7_real.json.gz"
A = json.load(gzip.open(fn, "rt"))
wire = A["wire"]

MAIN = 0x5450001000
QVA = None
names = {0x147630: "PUSH", 0x146470: "PUSH2", 0x147734: "POP", 0x146478: "POP2",
         0x147a20: "CAPSW", 0x14784c: "CAPPU", 0x147a18: "CAPPU0",
         0x147304: "LENQ", 0x146ed8: "EMIT"}
rows = []
for e in wire:
    if e[0] in ("PUSH", "POP"):
        rows.append((e[0], e[1], "q=%x" % (e[2] & 0xFFFF), "v=%08x" % e[3]))
    elif e[0] in ("SW", "PU"):
        rows.append((e[0], e[1], "q=%x" % (e[2] & 0xFFFF), "k=%d" % e[3]))
    elif e[0] == "E" and (e[2] & 0xFFFFFFFFFFFF) == MAIN:
        rows.append(("E", e[1], "abs=%d" % (e[3] + e[4]), "v=%02x" % (e[5] & 0xFF)))
    elif e[0] == "Q" and (e[2] & 0xFFFFFFFFFFFF) == MAIN:
        rows.append(("Q", e[1], "arg=%d" % e[4], "->%08x" % e[5]))

# find the first 0x10d0ec E
i0 = next(i for i, r in enumerate(rows)
          if r[0] == "E" and r[1] == 0x10d0ec)
start = next(i for i, r in enumerate(rows)
             if r[0] == "E" and r[1] == 0x111f70)  # first SKT of round 1
for r in rows[start:i0 + 30]:
    print("%-6s %-9s %-12s %s" % r)
