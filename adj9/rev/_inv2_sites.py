"""_inv2_sites.py — per-site law lifting on chunk 1 with pre/post state."""
import gzip
import json

MAIN = 0x5450001000
REC_TOP = 1134

A = json.load(gzip.open("_inv2_row7_real.json.gz", "rt"))
wire = A["wire"]
record = bytes.fromhex(A["record"])
blob = bytes.fromhex(A["blob"])

# MAIN E/Q ops in wire order
ops = [(e[0], e[1], e[3] + e[4] if e[0] == "E" else e[4], e[5] & 0xFFFFFFFF)
       for e in wire if e[2] == MAIN and e[0] in ("E", "Q")]

state = {}
pre = []          # (kind, pc, off, pre, val)
for (kind, pc, o, v) in ops:
    pre.append((kind, pc, o, state.get(o, 0), v))
    if kind == "E":
        state[o] = v & 0xFF

# locate the record builder
rb = next(i for i, (kind, pc, o, pv, v) in enumerate(pre) if pc == 0x119538)
re_ = next(i for i in range(len(pre) - 1, -1, -1)
           if pre[i][1] == 0x119538 and pre[i][0] == "E")
print("record build events: %d..%d" % (rb, re_))

# from record build end: print E sites in order (compact) with window
seq = []
for i in range(re_ + 1, len(pre)):
    kind, pc, o, pv, v = pre[i]
    if kind == "E":
        seq.append((i, pc, o, pv, v))

# print the first 400 E events after the record build, grouped by pc
out = []
last_pc = None
cnt = 0
for (i, pc, o, pv, v) in seq:
    if pc != last_pc:
        if last_pc is not None:
            out.append("    (%d events)" % cnt)
        out.append("pc=%#x" % pc)
        last_pc = pc
        cnt = 0
    cnt += 1
    if cnt <= 3:
        out.append("  [%d] abs=%d pre=%02x -> v=%02x" % (i, o, pv, v & 0xFF))
out.append("    (%d events)" % cnt)
print("\n".join(out[:160]))
