"""_inv2_law.py — full E/Q trace of chunk 0 with state, per-site law fitting."""
import gzip
import json

MAIN = 0x5450001000

A = json.load(gzip.open("_inv2_row7_real.json.gz", "rt"))
wire = A["wire"]
ops = [(e[0], e[1], e[3] + e[4] if e[0] == "E" else e[4], e[5] & 0xFFFFFFFF)
       for e in wire if e[2] == MAIN and e[0] in ("E", "Q")]

state = {}
trace = []
for (kind, pc, o, v) in ops:
    if kind == "E":
        trace.append(("E", pc, o, state.get(o, 0), v & 0xFF))
        state[o] = v & 0xFF
    else:
        trace.append(("Q", pc, o, state.get(o, 0), v & 0xFFFFFFFF))

rb = next(i for i, t in enumerate(trace) if t[1] == 0x119538 and t[0] == "E")
re_ = max(i for i, t in enumerate(trace) if t[1] == 0x119538 and t[0] == "E")

# chunk 0 = from re_+1 to the first 0x109f9c after it
c1end = next(i for i in range(re_ + 1, len(trace))
             if trace[i][1] == 0x109f9c and trace[i][0] == "E")
print("chunk 0 events: %d..%d (n=%d)" % (re_ + 1, c1end + 15, c1end + 16 - re_))

# print all E events of chunk 0 with pre/post + the Q taps seen since previous E
qwin = []
for i in range(re_ + 1, c1end + 16):
    kind, pc, o, pv, v = trace[i]
    if kind == "Q":
        qwin.append((o, pv, v))
    else:
        taps = ",".join("%d:%02x->%08x" % (a, b, c) for (a, b, c) in qwin)
        print("E pc=%#x abs=%d pre=%02x -> %02x   taps[%d]: %s"
              % (pc, o, pv, v, len(qwin), taps))
        qwin = []
