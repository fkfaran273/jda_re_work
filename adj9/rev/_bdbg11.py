"""_bdbg11.py — extract the per-sweep whitening schedule from a wire log.

The 0x111c68 loop sweeps the d0 byte area [514..657) multiple times.  Each
write: out[i] = in[i] ^ 0x55 ^ sec[fbpos].  Group writes into sweeps (each
sweep = 144 consecutive writes covering 514..657), record the fb position
per (sweep, i).  Compare schedules across rows.
"""
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

def schedule(logfile):
    WL = json.load(open(logfile))
    writes = []          # (si, n, v)
    for si, ev in enumerate(WL):
        if ev[0] == "E" and ev[1] == 0x111c68:
            pos = ev[3] + ev[4] - 620
            if 514 <= pos < 658:
                writes.append((si, pos, ev[5]))
    # fb reads: Q at pc 0x111afc; map si -> (pos, val)
    fbreads = {}
    for si, ev in enumerate(WL):
        if ev[0] == "Q" and ev[1] == 0x111afc:
            fbreads[si] = (ev[3] + ev[4] - 620, ev[5])
    # for each write, fb read = last fbread before it within 45 events
    import bisect
    fbsi = sorted(fbreads)
    sched = []           # per write: (pos, fbpos, fbval)
    for si, pos, v in writes:
        k = bisect.bisect_left(fbsi, si) - 1
        if k < 0 or si - fbsi[k] > 45:
            sched.append((pos, None, None))
            continue
        fp, fv = fbreads[fbsi[k]]
        sched.append((pos, fp, fv))
    # group into sweeps by pos returning to 514
    sweeps = []
    cur = {}
    for (pos, fp, fv) in sched:
        if pos == 514 and cur:
            sweeps.append(cur)
            cur = {}
        cur[pos] = (fp, fv)
    if cur:
        sweeps.append(cur)
    return sweeps, writes


for tag, f in (("row7", "_bdbg5_wirelog.json"),
               ("row4", "_bdbg5_wirelog_row4.json"),
               ("probeA", "_bdbg10_wirelogA.json")):
    try:
        sw, writes = schedule(os.path.join(HERE, f))
    except FileNotFoundError:
        print(tag, "no log")
        continue
    print("%s: %d writes -> %d sweeps" % (tag, len(writes), len(sw)))
    for k, s in enumerate(sw):
        fbpos = [s[i][0] for i in sorted(s)]
        fbval = [s[i][1] for i in sorted(s)]
        print("  sweep %d: fbpos[0..8]=%s ... fbpos[-3:]=%s"
              % (k, fbpos[:9], fbpos[-3:]))
        if k == 0:
            print("           fbval=", bytes(x if x is not None else 0 for x in fbval).hex())
