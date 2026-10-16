# Extract per-round ARK laws from an interleaved trace (R+W with values).
# Usage: python c_rounds.py trace3.txt.gz
import gzip, sys

KEYLO = 0x900e3e8
STLO = 0x900e6e8
STHI = STLO + 0x400

fn = sys.argv[1] if len(sys.argv) > 1 else "trace3.txt.gz"
ev = []
with gzip.open(fn, "rt") as f:
    for line in f:
        p = line.split()
        ev.append((p[0] == "W", int(p[1], 16), int(p[2], 16), int(p[3]),
                   int(p[4], 16)))
print("events:", len(ev))

# key read positions
kreads = [(i, (a - KEYLO) // 4, v) for i, (w, pc, a, s, v) in enumerate(ev)
          if not w and s == 4 and KEYLO <= a < KEYLO + 768]
# ST read/write positions
stR = {i: ((a - STLO) // 4, v) for i, (w, pc, a, s, v) in enumerate(ev)
       if not w and s == 4 and STLO <= a < STHI and pc == 0x5105bc}
stW = [(i, (a - STLO) // 4, v) for i, (w, pc, a, s, v) in enumerate(ev)
       if w and s == 4 and STLO <= a < STHI and pc == 0x5102b4]

# group key reads into rounds by gap>4000
groups = []
cur = [kreads[0]]
for item in kreads[1:]:
    if item[0] - cur[-1][0] > 4000:
        groups.append(cur)
        cur = [item]
    else:
        cur.append(item)
groups.append(cur)
print("key groups:", [(g[0][1], g[-1][1]) for g in groups])

for gi, g in enumerate(groups):
    if g[0][1] > 174:
        print("group %d: setup slots %d..%d" % (gi, g[0][1], g[-1][1]))
        continue
    lo_ev, hi_ev = g[0][0], g[-1][0]
    # ST writes within round span (from first key read to first key read of
    # next group, minus the mixing tail: ARK writes come right after key
    # reads with matching rhythm; we take writes in [lo_ev, hi_ev+400])
    arkw = [x for x in stW if lo_ev - 50 <= x[0] <= hi_ev + 500]
    print("round group %d: slots %d..%d, ARK writes %d" %
          (gi, g[0][1], g[-1][1], len(arkw)))
    for (ki, slot, kv), (wi, idx, post) in zip(g, arkw):
        # pre value: last ST read of same idx before write
        pre = None
        for j in range(wi - 1, lo_ev - 200, -1):
            if j in stR and stR[j][0] == idx:
                pre = stR[j][1]
                break
        rc = (pre ^ kv ^ post) if pre is not None else None
        print("  slot%3d ST[%3d] pre=%s key=%02x post=%02x rc=%s" %
              (slot, idx, ("%02x" % pre) if pre is not None else "??",
               kv, post, ("%02x" % rc) if rc is not None else "?"))
