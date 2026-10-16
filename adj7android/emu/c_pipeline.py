# Master pipeline extractor: replay ALL state-array + key events from trace4,
# classify each phase (record-load, xor layers, ARK rounds, SB, SR, MC).
import gzip, sys

KEYLO, STLO = 0x900e3e8, 0x900e6e8
STN = 256
SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

ev = []
with gzip.open("trace4.txt.gz", "rt") as f:
    for line in f:
        p = line.split()
        ev.append((p[0] == "W", int(p[1], 16), int(p[2], 16), int(p[3]),
                   int(p[4], 16)))
print("events:", len(ev))

st = [None] * STN          # simulated state
log = []                   # (idx, op, detail)
kreads = []                # (evi, slot, val) in order


def classify_write(idx, val, pc, evi):
    global st
    if st[idx] is None:
        st[idx] = val
        return "init"
    pre = st[idx]
    d = pre ^ val
    if d == 0:
        return "same"
    if val == SBOX[pre]:
        st[idx] = val
        return "SB"
    st[idx] = val
    return ("XOR", d)


# walk events; classify ST writes; collect key reads
phases = []
cur = []
for evi, (w, pc, a, s, v) in enumerate(ev):
    v &= (1 << (s * 8)) - 1
    if s == 4 and KEYLO <= a < KEYLO + 768:
        if not w:
            kreads.append((evi, (a - KEYLO) // 4, v))
        continue
    if s == 4 and STLO <= a < STLO + 4 * STN:
        idx = (a - STLO) // 4
        if w:
            c = classify_write(idx, v, pc, evi)
            cur.append((evi, idx, c, v))
            if len(cur) > 4000:
                phases.append(cur)
                cur = []
        else:
            cur.append((evi, idx, "R", v))
phases.append(cur)
print("key reads:", len(kreads))
print("first 5 key reads:", kreads[:5])

# print condensed phase summaries
for pi, ph in enumerate(phases):
    kinds = {}
    for evi, idx, c, v in ph:
        k = c if isinstance(c, str) else c[0]
        kinds[k] = kinds.get(k, 0) + 1
    print("phase %d: %d events, kinds=%s, ev range %d..%d" %
          (pi, len(ph), kinds, ph[0][0], ph[-1][0]))

sys.stdout.flush()
# dump first 120 events of phase 0 and phase boundaries around key reads
with open("c_pipeline_out.txt", "w") as f:
    for pi, ph in enumerate(phases):
        f.write("== phase %d (%d events, %d..%d)\n" %
                (pi, len(ph), ph[0][0], ph[-1][0]))
        for evi, idx, c, v in ph[:200]:
            f.write("%7d ST[%3d] %-8s %02x\n" % (evi, idx, str(c), v))
print("wrote c_pipeline_out.txt")
