import sys, os, datetime, calendar
sys.path.insert(0, os.getcwd())
import mylaws as ml

target = bytes.fromhex("3E3B6EC1041DFB7154F0C731513E2AA9")
M, A = 2147483647, 16807

def draws(seed, warmup, n):
    s = int(seed) & 0xFFFFFFFF
    if s == 0: s = 1
    w0 = s if s < 0x80000000 else s - 0x100000000
    r = [0]*31; r[0] = w0; p = w0
    for i in range(1, 31):
        p = (A * p) % M; r[i] = p
    f, b = 3, 0
    out = []
    for k in range(warmup + n):
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < M else v - 0x100000000
        f = (f + 1) % 31; b = (b + 1) % 31
        if k >= warmup: out.append(v >> 1)
    return out

dt = lambda s: datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f")
c_utc = calendar.timegm(dt("2026-02-16T13:44:04.198").timetuple())
s_utc = calendar.timegm(dt("2026-02-16T13:45:48.523").timetuple())
i_utc = calendar.timegm(dt("2026-02-16T13:43:27.591").timetuple())
OFF = 10800
secs = set()
for b in (c_utc, s_utc, i_utc):
    for d in range(-7200, 7201):
        secs.add(b + d); secs.add(b - OFF + d)
print("window size:", len(secs))
hits = []
for s in sorted(secs):
    d = draws(s, 310, 80)
    # header = XOR pairs of d[off:off+8] for any offset 0..72
    for off in range(0, 73):
        w = [d[off + 2*i] ^ d[off + 2*i + 1] for i in range(4)]
        h = b"".join(x.to_bytes(4, "big") for x in w)
        if h == target:
            hits.append((s, "xor_off", off))
    # raw 4 draws at offset
    for off in range(0, 77):
        h = b"".join(d[off + i].to_bytes(4, "big") for i in range(4))
        if h == target:
            hits.append((s, "raw_off", off))
    # little-endian variants
    for off in range(0, 73):
        w = [d[off + 2*i] ^ d[off + 2*i + 1] for i in range(4)]
        h = b"".join(x.to_bytes(4, "little") for x in w)
        if h == target:
            hits.append((s, "xor_off_le", off))
print("hits:", hits)
