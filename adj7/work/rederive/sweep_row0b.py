import numpy as np, sys, os, datetime, calendar
sys.path.insert(0, os.getcwd())

target = bytes.fromhex("3E3B6EC1041DFB7154F0C731513E2AA9")
t_words = [int.from_bytes(target[4*i:4*i+4], "big") for i in range(4)]

dt = datetime.datetime.strptime("2026-02-16T13:44:04.198", "%Y-%m-%dT%H:%M:%S.%f")
base = calendar.timegm(dt.timetuple()) - 10800
lo, hi = base - 30*86400, base + 30*86400
seeds_all = np.arange(lo, hi + 1, dtype=np.uint32)

M31 = np.uint64(2147483647)
pw = np.array([pow(16807, i, 2147483647) for i in range(31)], dtype=np.uint64)
NOUT = 40   # draws 311..350

def draws_batch(seeds):
    s = seeds.astype(np.uint64)
    r = (s[:, None] * pw[None, :]) % M31
    out = np.empty((len(seeds), NOUT), dtype=np.uint64)
    for k in range(310 + NOUT):
        f = (3 + k) % 31
        b = k % 31
        v = (r[:, f] + r[:, b]) & np.uint64(0xFFFFFFFF)
        r[:, f] = np.where(v >= M31, v - np.uint64(0x100000000), v)
        d = k - 310
        if d >= 0:
            out[:, d] = v >> np.uint64(1)
    return out

CH = 400_000
hits = []
for i in range(0, len(seeds_all), CH):
    ch = seeds_all[i:i+CH]
    d = draws_batch(ch)
    for off in range(0, NOUT - 8 + 1):
        w = d[:, off::2][:, :4] ^ d[:, off+1::2][:, :4]   # pairs d[off],d[off+1],...
        m = (w[:,0] == t_words[0]) & (w[:,1] == t_words[1]) & (w[:,2] == t_words[2]) & (w[:,3] == t_words[3])
        if m.any():
            for sec in ch[m].tolist():
                hits.append((int(sec), "xor", off))
                print("HIT xor:", sec, datetime.datetime.utcfromtimestamp(sec), "off", off)
    for off in range(0, NOUT - 4 + 1):
        w = d[:, off:off+4]
        m = (w[:,0] == t_words[0]) & (w[:,1] == t_words[1]) & (w[:,2] == t_words[2]) & (w[:,3] == t_words[3])
        if m.any():
            for sec in ch[m].tolist():
                hits.append((int(sec), "raw", off))
                print("HIT raw:", sec, datetime.datetime.utcfromtimestamp(sec), "off", off)
print("done, hits:", hits)
