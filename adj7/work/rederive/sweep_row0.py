import numpy as np, sys, os, datetime, calendar
sys.path.insert(0, os.getcwd())
import mylaws as ml

target = bytes.fromhex("3E3B6EC1041DFB7154F0C731513E2AA9")
t_words = [int.from_bytes(target[4*i:4*i+4], "big") for i in range(4)]

dt = datetime.datetime.strptime("2026-02-16T13:44:04.198", "%Y-%m-%dT%H:%M:%S.%f")
base = calendar.timegm(dt.timetuple()) - 10800   # 10:44:04 UTC
lo, hi = base - 30*86400, base + 30*86400
seeds_all = np.arange(lo, hi + 1, dtype=np.uint32)

M31 = np.uint64(2147483647)
A = np.uint64(16807)
pw = np.array([pow(16807, i, 2147483647) for i in range(31)], dtype=np.uint64)

def header_batch(seeds):
    n = len(seeds)
    s = seeds.astype(np.uint64)
    # r[i] = s * A^i mod M31  (r[0] = s)
    r = (s[:, None] * pw[None, :]) % M31          # (n,31) values in [0, M31)
    f0, b0 = 3, 0
    out_draws = np.empty((n, 8), dtype=np.uint64)
    for k in range(318):
        f = (3 + k) % 31
        b = k % 31
        v = (r[:, f] + r[:, b]) & np.uint64(0xFFFFFFFF)
        rv = np.where(v >= M31, v - np.uint64(0x100000000), v)
        r[:, f] = rv
        d = k - 310
        if d >= 0:
            out_draws[:, d] = v >> np.uint64(1)
    w = out_draws[:, 0::2] ^ out_draws[:, 1::2]   # (n,4)
    return w

CH = 400_000
hits = []
for i in range(0, len(seeds_all), CH):
    ch = seeds_all[i:i+CH]
    w = header_batch(ch)
    m = (w[:,0] == t_words[0]) & (w[:,1] == t_words[1]) & (w[:,2] == t_words[2]) & (w[:,3] == t_words[3])
    if m.any():
        hits.extend(ch[m].tolist())
        print("HIT:", [h for h in ch[m].tolist()])
print("sweep done", lo, "->", hi, "hits:", hits)
for h in hits:
    print("  sec", h, datetime.datetime.utcfromtimestamp(h),
          "delta vs created_off:", h - base)
# sanity: verify the batch function against the scalar impl
test = np.array([1771238644, 1771238645, 1769758661], dtype=np.uint32)
w = header_batch(test)
for s, row in zip(test.tolist(), w.tolist()):
    scalar = ml.header_from_second(s)
    got = b"".join(int(x).to_bytes(4, "big") for x in row)
    assert got == scalar, (s, got.hex(), scalar.hex())
print("batch fn sanity: OK")
