import sys, os, datetime, calendar
sys.path.insert(0, os.getcwd())
import mylaws as ml

target = bytes.fromhex("3E3B6EC1041DFB7154F0C731513E2AA9")
M, A = 2147483647, 16807

def header_variant(seed, chain="m31", f0=3, b0=0, warmup=310, ndraw=8, mode="xor_adj", out_shift=1):
    s = int(seed) & 0xFFFFFFFF
    if s == 0: s = 1
    w0 = s if s < 0x80000000 else s - 0x100000000
    r = [0]*31
    r[0] = w0
    p = w0
    for i in range(1, 31):
        if chain == "m31": p = (A * p) % M
        elif chain == "m31u": p = (A * p) % M if p >= 0 else p  # same, kept for clarity
        elif chain == "m32": p = (A * p) & 0xFFFFFFFF
        elif chain == "m31half": p = (A * p) % (2**31)
        r[i] = p if p < 0x80000000 else p - 0x100000000
    f, b = f0 % 31, b0 % 31
    d = []
    for k in range(warmup + ndraw):
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < M else v - 0x100000000
        f = (f + 1) % 31; b = (b + 1) % 31
        if k >= warmup: d.append(v >> out_shift)
    if mode == "xor_adj":
        words = [d[2*i] ^ d[2*i+1] for i in range(4)]
    elif mode == "raw4":
        words = d[:4]
    elif mode == "xor_cross":
        words = [d[i] ^ d[i+4] for i in range(4)]
    elif mode == "raw8_be16":
        # 8 draws -> 16 bytes as (d >> 16) big-endian shorts? skip
        words = None
    if words is None: return None
    return b"".join((x & 0xFFFFFFFF).to_bytes(4, "big") for x in words)

dt = lambda s: datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f")
c_utc = calendar.timegm(dt("2026-02-16T13:44:04.198").timetuple())
s_utc = calendar.timegm(dt("2026-02-16T13:45:48.523").timetuple())
i_utc = calendar.timegm(dt("2026-02-16T13:43:27.591").timetuple())
OFF = 10800
plaus = set()
for b in (c_utc, s_utc, i_utc):
    for d in range(-300, 301):
        plaus.add(b + d); plaus.add(b - OFF + d)

hits = []
for s in sorted(plaus):
    for chain in ("m31", "m32", "m31half"):
        for f0, b0 in ((3,0),(0,0),(3,3),(0,3),(1,0),(2,1),(31,0)):
            for wu in (310,):
                for mode in ("xor_adj","raw4","xor_cross"):
                    for sh in (1,0):
                        h = header_variant(s, chain, f0, b0, wu, 8, mode, sh)
                        if h == target:
                            hits.append((s, chain, f0, b0, mode, sh))
print("plausible-window hits:", hits)

# raw4 with other draw counts
for s in sorted(plaus):
    for nd in (4, 16, 12):
        h = header_variant(s, "m31", 3, 0, 310, nd, "raw4" if nd>=4 else "raw4", 1)
        if h == target: hits.append((s, "raw4", nd))
        h2 = header_variant(s, "m31", 3, 0, 310, nd, "xor_adj", 1) if nd >= 8 else None
        if h2 == target: hits.append((s, "xor_adj", nd))
print("all hits:", hits)
