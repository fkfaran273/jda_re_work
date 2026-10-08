import sys, os, datetime, calendar, struct
sys.path.insert(0, os.getcwd())
import mylaws as ml

target = bytes.fromhex("3E3B6EC1041DFB7154F0C731513E2AA9")
M, A = 2147483647, 16807

def bionic_state(seed, warmup):
    g = ml.Bionic(seed)
    # redo with custom warmup: rebuild manually
    s = int(seed) & 0xFFFFFFFF
    if s == 0: s = 1
    w = s if s < 0x80000000 else s - 0x100000000
    r = [0]*31
    r[0] = w
    p = w
    for i in range(1, 31):
        p = (A * p) % M
        r[i] = p
    f, b = 3, 0
    def step():
        nonlocal f, b
        v = (r[f] + r[b]) & 0xFFFFFFFF
        r[f] = v if v < M else v - 0x100000000
        f = (f + 1) % 31
        b = (b + 1) % 31
        return v >> 1
    for _ in range(warmup): step()
    return step

def minstd(seed):
    x = seed % M
    def step():
        nonlocal x
        x = (A * x) % M
        return x
    return step

def java_random(seed):
    state = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
    def step(bits=32):
        nonlocal state
        state = (state * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return state >> (48 - bits)
    return step

def variants(seed):
    """yield (name, 16-byte header)"""
    outs = {}
    for wu in (0, 10, 31, 100, 310, 311, 1000):
        st = bionic_state(seed, wu)
        d = [st() for _ in range(8)]
        outs[f"bionic_wu{wu}_xor_adj_be"] = b"".join(((d[2*i] ^ d[2*i+1]) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(4))
        outs[f"bionic_wu{wu}_xor_adj_le"] = b"".join(((d[2*i] ^ d[2*i+1]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(4))
        outs[f"bionic_wu{wu}_xor_cross_be"] = b"".join(((d[i] ^ d[i+4]) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(4))
        outs[f"bionic_wu{wu}_raw4_be"] = b"".join(d[i].to_bytes(4, "big") for i in range(4))
        outs[f"bionic_wu{wu}_raw4_le"] = b"".join(d[i].to_bytes(4, "little") for i in range(4))
        outs[f"bionic_wu{wu}_xor8_be"] = ((d[0] ^ d[1]) & 0xFFFFFFFF).to_bytes(4, "big") + ((d[2] ^ d[3]) & 0xFFFFFFFF).to_bytes(4, "big") + ((d[4] ^ d[5]) & 0xFFFFFFFF).to_bytes(4, "big") + ((d[6] ^ d[7]) & 0xFFFFFFFF).to_bytes(4, "big")
        # full-word output variant
        st2 = bionic_state(seed, wu)
        # rebuild with no >>1
        s = seed & 0xFFFFFFFF or 1
        w0 = s if s < 0x80000000 else s - 0x100000000
        r = [0]*31; r[0] = w0; p = w0
        for i in range(1, 31):
            p = (A * p) % M; r[i] = p
        f, b = 3, 0
        dd = []
        for k in range(wu + 8):
            v = (r[f] + r[b]) & 0xFFFFFFFF
            r[f] = v if v < M else v - 0x100000000
            f = (f + 1) % 31; b = (b + 1) % 31
            if k >= wu: dd.append(v)
        outs[f"bionic_wu{wu}_noshift_xor_be"] = b"".join(((dd[2*i] ^ dd[2*i+1]) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(4))
    st = minstd(seed)
    for wu in (0, 310, 10000):
        st2 = minstd(seed)
        for _ in range(wu): st2()
        d = [st2() for _ in range(8)]
        outs[f"minstd_wu{wu}_xor_be"] = b"".join(((d[2*i] ^ d[2*i+1]) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(4))
        outs[f"minstd_wu{wu}_raw4_be"] = b"".join(d[i].to_bytes(4, "big") for i in range(4))
    j = java_random(seed)
    d = [j(32) for _ in range(8)]
    outs["java_xor_be"] = b"".join(((d[2*i] ^ d[2*i+1]) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(4))
    outs["java_raw4_be"] = b"".join(d[i].to_bytes(4, "big") for i in range(4))
    return outs

dt = lambda s: datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f")
c_utc = calendar.timegm(dt("2026-02-16T13:44:04.198").timetuple())
s_utc = calendar.timegm(dt("2026-02-16T13:45:48.523").timetuple())
i_utc = calendar.timegm(dt("2026-02-16T13:43:27.591").timetuple())
OFF = 10800
secs = set()
for b in (c_utc, s_utc, i_utc):
    for d in range(-300, 301):
        secs.add(b + d)          # as-UTC
        secs.add(b - OFF + d)    # offset-applied
# ms-based seeds
ms_variants = {
    "created_ms_utc": c_utc * 1000 + 198, "created_ms_off": (c_utc - OFF) * 1000 + 198,
    "sent_ms_utc": s_utc * 1000 + 523, "sent_ms_off": (s_utc - OFF) * 1000 + 523,
    "created_ms32_utc": (c_utc * 1000 + 198) & 0xFFFFFFFF,
    "created_ms32_off": ((c_utc - OFF) * 1000 + 198) & 0xFFFFFFFF,
    "sent_ms32_off": ((s_utc - OFF) * 1000 + 523) & 0xFFFFFFFF,
    "install_ms32_off": ((i_utc - OFF) * 1000 + 591) & 0xFFFFFFFF,
}
hits = []
for s in sorted(secs):
    for name, h in variants(s).items():
        if h == target:
            hits.append((name, s))
for name, seed in ms_variants.items():
    for vn, h in variants(seed & 0xFFFFFFFF).items():
        if h == target:
            hits.append((f"{name}/{vn}", seed))
print("hits:", hits)

# also dump the plain bionic headers at the most plausible seconds for eyeballing
for s in (c_utc, c_utc - OFF, s_utc - OFF, s_utc):
    print(s, ml.header_from_second(s).hex(), "TARGET:", target.hex())
