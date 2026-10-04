"""Identify the header COMPOSITION by scoring predicted bit-13 rate.

Confirmed fact: observed bit-13 rate = 0.688 (p=0.0025 under permutation test),
high in all four word slots, and within-header popcount of 1 never occurs.
XOR of two independent 31-bit draws predicts exactly 0.500 -> excluded.

So score every (generator, composition) pair by its PREDICTED bit-13 rate over a
large seed sample. The correct composition should land near 0.688. Then confirm
with exact matching inside the signing window.
"""
import base64, re, struct, zipfile
from datetime import datetime

SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
z = zipfile.ZipFile(SAZ)
rows = []
for n in sorted(z.namelist()):
    if n.endswith("_c.txt"):
        d = z.read(n).decode("utf8", errors="replace")
        m = re.search(r'signature="([^"]+)"', d)
        if m:
            rows.append((int(re.search(r"(\d+)_c", n).group(1)),
                         base64.b64decode(m.group(1))[:16]))
times = {}
for n in z.namelist():
    if n.endswith("_m.xml"):
        sid = int(re.search(r"(\d+)_m", n).group(1))
        x = z.read(n).decode("utf8", "replace")
        cc = re.search(r'ClientConnected="([^"]+)"', x)
        br = re.search(r'ClientBeginRequest="([^"]+)"', x)
        if cc and br:
            times[sid] = (datetime.fromisoformat(cc.group(1).replace("Z", "+00:00")).timestamp(),
                          datetime.fromisoformat(br.group(1).replace("Z", "+00:00")).timestamp())
seen, data = set(), []
for sid, h in rows:
    if sid in times and h.hex() not in seen:
        seen.add(h.hex())
        lo, hi = times[sid]
        data.append((h, int(lo), int(hi)))

M31 = 0x7FFFFFFF
M32 = 0xFFFFFFFF
P = 2 ** 31 - 1


def minstd(seed, n=8):
    x = seed & M31
    if x == 0:
        x = 1
    out = []
    for _ in range(n):
        hi, lo = divmod(x, 127773)
        x = 16807 * lo - 2836 * hi
        if x < 0:
            x += P
        out.append(x)
    return out


def apple_rand(seed, n=8):
    ctx = seed & M32
    out = []
    for _ in range(n):
        x = (ctx % 0x7FFFFFFE) + 1
        hi, lo = divmod(x, 127773)
        x = 16807 * lo - 2836 * hi
        if x < 0:
            x += 0x7FFFFFFF
        ctx = x
        out.append(x)
    return out


def lrand48(seed, n=8):
    X = (((seed & M32) << 16) | 0x330E) & ((1 << 48) - 1)
    out = []
    for _ in range(n):
        X = (0x5DEECE66D * X + 0xB) & ((1 << 48) - 1)
        out.append(X >> 17)
    return out


def bsd_random(seed, n=8, warm=310):
    """classic BSD random(): state[0]=seed, state[1..30] = 1103515245 LCG."""
    st = [0] * 31
    st[0] = seed & M31
    for i in range(1, 31):
        st[i] = (1103515245 * st[i - 1] + 12345) & M31
    f, b = 3, 0
    out = []
    for i in range(warm + n):
        v = (st[f] + st[b]) & M31
        st[f] = v
        o = v >> 1
        f = (f + 1) % 31
        b = (b + 1) % 31
        if i >= warm:
            out.append(o)
    return out


GENS = {"minstd": minstd, "apple_rand": apple_rand, "lrand48": lrand48, "bsd_random": bsd_random}


def comps(d):
    """composition -> 4 words (each masked to 31 bits)"""
    o = {}
    o["xor_consec"] = [(d[2 * i] ^ d[2 * i + 1]) & M31 for i in range(4)]
    o["xor_skip2"] = [(d[i] ^ d[i + 4]) & M31 for i in range(4)]
    o["add_consec"] = [(d[2 * i] + d[2 * i + 1]) & M31 for i in range(4)]
    o["sub_consec"] = [(d[2 * i] - d[2 * i + 1]) & M31 for i in range(4)]
    o["sub_rev"] = [(d[2 * i + 1] - d[2 * i]) & M31 for i in range(4)]
    o["and_consec"] = [d[2 * i] & d[2 * i + 1] for i in range(4)]
    o["direct_even"] = [d[2 * i] & M31 for i in range(4)]
    o["mul_consec"] = [(d[2 * i] * d[2 * i + 1]) & M31 for i in range(4)]
    o["diff_prev"] = [(d[2 * i] - d[2 * i - 1]) & M31 for i in range(4)] if d[0] else [0] * 4
    o["div_consec"] = [((d[2 * i + 1] - d[2 * i]) // 16806) & M31 for i in range(4)]
    return o


OBS = 0.688
print(f"observed bit-13 rate: {OBS}   (bit25: 0.634)\n")
print(f"{'generator':<12} {'composition':<12} {'pred b13':>9} {'dist':>7}   verdict")
best = []
for gname, gen in GENS.items():
    acc = {}
    for s in range(1780000000, 1780004000):
        d = gen(s, 16)
        for k, ws in comps(d).items():
            for w in ws:
                acc.setdefault(k, []).append((w >> 13) & 1)
    for k, bits in acc.items():
        rate = sum(bits) / len(bits)
        dev = abs(rate - OBS)
        best.append((dev, gname, k, rate, len(bits)))
best.sort()
for dev, gname, k, rate, nb in best[:18]:
    flag = "*** CLOSE" if dev < 0.03 else ("close" if dev < 0.06 else "")
    print(f"{gname:<12} {k:<12} {rate:>9.4f} {abs(rate-0.5):>7.4f}   {flag}")

print("\n=== exact-match confirmation for the top compositions ===")
for dev, gname, k, rate, nb in best[:8]:
    gen = GENS[gname]
    ok = 0
    for h, lo, hi in data:
        hit = False
        for sec in range(lo - 4, hi + 5):
            ws = comps(gen(sec, 16))[k]
            for endian in (">I", "<I"):
                if b"".join(struct.pack(endian, w) for w in ws) == h:
                    hit = True
                    break
            if hit:
                break
        ok += hit
    print(f"  {gname:<12} {k:<12} predicted_b13={rate:.3f}  exact={ok}/{len(data)}")