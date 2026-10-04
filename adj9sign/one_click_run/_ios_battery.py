"""Battery test: (A) verify the bit-13 anomaly rigorously, (B) test hash-based
and modern-generator header hypotheses in the exact signing window.

(A) matters because if bit-13 bias is real, the Android pair-XOR composition is
excluded and the words share per-second state. If it's noise, the exclusion falls.
"""
import base64, hashlib, re, struct, zipfile, zlib
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
print(f"distinct headers: {len(data)}\n")

# ---------------- (A) bit-13 verification ----------------
print("=" * 70)
print("A) PER-BIT STATISTICS with rigorous permutation test")
words = []
for h, _, _ in data:
    words.extend(struct.unpack(">4I", h))
nb = len(words)
obs = [sum((w >> b) & 1 for w in words) for b in range(31)]
print(f"n words = {nb}")
top = sorted(range(31), key=lambda b: -abs(obs[b] - nb / 2))[:6]
for b in top:
    zsc = (obs[b] - nb / 2) / (nb * 0.25) ** 0.5
    print(f"  bit{b:<2} ones={obs[b]:>3}/{nb} rate={obs[b]/nb:.3f}  z={zsc:+.2f}")

# proper test: distribution of max|z| over all 31 bits under the null
import random
mx = []
for _ in range(20000):
    s = [sum(random.getrandbits(1) for _ in range(nb)) for _ in range(31)]
    mx.append(max(abs(s[b] - nb / 2) / (nb * 0.25) ** 0.5 for b in range(31)))
mx.sort()
p_max = sum(1 for v in mx if v >= max(abs(obs[b] - nb / 2) / (nb * 0.25) ** 0.5 for b in range(31))) / len(mx)
print(f"\n  max|z| observed = {max(abs(obs[b]-nb/2)/(nb*0.25)**0.5 for b in range(31)):.2f}")
print(f"  permutation p (any bit reaching this |z|) = {p_max:.4f}   "
      f"{'<-- REAL SIGNAL' if p_max < 0.01 else '<-- NOT significant (multiple-testing noise)'}")

# per-slot bit-13
for b in (13, 25):
    if b < 31:
        per = [sum((struct.unpack('>4I', h)[s] >> b) & 1 for h, _, _ in data) for s in range(4)]
        print(f"  bit{b} per-slot counts {per} (of {len(data)})")
pops = [sum((w >> 13) & 1 for w in struct.unpack(">4I", h)) for h, _, _ in data]
from collections import Counter
print(f"  within-header bit-13 popcount distribution: {dict(sorted(Counter(pops).items()))}")

# ---------------- (B) hypothesis battery ----------------
print("\n" + "=" * 70)
print("B) GENERATOR / HASH HYPOTHESES (exact window, +/-4 s)")


def words_from(d, layout="be-pair"):
    if layout == "be-pair":
        return b"".join(struct.pack(">I", (d[i] ^ d[i + 1]) & 0xFFFFFFFF) for i in range(0, 8, 2))
    if layout == "le-pair":
        return b"".join(struct.pack("<I", (d[i] ^ d[i + 1]) & 0xFFFFFFFF) for i in range(0, 8, 2))
    if layout == "be-direct":
        return b"".join(struct.pack(">I", d[i] & 0x7FFFFFFF) for i in range(4))
    if layout == "le-direct":
        return b"".join(struct.pack("<I", d[i] & 0x7FFFFFFF) for i in range(4))
    if layout == "be-mix":   # d ^ (d>>16) per draw
        return b"".join(struct.pack(">I", ((d[i] ^ (d[i] >> 16)) & 0x7FFFFFFF)) for i in range(4))
    raise ValueError(layout)


def splitmix64(x):
    x = (x + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
    z = x
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & ((1 << 64) - 1)
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & ((1 << 64) - 1)
    return z ^ (z >> 31)


def splitmix_draws(seed, n=8):
    s = seed & ((1 << 64) - 1)
    return [splitmix64(s + i * 0x9E3779B97F4A7C15) for i in range(n)]


def xorshift64s(x):
    x &= (1 << 64) - 1
    x ^= (x << 13) & ((1 << 64) - 1)
    x ^= x >> 7
    x ^= (x << 17) & ((1 << 64) - 1)
    return x


def xorshift_draws(seed, n=8):
    s = seed if seed else 88172645463325252
    out = []
    for _ in range(n):
        s = xorshift64s(s)
        out.append(s)
    return out


def mt19937(seed, n=8):
    mt = [0] * 624
    mt[0] = seed & 0xFFFFFFFF
    for i in range(1, 624):
        mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
    idx = 624
    out = []
    while len(out) < n:
        if idx >= 624:
            for i in range(624):
                y = (mt[i] & 0x80000000) + (mt[(i + 1) % 624] & 0x7FFFFFFF)
                mt[i] = mt[(i + 397) % 624] ^ (y >> 1)
                if y % 2:
                    mt[i] ^= 0x9908B0DF
            idx = 0
        y = mt[idx]
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        out.append(y & 0xFFFFFFFF)
        idx += 1
    return out


def pcg32(seed, n=8):
    s = (seed * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
    st = s | 1
    out = []
    for _ in range(n):
        old = st
        st = (old * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        xorshifted = (((old >> 18) ^ old) >> 27) & 0xFFFFFFFF
        rot = (old >> 59) & 31
        out.append(((xorshifted >> rot) | (xorshifted << ((-rot) & 31))) & 0xFFFFFFFF)
    return out


def hash_draws(sec, kind):
    out = []
    if kind == "sha1_be":
        dg = hashlib.sha1(struct.pack(">I", sec)).digest()
    elif kind == "sha1_le":
        dg = hashlib.sha1(struct.pack("<I", sec)).digest()
    elif kind == "sha1_dec":
        dg = hashlib.sha1(str(sec).encode()).digest()
    elif kind == "sha256_be":
        dg = hashlib.sha256(struct.pack(">I", sec)).digest()
    elif kind == "sha256_dec":
        dg = hashlib.sha256(str(sec).encode()).digest()
    elif kind == "md5_be":
        dg = hashlib.md5(struct.pack(">I", sec)).digest()
    elif kind == "blake2b":
        dg = hashlib.blake2b(struct.pack(">I", sec), digest_size=32).digest()
    elif kind == "sha1d":
        dg = hashlib.sha1(struct.pack(">Q", sec)).digest()
    for i in range(0, len(dg) - 3, 4):
        out.append(struct.unpack(">I", dg[i:i + 4])[0] & 0x7FFFFFFF)
    while len(out) < 8:
        out.append(0)
    return out[:8]


GENS = {
    "splitmix64": splitmix_draws, "xorshift64s": xorshift_draws,
    "mt19937": mt19937, "pcg32": pcg32,
}
for k in ("sha1_be", "sha1_le", "sha1_dec", "sha1d", "sha256_be", "sha256_dec",
          "md5_be", "blake2b"):
    GENS["hash-" + k] = (lambda kk: (lambda s: hash_draws(s, kk)))(k)
LAYOUTS = ["be-pair", "le-pair", "be-direct", "le-direct", "be-mix"]

hits = 0
for gname, gen in GENS.items():
    for lay in LAYOUTS:
        ok = 0
        for h, lo, hi in data:
            if any(words_from(gen(sec), lay) == h for sec in range(lo - 4, hi + 5)):
                ok += 1
        if ok:
            hits += 1
            print(f"  *** HIT {gname} / {lay}: {ok}/{len(data)}")
print(f"  hits: {hits}   (hypotheses tested: {len(GENS)} generators x {len(LAYOUTS)} layouts)")