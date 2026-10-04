"""fit_families.py - test PRF / PRNG candidate families against the labelled
(V, pid, tid) -> region table.  Reports hits/misses per family.

A family is a function  out(V,pid,tid) -> bytes.  We score it three ways:
  exact_d4 : 32-byte output == d4  (the 256-bit avalanche block)
  exact_all: output == d0||d2||d4 as an 180-byte stream
  wordhits : # of V-points where a 4-byte window of the output equals the
             corresponding 4-byte window of d4/d0/d2 (positional)
  anyhit   : # of V-points where SOME 4-byte window of the first 512 output
             bytes equals SOME 4-byte window of the region (position-free;
             reported as a weak upper bound only)
"""
import hashlib
import hmac
import itertools
import struct
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fit_table as F

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


# ------------------------------------------------------------------ PRNGs
def splitmix64_stream(seed, n):
    s = seed & M64
    out = bytearray()
    for _ in range(n):
        s = (s + 0x9E3779B97F4A7C15) & M64
        z = s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        out += struct.pack(">Q", z ^ (z >> 31))
    return bytes(out)


def xorshift64star(seed, n):
    s = seed & M64 or 1
    out = bytearray()
    for _ in range(n):
        s ^= (s >> 12); s &= M64
        s ^= (s << 25) & M64
        s ^= (s >> 27)
        out += struct.pack(">Q", (s * 0x2545F4914F6CDD1D) & M64)
    return bytes(out)


def xorshift64(seed, n):
    s = seed & M64 or 1
    out = bytearray()
    for _ in range(n):
        s ^= (s << 13) & M64
        s ^= (s >> 7)
        s ^= (s << 17) & M64
        out += struct.pack(">Q", s)
    return bytes(out)


def xoshiro256ss(seed, n):
    s = seed & M64 or 1
    st = [s]
    for i in range(1, 4):
        st.append((splitmix64_stream(s + i, 8) and 0) or ((s * (i + 0x9E3779B97F4A7C15)) & M64))
    out = bytearray()

    def rot(x, k):
        return ((x << k) | (x >> (64 - k))) & M64
    for _ in range(n):
        r = (rot((st[1] * 5) & M64, 7) * 9) & M64
        t = (st[1] << 17) & M64
        st[2] ^= st[0]; st[3] ^= st[1]; st[1] ^= st[2]; st[0] ^= st[3]
        st[2] ^= t
        st[3] = rot(st[3], 45)
        out += struct.pack(">Q", r)
    return bytes(out)


def pcg32_stream(seed, n):
    state = 0
    inc = 0x14057B7EF767814F
    out = bytearray()
    for _ in range(n):
        old = state
        state = (old * 6364136223846793005 + inc) & M64
        xorshifted = (((old >> 18) ^ old) >> 27) & M32
        rot = (old >> 59) & 31
        out += struct.pack("<I", ((xorshifted >> rot) | (xorshifted << ((-rot) & 31))) & M32)
    return bytes(out)


def lcg_rand3(seed, n, a=1103515245, c=12345, shift=16):
    """bionic random(): state = state*a+c; return state >> 1 (int).
    Emulate a draw of a 32-bit word either from the raw state or the shifted
    return value, both endiannesses."""
    s = seed & M32
    vals = []
    for _ in range(n):
        s = (s * a + c) & M32
        vals.append(s)
    for name, pick in (("hi16", lambda v: v >> 16),
                       ("sh1", lambda v: (v >> 1) & M32),
                       ("raw", lambda v: v)):
        out = b"".join(struct.pack(">I", pick(v) & M32) for v in vals)
        yield name, out
    out = b"".join(struct.pack("<I", v) for v in vals)
    yield "le", out


def rc4_stream(key, n):
    if not key:
        key = b"\0"
    S = list(range(256))
    j = 0
    kl = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % kl]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def _sha(v, n):
    h = hashlib.sha256(v).digest()
    out = h
    while len(out) < n:
        out += hashlib.sha256(out).digest()
    return out[:n]


def _sha1(v, n):
    h = hashlib.sha1(v).digest()
    out = h
    while len(out) < n:
        out += hashlib.sha1(out).digest()
    return out[:n]


def _md5(v, n):
    h = hashlib.md5(v).digest()
    out = h
    while len(out) < n:
        out += hashlib.md5(out).digest()
    return out[:n]


def _keystream_aes_ctr(key, iv, n):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:
        try:
            from Crypto.Cipher import AES  # noqa
        except Exception:
            return None
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(b"\0" * n)


def _keystream_chacha(key, nonce, n):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:
        return None
    if len(key) != 32:
        return None
    c = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
    return c.update(b"\0" * n)


# ------------------------------------------------------------- seed builders
def seeds(V, pid, tid):
    """candidate 32/64-bit seeds mixing V with pid/tid in various ways"""
    yield "V", V & M32
    yield "V^pid^tid", (V ^ pid ^ tid) & M32
    yield "V+pid+tid", (V + pid + tid) & M32
    yield "V-pid-tid", (V - pid - tid) & M32
    yield "V*pid+tid", (V * pid + tid) & M32
    yield "V^pid", (V ^ pid) & M32
    yield "V^tid", (V ^ tid) & M32
    yield "V,pid64", (V << 32 | (pid << 16 | tid)) & M64
    yield "V,pid64^", ((V << 32) ^ pid ^ tid) & M64
    yield "pidtid^V64", ((pid << 32 | tid << 16 | V)) & M64
    yield "V*(pid^tid)", (V * (pid ^ tid)) & M32
    yield "(V^pid)*tid", ((V ^ pid) * tid) & M32
    yield "V+0x9e37", (V + 0x9E3779B9) & M32
    yield "V^0xa5a5", (V ^ 0xA5A5A5A5) & M32
    yield "V*0x45d9", (V * 0x45D9F3B) & M32
    yield "V^(V>>16)", (V ^ (V >> 16)) & M32
    yield "bswap(V)", struct.unpack(">I", struct.pack("<I", V & M32))[0]


def venc(V, pid, tid):
    return (struct.pack(">I", V & M32) + struct.pack(">I", pid & M32) +
            struct.pack(">I", tid & M32))


# ------------------------------------------------------------------ scoring
def region_stream(r):
    """canonical 180-byte stream: d0||d2||d4 (era-1 phase not normalised --
    d2/d4 are era-invariant, d0 is compared verbatim)."""
    return r["d0"] + r["d2"] + r["d4"]


def score_family(name, gen, rows, verbose=False):
    """gen(V,pid,tid) -> bytes (>= 180) or None"""
    exact_d4 = exact_all = 0
    wordhit = 0
    anyhit = 0
    n = 0
    for r in rows:
        n += 1
        try:
            out = gen(r["V"], r["pid"], r["tid"])
        except Exception:
            return None
        if not out or len(out) < 180:
            return None
        reg = region_stream(r)
        if out[:32] == r["d4"]:
            exact_d4 += 1
        if out[:180] == reg:
            exact_all += 1
        # positional 4-byte windows
        hw = 0
        for off in range(0, 180, 4):
            w = out[off:off + 4]
            if w in (r["d0"][off:off + 4] if off < 144 else
                     r["d2"] if off == 144 else r["d4"][off - 148:off - 144]):
                hw += 1
        if hw:
            wordhit += 1
        # position-free (weak)
        ow = set(out[i:i + 4] for i in range(0, min(len(out), 512), 4))
        rw = set(reg[i:i + 4] for i in range(0, 180, 4))
        if ow & rw:
            anyhit += 1
    return dict(name=name, n=n, exact_d4=exact_d4, exact_all=exact_all,
                wordhit=wordhit, anyhit=anyhit)


FAMILIES = []


def fam(name):
    def deco(fn):
        FAMILIES.append((name, fn))
        return fn
    return deco


@fam("splitmix64(seed)")
def _(V, p, t):
    for sn, s in seeds(V, p, t):
        out = splitmix64_stream(s, 256)
        if out[:32] == TARGET_D4[0] or out[:180] == TARGET_ALL[0]:
            return out
    return b"\0" * 180


def _one_stream(name, streamfn, nbytes=256):
    def g(V, p, t):
        best = None
        for sn, s in seeds(V, p, t):
            try:
                out = streamfn(s, nbytes)
            except Exception:
                continue
            if out is None:
                continue
            yield_ = out
            return out   # placeholder, replaced by multi-seed scoring
        return None
    return g


# We need multi-seed evaluation: restructure to let each family yield a dict
# of {seedname: bytes} so we can attribute hits.
def build_cases(rows):
    return [(r["V"], r["pid"], r["tid"], r) for r in rows]


def run_all(rows):
    results = []
    targets = {r["tag"]: (r["d4"], region_stream(r)) for r in rows}

    def try_all(name, gen):
        ed = ea = wh = ah = 0
        for r in rows:
            out = gen(r["V"], r["pid"], r["tid"])
            if out is None or len(out) < 180:
                return
            reg = region_stream(r)
            if out[:32] == r["d4"]:
                ed += 1
            if out[:180] == reg:
                ea += 1
            hw = 0
            for off in range(0, 180, 4):
                seg = r["d0"][off:off + 4] if off < 144 else (
                    r["d2"] if off == 144 else r["d4"][off - 148:off - 144])
                if out[off:off + 4] == seg:
                    hw += 1
            if hw:
                wh += 1
            ow = set(out[i:i + 4] for i in range(0, 512, 4))
            rw = set(reg[i:i + 4] for i in range(0, 180, 4))
            if ow & rw:
                ah += 1
        results.append((name, len(rows), ed, ea, wh, ah))

    # 1. splitmix64 for every seed
    for sn, _ in seeds(0, 1, 2):
        try_all("splitmix64[%s]" % sn,
                lambda V, p, t, sn=sn: splitmix64_stream(dict(seeds(V, p, t))[sn], 512))
    # 2. xorshift64* / xorshift64
    for sn, _ in seeds(0, 1, 2):
        try_all("xorshift64*[%s]" % sn,
                lambda V, p, t, sn=sn: xorshift64star(dict(seeds(V, p, t))[sn], 512))
        try_all("xorshift64[%s]" % sn,
                lambda V, p, t, sn=sn: xorshift64(dict(seeds(V, p, t))[sn], 512))
    # 3. xoshiro256**
    for sn, _ in seeds(0, 1, 2):
        try_all("xoshiro256ss[%s]" % sn,
                lambda V, p, t, sn=sn: xoshiro256ss(dict(seeds(V, p, t))[sn], 512))
    # 4. pcg32
    for sn, _ in seeds(0, 1, 2):
        try_all("pcg32[%s]" % sn,
                lambda V, p, t, sn=sn: pcg32_stream(dict(seeds(V, p, t))[sn], 512))
    # 5. bionic random()/rand() TYPE_3
    for sn, _ in seeds(0, 1, 2):
        for mode in ("hi16", "sh1", "raw", "le"):
            try_all("bionic_random3[%s,%s]" % (sn, mode),
                    lambda V, p, t, sn=sn, mode=mode: dict(
                        (m, o) for m, o in lcg_rand3(dict(seeds(V, p, t))[sn], 128)
                    ).get(mode))
    # 6. RC4 keyed by various byte encodings
    keymakers = {
        "Vbe4": lambda V, p, t: struct.pack(">I", V & M32),
        "Vle4": lambda V, p, t: struct.pack("<I", V & M32),
        "Vbe4p": lambda V, p, t: struct.pack(">III", V & M32, p & M32, t & M32),
        "Vle4p": lambda V, p, t: struct.pack("<III", V & M32, p & M32, t & M32),
        "Vp^t": lambda V, p, t: struct.pack(">I", (V ^ p ^ t) & M32),
        "Vp^tpad16": lambda V, p, t: struct.pack(">I", (V ^ p ^ t) & M32) + b"\0" * 12,
        "empty": lambda V, p, t: b"",
        "Vp^tstr": lambda V, p, t: b"adj9" + struct.pack(">III", V & M32, p & M32, t & M32),
    }
    for kn, km in keymakers.items():
        try_all("rc4[%s]" % kn, lambda V, p, t, km=km: rc4_stream(km(V, p, t), 512))
    # 7. SHA-256 / SHA-1 / MD5 expansions
    for sn, _ in seeds(0, 1, 2):
        try_all("sha256exp[%s]" % sn,
                lambda V, p, t, sn=sn: _sha(struct.pack(">I", dict(seeds(V, p, t))[sn] & M32), 512))
        try_all("sha256exp64[%s]" % sn,
                lambda V, p, t, sn=sn: _sha(struct.pack(">Q", dict(seeds(V, p, t))[sn] & M64), 512))
    try_all("sha256(Vbe4|p|t)", lambda V, p, t: _sha(venc(V, p, t), 512))
    try_all("sha256(Vbe4)", lambda V, p, t: _sha(struct.pack(">I", V & M32), 512))
    try_all("sha1(Vbe4)", lambda V, p, t: _sha1(struct.pack(">I", V & M32), 512))
    try_all("md5(Vbe4)", lambda V, p, t: _md5(struct.pack(">I", V & M32), 512))
    for key, msg in (("V", lambda V, p, t: b""),
                     ("Vp", lambda V, p, t: struct.pack(">I", p & M32)),
                     ("Vp|t", lambda V, p, t: struct.pack(">II", p & M32, t & M32))):
        def mkh(key, msg):
            def g(V, p, t):
                if key == "V":
                    kb = struct.pack(">I", V & M32)
                elif key == "Vp":
                    kb = struct.pack(">I", p & M32)
                else:
                    kb = struct.pack(">II", p & M32, t & M32)
                return _hmac_stream(kb, msg(V, p, t), 512)
            return g
        try_all("hmac_sha256(key=%s,msg=%s)" % (key, msg), mkh(key, msg))
    # 8. AES-CTR / ChaCha
    for kn, km in (("Vbe4pad", lambda V, p, t: struct.pack(">I", V & M32) + b"\0" * 12),
                   ("Vp^tpad", lambda V, p, t: struct.pack(">I", (V ^ p ^ t) & M32) + b"\0" * 12),
                   ("Vp^t_ivV", lambda V, p, t: (struct.pack(">I", (V ^ p ^ t) & M32) + b"\0" * 12,
                                                  struct.pack(">I", V & M32) + b"\0" * 12))):
        def mk(km):
            def g(V, p, t):
                r = km(V, p, t)
                if isinstance(r, tuple):
                    return _keystream_aes_ctr(r[0], r[1], 512)
                return _keystream_aes_ctr(r, b"\0" * 16, 512)
            return g
        try_all("aes128ctr[%s]" % kn, mk(km))
    for kn, km in (("Vbe4x4", lambda V, p, t: struct.pack(">IIII", V & M32, (V ^ p ^ t) & M32, p & M32, t & M32)),
                   ("Vp^t_x2", lambda V, p, t: struct.pack(">II", (V ^ p ^ t) & M32, (V ^ p ^ t) & M32) + b"\0" * 16),
                   ("Vp^t_x4", lambda V, p, t: struct.pack(">IIII", (V ^ p ^ t) & M32, (V ^ p ^ t) & M32, p & M32, t & M32))):
        def mkc(km):
            def g(V, p, t):
                k = km(V, p, t)
                try:
                    return _keystream_chacha(k, b"\0" * 16, 512)
                except Exception:
                    return None
            return g
        try_all("chacha20[%s]" % kn, mkc(km))
    return results


def _hmac_stream(key, msg, n):
    out = b""
    ctr = b"\0" * 4
    while len(out) < n:
        out += hmac.new(key, msg + ctr, hashlib.sha256).digest()
        ctr = (int.from_bytes(ctr, "big") + 1).to_bytes(4, "big")
    return out[:n]


if __name__ == "__main__":
    rows = F.dedup(F.load_all())
    # use era-2 rows only for the primary score (largest consistent set)
    era2 = [r for r in rows if r["era"] == 2]
    print("scoring on %d era-2 unique rows" % len(era2))
    res = run_all(era2)
    res.sort(key=lambda x: (-x[2], -x[3], -x[4], -x[5]))
    print("%-34s %4s %6s %6s %6s %6s" % ("family", "N", "d4", "all", "whit", "any"))
    for name, n, ed, ea, wh, ah in res:
        print("%-34s %4d %6d %6d %6d %6d" % (name, n, ed, ea, wh, ah))
