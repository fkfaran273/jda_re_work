#!/usr/bin/env python3
"""_sub_alg_seedx.py — attack 5: counter/mixed seed test (targeted sets that
the earlier seed sweeps did NOT cover). Generators: bionic Random3 (the
verified Android generator, warm-up 310 fixed) and lrand48/srand48 (X=48-bit
LCG a=0x5DEECE66D c=0xB, output X>>17, warm-ups swept for the small sets,
{0,10} for the big XOR sweep). Draw->word layouts: direct (w_i = d_i) and
pair-XOR (w_i = d_{2i} ^ d_{2i+1}, the Android layout).

Seed families tested per candidate signing second s:
  small:  s, 2*s, s*1000>>k (k 0..10), s>>k (k 0..10), s+c (c -64..64),
          int(cc*1000), int(cb*1000), int(cc), int(cb)
  xor:    s ^ c, c in 0..65535
A hit must reproduce ALL FOUR words of the owning header (exact match).
Writes _sub_alg_seedx_out.json; prints every hit with exact parameters.
"""
import json, os, time

HERE = os.path.dirname(os.path.abspath(__file__))
H = json.load(open(os.path.join(HERE, "_sub_alg_headers.json")))
HEADERS = H["headers"]

# ---------- generators ----------
_MINSTD_M = (1 << 31) - 1
_MINSTD_A = 7 ** 5
_MINSTD_Q = _MINSTD_M // _MINSTD_A
_MINSTD_R = _MINSTD_M % _MINSTD_A
_MASK32 = (1 << 32) - 1

def rand3_draws(seed, n=8):
    """bionic rand(): 31-word additive LCG, 310-draw warm-up, output >>1."""
    r = [0] * 31
    s = seed & _MASK32
    if s == 0:
        s = 1
    w = s if s < 2 ** 31 else s - 2 ** 32
    r[0] = w
    prev = w
    for i in range(1, 31):
        if prev >= 0:
            hi = prev // _MINSTD_Q
            lo = prev - hi * _MINSTD_Q
        else:
            hi = -((-prev) // _MINSTD_Q)
            lo = prev - hi * _MINSTD_Q
        word = _MINSTD_A * lo - _MINSTD_R * hi
        if word < 0:
            word += _MINSTD_M
        prev = word
        r[i] = word
    f, b = 3, 0
    out = []
    for _ in range(310 + n):
        v = (r[f] + r[b]) & _MASK32
        r[f] = v if v < 2 ** 31 else v - 2 ** 32
        f = (f + 1) % 31
        b = (b + 1) % 31
        out.append(v >> 1)
    return out[310:]

_L48_A = 0x5DEECE66D
_L48_C = 0xB
_L48_M = (1 << 48) - 1

def lrand48_draws(seed, n=8, warmup=0):
    x = ((seed & 0xFFFFFFFFFFFF) << 16) | 0x330E
    for _ in range(warmup):
        x = (_L48_A * x + _L48_C) & _L48_M
    out = []
    for _ in range(n):
        x = (_L48_A * x + _L48_C) & _L48_M
        out.append(x >> 17)
    return out

def check(d, hdr_words):
    """d = >=8 draws; test direct and pair-XOR layouts vs the 4 words."""
    if d[0] == hdr_words[0] and d[1] == hdr_words[1] and \
       d[2] == hdr_words[2] and d[3] == hdr_words[3]:
        return "direct"
    for i in range(4):
        if (d[2 * i] ^ d[2 * i + 1]) != hdr_words[i]:
            return None
    return "pair_xor"

# ---------- header/second map ----------
sec2hdr = {}
for hi, u in enumerate(HEADERS):
    for s in u["sec_candidates"]:
        sec2hdr.setdefault(s, []).append(hi)
print(f"distinct candidate seconds: {len(sec2hdr)}")

hits = []

def try_seed(seed, sec, gen, tag):
    for hi in sec2hdr.get(sec, []):
        w = HEADERS[hi]["w"]
        if gen == "rand3":
            d = rand3_draws(seed, 8)
        else:
            d = lrand48_draws(seed, 8, WARM)
        lay = check(d, w)
        if lay:
            hits.append({"gen": gen, "tag": tag, "seed": seed, "seed_hex": hex(seed),
                         "second": sec, "header_idx": hi, "layout": lay,
                         "header": HEADERS[hi]["header16_hex"],
                         "draws8": d})
            print(f"*** HIT gen={gen} tag={tag} seed={seed} ({hex(seed)}) "
                  f"second={sec} hdr={hi} layout={lay}")

# ---------- small transform families ----------
t0 = time.time()
small_secs = sorted(sec2hdr)
reqs = H["requests"]
sec_cc = {}
for r in reqs:
    for s in r["sec_candidates"]:
        sec_cc.setdefault(s, (r["cc"], r["cb"]))
for gen in ("rand3", "lrand48"):
    for sec in small_secs:
        cc, cb = sec_cc[sec]
        seeds = ([sec, 2 * sec]
                 + [sec * 1000 >> k for k in range(11)]
                 + [sec >> k for k in range(11)]
                 + [sec + c for c in range(-64, 65)]
                 + [int(cc * 1000), int(cb * 1000), int(cc), int(cb)])
        for seed in seeds:
            if gen == "rand3":
                try_seed(seed, sec, gen, "small")
            else:
                for WARM in range(0, 65):
                    try_seed(seed, sec, gen, f"small_w{WARM}")
    print(f"[{gen}] small families done ({time.time()-t0:.1f}s), hits so far: {len(hits)}")

# ---------- XOR sweep ----------
for gen in ("lrand48", "rand3"):
    t1 = time.time()
    for sec in small_secs:
        for c in range(65536):
            seed = sec ^ c
            if gen == "rand3":
                try_seed(seed, sec, gen, "xor")
            else:
                for WARM in (0, 10):
                    try_seed(seed, sec, gen, f"xor_w{WARM}")
    print(f"[{gen}] XOR sweep done ({time.time()-t1:.1f}s), hits so far: {len(hits)}")

json.dump(hits, open(os.path.join(HERE, "_sub_alg_seedx_out.json"), "w"), indent=1)
print(f"\nTOTAL HITS: {len(hits)}")
if not hits:
    print("All counter/mixed seed families RULED OUT for both generators, both layouts.")
print("wrote _sub_alg_seedx_out.json")
