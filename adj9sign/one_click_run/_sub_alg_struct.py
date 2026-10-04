#!/usr/bin/env python3
"""_sub_alg_struct.py — attack 6: structural insights without a generator model.

  1) bit/byte statistics: per-bit-position bias across the 112 words, per-byte
     high-bit law, ASCII-likeness.
  2) within-header arithmetic: constant differences/ratios of consecutive
     words, sums, carries; simple f(w0,w1)->w2 style equalities.
  3) w3-as-checksum of w0..w2: sum32, xor, crc32, FNV-1/1a-32, adler32, and
     31-bit masked variants, over the 12 bytes (BE and LE int packing).
  4) cross-header: repeated words, Pearson correlation between word slots,
     correlation of words with the signing second, hamming distance of
     consecutive-second headers vs uniform expectation.
  5) same-second requests: header identity vs body (byte 16+) variation.
Writes _sub_alg_struct_out.json.
"""
import json, os, zlib, itertools, base64
from math import sqrt

HERE = os.path.dirname(os.path.abspath(__file__))
H = json.load(open(os.path.join(HERE, "_sub_alg_headers.json")))
HEADERS = H["headers"]
REQS = H["requests"]
out = {}

# ---------- 1) bit/byte statistics ----------
words = [u["w"] for u in HEADERS]          # 28 x 4
flat = [w for ws in words for w in ws]     # 112
ones_per_bit = []
for b in range(31):
    c = sum((w >> b) & 1 for w in flat)
    ones_per_bit.append(c)
# binomial(112, .5): mean 56, sd sqrt(112)/2 = 5.29
sd = sqrt(112) / 2
biased = [(b, c, (c - 56) / sd) for b, c in enumerate(ones_per_bit)
          if abs(c - 56) / sd > 2.5]
out["ones_per_bit"] = ones_per_bit
out["strongly_biased_bits_gt2.5sigma"] = biased
print("1) per-bit ones-count across 112 words (mean 56, sd 5.29):")
print("   extremes:", biased if biased else "none beyond 2.5 sigma")
lead_hi = [int.from_bytes(bytes.fromhex(u["header16_hex"])[i:i+1], "big") >> 7
           for u in HEADERS for i in (0, 4, 8, 12)]     # word-leading bytes
trail_hi = [int.from_bytes(bytes.fromhex(u["header16_hex"])[i:i+1], "big") >> 7
            for u in HEADERS for i in range(16) if i % 4 != 0]
out["byte_high_bit"] = {"leading_set": sum(lead_hi), "leading_total": len(lead_hi),
                        "trailing_set": sum(trail_hi), "trailing_total": len(trail_hi)}
print(f"   byte high-bit: word-leading {sum(lead_hi)}/{len(lead_hi)} "
      f"(0 required by 31-bit law), trailing {sum(trail_hi)}/{len(trail_hi)} "
      f"({sum(trail_hi)/len(trail_hi):.1%}, uniform expectation 50%)")
ascii_like = sum(1 for u in HEADERS for by in bytes.fromhex(u["header16_hex"])
                 if 0x30 <= by <= 0x39 or 0x61 <= by <= 0x66)
out["ascii_hexdigit_bytes"] = ascii_like
print(f"   bytes that are hex-digit ASCII: {ascii_like}/448")

# ---------- 2) within-header arithmetic ----------
print("\n2) within-header arithmetic (28 headers)")
const_diff = {}
for m in (1 << 31, 1 << 32):
    diffs = set()
    ok = True
    for ws in words:
        d = tuple((ws[i + 1] - ws[i]) % m for i in range(3))
        if len(set(d)) != 1:
            ok = False
            break
        diffs.add(d[0])
    print(f"   consecutive-word difference constant within every header "
          f"(mod 2^{31 if m == 2**31 else 32}): {ok}")
# ratio test was done algebraically in _sub_alg_lcg.py (0/28) — no need here
sums = {}
for ws in words:
    s = sum(ws)
    sums.setdefault(s & 0xFFFFFFFF, 0)
    sums[s & 0xFFFFFFFF] += 1
out["sum32_value_counts_top"] = sorted(sums.items(), key=lambda kv: -kv[1])[:3]
print(f"   w0+w1+w2+w3 mod 2^32: {len(sums)} distinct values across 28 headers "
      f"(4 would hint a checksum; {len(sums)} = unconstrained)")
# simple equalities
eq_counts = {"w2==w0+w1": 0, "w2==w0^w1": 0, "w2==w0-w1": 0, "w3==w0^w1^w2": 0,
             "w3==w0+w1+w2": 0, "w1==w0+w2": 0}
for ws in words:
    M = 1 << 32
    if (ws[0] + ws[1]) & 0x7FFFFFFF == ws[2] % (1 << 31): eq_counts["w2==w0+w1"] += 1
    if (ws[0] ^ ws[1]) == ws[2]: eq_counts["w2==w0^w1"] += 1
    if (ws[0] - ws[1]) % (1 << 31) == ws[2]: eq_counts["w2==w0-w1"] += 1
    if (ws[0] ^ ws[1] ^ ws[2]) == ws[3]: eq_counts["w3==w0^w1^w2"] += 1
    if (ws[0] + ws[1] + ws[2]) & 0x7FFFFFFF == ws[3]: eq_counts["w3==w0+w1+w2"] += 1
    if (ws[0] + ws[2]) & 0x7FFFFFFF == ws[1]: eq_counts["w1==w0+w2"] += 1
out["simple_equalities"] = eq_counts
print(f"   simple equalities (out of 28): {eq_counts}")

# ---------- 3) w3 as checksum of w0..w2 ----------
print("\n3) w3-as-checksum tests (matches out of 28)")

def fnv1a32(bs):
    h = 0x811C9DC5
    for by in bs:
        h ^= by
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h

def fnv1_32(bs):
    h = 0x811C9DC5
    for by in bs:
        h = (h * 0x01000193) & 0xFFFFFFFF
        h ^= by
    return h

CK = {}
def ck_register(name, fn):
    CK[name] = fn

ck_register("sum32_be12", lambda b12: sum(b12) & 0xFFFFFFFF)
ck_register("xor12", lambda b12: __import__("functools").reduce(lambda a, b: a ^ b, b12, 0))
ck_register("crc32_be", lambda b12: zlib.crc32(b12) & 0xFFFFFFFF)
ck_register("adler32_be", lambda b12: zlib.adler32(b12) & 0xFFFFFFFF)
ck_register("fnv1a_be", fnv1a32)
ck_register("fnv1_be", fnv1_32)
ck_register("xor_w012", lambda b12, ws=None: ws[0] ^ ws[1] ^ ws[2])
ck_register("sum_w012", lambda b12, ws=None: (ws[0] + ws[1] + ws[2]) & 0xFFFFFFFF)
# LE-packed 12 bytes
import struct
ck_register("crc32_le", lambda b12, ws=None: zlib.crc32(struct.pack("<III", *ws[:3])) & 0xFFFFFFFF)
ck_register("fnv1a_le", lambda b12, ws=None: fnv1a32(struct.pack("<III", *ws[:3])))
ck_register("sum32_le", lambda b12, ws=None: sum(struct.pack("<III", *ws[:3])) & 0xFFFFFFFF)

res = {k: 0 for k in CK}
for u in HEADERS:
    ws = u["w"]
    b12 = bytes.fromhex(u["header16_hex"])[:12]
    for name, fn in CK.items():
        try:
            v = fn(b12) if "ws" not in fn.__code__.co_varnames else fn(b12, ws)
        except TypeError:
            v = fn(b12, ws)
        for target, mask in (("w3", 0xFFFFFFFF), ("w3&31bit", 0x7FFFFFFF)):
            if (v & mask) == (ws[3] & mask):
                res[name + "@" + target] = res.get(name + "@" + target, 0) + 1
out["checksum_matches"] = {k: v for k, v in res.items()}
print("   " + ", ".join(f"{k}={v}" for k, v in sorted(res.items())))

# ---------- 4) cross-header ----------
print("\n4) cross-header structure")
allws = [(w, hi, k) for hi, u in enumerate(HEADERS) for k, w in enumerate(u["w"])]
seen = {}
rep = 0
for w, hi, k in allws:
    if w in seen:
        print(f"   repeated word {w:#010x}: hdr{seen[w]} and hdr{hi} pos{k}")
        rep += 1
    seen[w] = (hi, k)
print(f"   repeated words across headers: {rep}")

def pearson(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sx = sqrt(sum((x - mx) ** 2 for x in xs))
    sy = sqrt(sum((y - my) ** 2 for y in ys))
    if sx == 0 or sy == 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)

sec0 = [u["sec_candidates"][0] for u in HEADERS]   # best-guess second
cors = {}
for k in range(4):
    ws_k = [u["w"][k] for u in HEADERS]
    cors[f"w{k}~second"] = round(pearson(ws_k, sec0), 3)
    for l in range(4):
        if l > k:
            cors[f"w{k}~w{l}"] = round(pearson(ws_k, [u["w"][l] for u in HEADERS]), 3)
    cors[f"w{k}~second_low16"] = round(pearson([w & 0xFFFF for w in ws_k],
                                               [s & 0xFFFF for s in sec0]), 3)
out["correlations"] = cors
big = {k: v for k, v in cors.items() if abs(v) > 0.45}
print(f"   Pearson correlations (n=28, |r|>0.45 significant at ~2 sigma): {big or 'none'}")

# consecutive-second header deltas / hamming
order = sorted(range(len(HEADERS)), key=lambda i: HEADERS[i]["sec_min"])
hd = []
for a, b in zip(order, order[1:]):
    wa = int.from_bytes(bytes.fromhex(HEADERS[a]["header16_hex"]), "big")
    wb = int.from_bytes(bytes.fromhex(HEADERS[b]["header16_hex"]), "big")
    hd.append(bin(wa ^ wb).count("1"))
exp = 128 / 2
out["consec_second_hamming_mean"] = round(sum(hd) / len(hd), 2)
out["consec_second_hamming_expected_uniform"] = exp
print(f"   consecutive-header hamming distance: mean {out['consec_second_hamming_mean']} "
      f"over 128 bits (uniform expectation {exp}); min {min(hd)} max {max(hd)}")

# word-delta closeness for consecutive seconds
mind = []
for a, b in zip(order, order[1:]):
    for k in range(4):
        d = (HEADERS[b]["w"][k] - HEADERS[a]["w"][k]) & 0x7FFFFFFF
        mind.append(min(d, (1 << 31) - d))
out["consec_second_word_delta_min_overall"] = min(mind)
print(f"   smallest |word delta| between consecutive-second headers: {min(mind):,} "
      f"(uniform min over 27*4 deltas ~ {2**31//108:,})")

# ---------- 5) same-second requests ----------
print("\n5) same-second requests: header vs body")
groups = {}
for r in REQS:
    groups.setdefault(r["header16_hex"], []).append(r)
for h, rs in groups.items():
    if len(rs) > 1:
        sigs = [base64.b64decode(r_file := x["file"] or "") or None for x in rs]
        # re-decode signatures properly
        import json as _j
        d = _j.load(open(os.path.join(HERE, "_sub_ios_timing.json")))
        sigs = [base64.b64decode(q["authorization"]["signature_b64"])
                for q in d["requests"] if q["sid"] in [x["sid"] for x in rs]]
        same = all(s[:16] == sigs[0][:16] for s in sigs)
        body_same = all(s[16:] == sigs[0][16:] for s in sigs)
        sids = [x["sid"] for x in rs]
        print(f"   sids {sids}: header16 identical={same}, bytes16..191 identical={body_same}")

json.dump(out, open(os.path.join(HERE, "_sub_alg_struct_out.json"), "w"), indent=1)
print("\nwrote _sub_alg_struct_out.json")
