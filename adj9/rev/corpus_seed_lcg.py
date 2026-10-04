"""corpus_seed_lcg.py — empirical lrand48 sweep on the signing corpora.

New ground truth under test: the wire/region words come from the C rand()
stream — bionic srand(time(NULL)) per resume (srand->srand48, rand->lrand48,
31-bit outputs), consumed by the wire builder (0x12a2fc/0x12a31c) with a
per-site mixing transform.

lrand48 (POSIX/bionic):
    srand48(s):  X = (s << 16) + 0x330E           (mod 2^48)
    step:        X = (0x5DEECE66D * X + 0xB) mod 2^48
    output:      r = X >> 17   (31-bit)

Swept mixes (r = draw k, r2 = draw k+1), all masked to 32 bits:
    m1  r
    m2  (r >> 15) | (r2 << 16)          (+ swapped-operand variant)
    m3  r ^ C
    m4  (r * C) >> 32
    m5  C - r
    m6  r * C mod 2^32
    m7  r ^ r2                          (bonus)
    m8  (r & 0xFFFF) | ((r2 & 0xFFFF) << 16)   (bonus)

C = mov/movk constants from rev/fn_9afa4_full.log (low and high 32 bits).

Corpora:
  region  rev/pair_h3.json — 8 rows, each with VERIFIED signing second
          (Random3 header law, re-verified here), the 192-B wire blob, H,
          and region words d0/d2/d4  -> words W0, X, U[0..3], d2, d4[0..7].
  fresh   device/java_dump/signings_extract.json — 3 signings, seconds
          1790106110/176/196; only WIRE words available (48 dwords per blob).

Seeds: resume second candidates = signing second -3..+1 (per row / per log
first row / fresh first signing -3..+1), k < 50000.

Usage: python corpus_seed_lcg.py
"""
import importlib.util
import json
import re
import sys
from collections import defaultdict

import numpy as np

BASE = "C:/Users/Apps/Downloads/com.penti.app/adj9"
REV = BASE + "/rev"
JD = BASE + "/device/java_dump"

spec = importlib.util.spec_from_file_location("header_gen", REV + "/header_gen.py")
hg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hg)

KMAX = 50000
A48 = 0x5DEECE66D
C48 = 0xB
M48 = (1 << 48) - 1

out_lines = []


def P(*a):
    s = " ".join(str(x) for x in a)
    out_lines.append(s)
    print(s)


def h32(v):
    return "%08x" % (v & 0xFFFFFFFF)


# ------------------------------------------------ lrand48
def lrand48_stream(seed, n=KMAX):
    X = (((seed & 0xFFFFFFFF) << 16) + 0x330E) & M48
    out = np.empty(n, dtype=np.uint32)
    for i in range(n):
        X = (A48 * X + C48) & M48
        out[i] = X >> 17
    return out


# ------------------------------------------------ C constants from fn log
def extract_constants(path):
    chain_reg = None
    chain_val = 0
    freq = defaultdict(int)

    def close():
        nonlocal chain_reg, chain_val
        if chain_reg is not None:
            freq[chain_val] += 1
        chain_reg = None
        chain_val = 0

    for ln in open(path, encoding="utf-8", errors="replace"):
        mm = re.match(r"^0x[0-9a-f]+\s+(movk?)\s+([wx]\d+|xzr|wzr),\s*#(0x[0-9a-f]+)(?:,\s*lsl\s*#(\d+))?", ln)
        if not mm:
            close()
            continue
        op, reg, imm, lsl = mm.group(1), mm.group(2), int(mm.group(3), 16), int(mm.group(4) or 0)
        if reg.startswith("w"):
            reg = "x" + reg[1:]
        if op == "mov":
            if chain_reg != reg:
                close()
            chain_reg = reg
            chain_val = imm & 0xFFFFFFFF
        else:  # movk
            if chain_reg != reg:
                close()
                chain_reg = reg
                chain_val = 0
            chain_val |= (imm << lsl)
            chain_val &= (1 << 64) - 1
    close()

    # rank: full 64-bit chains (with lsl-48 bits or at least high bits) first,
    # then shorter prefixes; split each into low32/high32
    ranked = sorted(freq.items(), key=lambda kv: -kv[1])
    C_list = []
    seen = set()
    for v, cnt in ranked:
        if v < 2:
            continue
        for c in (v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF):
            if c >= 1 and c not in seen:
                seen.add(c)
                C_list.append((c, cnt, v))
    return ranked, C_list


# ------------------------------------------------ mixes
def mix_m1(r, r2, C):
    return r


def mix_m2(r, r2, C):
    return ((r >> 15) | (r2 << 16)) & np.uint32(0xFFFFFFFF)


def mix_m2s(r, r2, C):
    return ((r2 >> 15) | (r << 16)) & np.uint32(0xFFFFFFFF)


def mix_m3(r, r2, C):
    return (r ^ np.uint32(C)).astype(np.uint32)


def mix_m4(r, r2, C):
    return ((r.astype(np.uint64) * np.uint64(C)) >> np.uint64(32)).astype(np.uint32)


def mix_m5(r, r2, C):
    return ((np.uint64(C) - r.astype(np.uint64)) & np.uint64(0xFFFFFFFF)).astype(np.uint32)


def mix_m6(r, r2, C):
    return (r.astype(np.uint64) * np.uint64(C) & np.uint64(0xFFFFFFFF)).astype(np.uint32)


def mix_m7(r, r2, C):
    return (r ^ r2).astype(np.uint32)


def mix_m8(r, r2, C):
    return (((r & np.uint32(0xFFFF)) | ((r2 & np.uint32(0xFFFF)) << np.uint32(16)))).astype(np.uint32)


MIXES = [("m1:r", mix_m1), ("m2:(r>>15|r2<<16)", mix_m2), ("m2s:(r2>>15|r<<16)", mix_m2s),
         ("m3:r^C", mix_m3), ("m4:(r*C)>>32", mix_m4), ("m5:C-r", mix_m5),
         ("m6:r*C", mix_m6), ("m7:r^r2", mix_m7), ("m8:lo|hi", mix_m8)]

# ------------------------------------------------ load corpora
P("=" * 78)
P("0. LOAD")
P("=" * 78)
rows = json.load(open(REV + "/pair_h3.json", encoding="utf-8"))
fresh = json.load(open(JD + "/signings_extract.json", encoding="utf-8"))["signings"]

P("pair_h3 rows: %d ; header-law (Random3) re-verification of 'second':" % len(rows))
for r in rows:
    ok = hg.make_header(r["second"]) == bytes.fromhex(r["blob"])[:16]
    P("  i=%d second=%d blobhdr=%s... match=%s" % (r["i"], r["second"], r["blob"][:16], ok))
P("NOTE: pair_h3 seconds are the TRUE signing seconds; they differ from the")
P("created_at+1 estimate in corpus_seed.md for rows 0..6 (flush lag) — corrected here.")

# region words per row: W0, X, U[0..3], d2, d4[0..7]
region_words = []       # (row_label, log, [(name, value), ...])
for r in rows:
    d0 = [int(r["d0"][i:i + 8], 16) for i in range(0, 144, 8)]
    d2 = int(r["d2"], 16)
    d4 = [int(r["d4"][i:i + 8], 16) for i in range(0, 64, 8)]
    words = ([("W0", d0[0]), ("X", d0[1])] + [("U%d" % k, d0[2 + k]) for k in range(4)]
             + [("d2", d2)] + [("d4_%d" % k, d4[k]) for k in range(8)])
    region_words.append(("pair_i%d" % r["i"], r["log"], r["second"], words))

fresh_words = []
for r in fresh:
    b = bytes.fromhex(r["blob"])
    ws = [int.from_bytes(b[i:i + 4], "big") for i in range(0, 192, 4)]
    names = ["hdr%d" % k for k in range(4)] + ["body%d" % k for k in range(44)]
    fresh_words.append(("fresh%d" % r["n"], r["ts"] // 1000, list(zip(names, ws))))

# ------------------------------------------------ constants
P("")
P("=" * 78)
P("1. C CONSTANTS from fn_9afa4_full.log")
P("=" * 78)
ranked, C_list = extract_constants(REV + "/fn_9afa4_full.log")
P("distinct chain values: %d ; C candidates (low32/high32, deduped): %d" % (len(ranked), len(C_list)))
P("top 15 chain values: %s" % [(h32(v & 0xFFFFFFFFFFFFFFFF), c) for v, c in ranked[:15]])
Cs = [c for c, cnt, v in C_list]
P("C sweep set: %d values: %s%s" % (len(Cs), [h32(c) for c in Cs[:20]], " ..." if len(Cs) > 20 else ""))

# ------------------------------------------------ seeds
seeds = []              # (label, seed, applies_to)  applies_to: 'all' | log name | fresh
for lbl, log, sec, _ in region_words:
    for d in range(-3, 2):
        seeds.append((lbl, sec + d, log))
for d in range(-3, 2):
    seeds.append(("wh2-log-first", 1789239390 + d, "adj9_wh2.log"))
    seeds.append(("wh4-log-first", 1789240075 + d, "adj9_wh4.log"))
for d in range(-3, 2):
    seeds.append(("fresh-first", 1790106110 + d, "fresh"))
seen_seed = set()
seed_list = []
for lbl, s, ap in seeds:
    key = (s, ap)
    if key not in seen_seed:
        seen_seed.add(key)
        seed_list.append((lbl, s, ap))
P("")
P("seed candidates: %d (%s)" % (len(seed_list), sorted(set(s for _, s, _ in seed_list))[:12]))

# ------------------------------------------------ target tables
# region rows: tested against EVERY seed (log-scoped + all)  -> label per row
# fresh rows: tested against 'fresh' seeds only
def targets_with_le(words):
    tv = []
    for name, v in words:
        tv.append((name, v & 0xFFFFFFFF))
        tv.append((name + "/LE", int.from_bytes(int.to_bytes(v & 0xFFFFFFFF, 4, "big"), "little")))
    return tv


val2loc = defaultdict(list)     # value -> [(group, wordname)]
groups = {}                     # group -> (kind, log, [values])
for lbl, log, sec, words in region_words:
    tv = targets_with_le(words)
    groups[lbl] = ("region", log, [v for _, v in tv])
    for name, v in tv:
        val2loc[v].append((lbl, name))
for lbl, tssec, words in fresh_words:
    tv = targets_with_le(words)
    groups[lbl] = ("fresh", "fresh", [v for _, v in tv])
    for name, v in tv:
        val2loc[v].append((lbl, name))

all_targets = np.array(sorted(val2loc.keys()), dtype=np.uint32)
P("target values (incl LE variants): %d from %d groups" % (len(all_targets), len(groups)))

# ------------------------------------------------ sweep
P("")
P("=" * 78)
P("2. SWEEP (k < %d, all C, all mixes)" % KMAX)
P("=" * 78)
hits = []
seed_draw_cache = {}
for lbl, s, ap in seed_list:
    if s not in seed_draw_cache:
        seed_draw_cache[s] = lrand48_stream(s)
    draws = seed_draw_cache[s]
    r, r2 = draws[:-1], draws[1:]
    which = [g for g, (kind, glog, _) in groups.items()
             if ap == "all" or (kind == "region" and glog == ap) or (kind == "fresh" and ap == "fresh")]
    tvals = np.array(sorted({v for g in which for v in groups[g][2]}), dtype=np.uint32)
    for cname, fn in MIXES:
        for C in Cs:
            mixed = fn(r, r2, C)
            if cname.startswith("m2") or cname.startswith("m7") or cname.startswith("m8"):
                m = mixed
            else:
                m = mixed
            mask = np.isin(m, tvals)
            ks = np.nonzero(mask)[0]
            for k in ks:
                v = int(m[k])
                for (g, wname) in val2loc[v]:
                    if g in which:
                        hits.append((s, cname, C, g, wname, int(k)))
P("raw (seed,mix,C,group,word,k) hits: %d" % len(hits))
for hgt in hits[:80]:
    P("   seed=%d %-18s C=%s %-12s %-8s k=%d" % (hgt[0], hgt[1], h32(hgt[2]), hgt[3], hgt[4], hgt[5]))
if len(hits) > 80:
    P("   ... %d more" % (len(hits) - 80))

# ------------------------------------------------ g tests
P("")
P("=" * 78)
P("3. GAP TESTS (draws-per-signing g)")
P("=" * 78)

# 3a. region: within one log (same process), hits with same seed+C+mix should
#     appear at increasing k across signings
bylog = defaultdict(lambda: defaultdict(list))
for s, cname, C, g, wname, k in hits:
    kind, glog, _ = groups[g]
    if kind == "region":
        bylog[(s, cname, C, glog)][g].append(k)
P("-- region logs: same-seed hits across multiple rows with increasing k:")
found_log = False
for (s, cname, C, glog), perrow in sorted(bylog.items()):
    if len(perrow) >= 2:
        ks = {row: min(v) for row, v in perrow.items()}
        order = sorted(ks.items())
        ks_sorted = [k for _, k in order]
        if ks_sorted == sorted(ks_sorted) and len(set(ks_sorted)) == len(ks_sorted):
            found_log = True
            P("   seed=%d %s C=%s log=%s rows->k: %s" %
              (s, cname, h32(C), glog, [(row, k) for row, k in order]))
if not found_log:
    P("   none")

# 3b. fresh: arithmetic progression k, k+g, k+2g across the 3 signings
P("-- fresh 3: (seed, mix, C, k1, g) with signing1 word at k, signing2 at k+g, signing3 at k+2g:")
fsets = {}
for s, cname, C, g, wname, k in hits:
    if groups[g][0] == "fresh":
        fsets.setdefault((s, cname, C, g), set()).add((g, wname, k))
fresh_progressions = []
for (s, cname, C, gname), trip in fsets.items():
    per = defaultdict(set)
    for (gname2, wname, k) in trip:
        signum = int(gname2.replace("fresh", "").split("/")[0])
        per[signum].add(k)
    if len(per) < 3:
        continue
    for k1 in per[1]:
        for k2 in per[2]:
            gg = k2 - k1
            if 1 <= gg <= 2000 and (k2 + gg) in per[3]:
                fresh_progressions.append((s, cname, C, k1, gg, k2 + gg))
if fresh_progressions:
    for pr in fresh_progressions[:40]:
        P("   seed=%d %-18s C=%s k1=%d g=%d k3=k1+2g=%d" % (pr[0], pr[1], h32(pr[2]), pr[3], pr[4], pr[5]))
    P("   total progressions: %d" % len(fresh_progressions))
else:
    P("   none")

# 3c. fresh: relaxed — hits for the 3 signings under one seed with roughly
#     increasing k (any mix), g between 1 and 2000 per adjacent pair
P("-- fresh 3 (relaxed): per-seed/mix/C hit k-sets per signing (adjacent gaps 1..2000):")
rel = defaultdict(lambda: defaultdict(dict))
for (s, cname, C, gname), trip in fsets.items():
    for (gname2, wname, k) in trip:
        signum = int(gname2.replace("fresh", "").split("/")[0])
        rel[(s, cname, C)].setdefault(signum, set()).add(k)
cnt_rel = 0
for (s, cname, C), per in rel.items():
    if len(per) == 3:
        gaps = []
        ok = True
        for i in (1, 2, 3):
            if i not in per:
                ok = False
                break
        if ok:
            for k1 in per[1]:
                for k2 in per[2]:
                    gg = k2 - k1
                    if 1 <= gg <= 2000 and any(1 <= k3 - k2 <= 2000 for k3 in per[3]):
                        cnt_rel += 1
                        if cnt_rel <= 20:
                            P("   seed=%d %s C=%s S1@%s S2@%s S3@%s" %
                              (s, cname, h32(C), sorted(per[1])[:4], sorted(per[2])[:4], sorted(per[3])[:4]))
P("   relaxed combos: %d" % cnt_rel)

# ------------------------------------------------ header sanity
P("")
P("-- sanity: header words (Random3-from-second, verified) as lrand48 targets?")
hdr_hits = 0
for r in rows:
    hdr = bytes.fromhex(r["blob"])[:16]
    hw = [int.from_bytes(hdr[i:i + 4], "big") for i in range(0, 16, 4)]
    for d in range(-3, 2):
        dr = seed_draw_cache.get(r["second"] + d)
        if dr is None:
            dr = seed_draw_cache[r["second"] + d] = lrand48_stream(r["second"] + d)
        for cname, fn in MIXES:
            for C in Cs[:40]:
                m = fn(dr[:-1], dr[1:], C)
                for v in hw:
                    le = int.from_bytes(int.to_bytes(v, 4, "big"), "little")
                    if v in m or le in m:
                        hdr_hits += 1
P("   header-word hits in lrand48 mixes (8 rows x 5 seeds x 40 C): %d" % hdr_hits)

with open(REV + "/corpus_seed_lcg.log", "w", encoding="utf-8") as f:
    f.write("\n".join(out_lines) + "\n")
print("\nsaved corpus_seed_lcg.log (%d lines)" % len(out_lines))
