#!/usr/bin/env python3
"""_sub_alg_gf2.py — attack 3: XOR-pair / GF(2)-linearity tests.

If draws come from an LFSR/xorshift (xor-linear), XOR-combinations of draws
are xor-linear too, so the 112 observed words (28 headers x 4) would carry
GF(2) structure. Tests:
  a) GF(2) rank of the 112x31 bit matrix (all words < 2^31, so max rank 30).
     rank < 30  => a global linear law exists among the words.
  b) sparse kernel relations, weight 1..6 (subset of the 112 words XORing to
     zero), via meet-in-the-middle; each hit reported with header/word indices
     and pattern classification (same header / aligned positions / random).
     Expected chance counts are printed for calibration.
  c) per-header relations: every subset of {w0,w1,w2,w3} XORing to 0
     (covers w2 = w0^w1, w3 = w0^w1^w2, parity-0, etc.), plus across-header
     aligned-position relations (w0_t == w0_u etc. are weight-2 hits of b).
Reads _sub_alg_headers.json. Writes _sub_alg_gf2_out.json.
"""
import json, os, itertools
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
H = json.load(open(os.path.join(HERE, "_sub_alg_headers.json")))
HEADERS = H["headers"]
M31 = (1 << 31) - 1  # mask of the 31 significant bits

# collect words with their (header_idx, word_idx) provenance
words = []      # 31-bit values
prov = []       # (h, k)
for hi, u in enumerate(HEADERS):
    for k, w in enumerate(u["w"]):
        words.append(w & M31)
        prov.append((hi, k))
N = len(words)
print(f"words: {N} (28 headers x 4), all < 2^31: "
      f"{all(0 <= w < (1<<31) for w in words)}")


def gf2_rank(vecs, nbits):
    basis = []
    for v in vecs:
        for b in basis:
            v = min(v, v ^ b)
        if v:
            basis.append(v)
            basis.sort(reverse=True)
    return len(basis)


rank = gf2_rank(words, 31)
print(f"\n(a) GF(2) rank of {N} word-vectors over 31 bits: {rank} "
      f"(max possible 31: only bit 31 is dead by the 31-bit law; "
      f"rank < 31 would mean a global linear law)")
# which bit positions are pivot / free?
basis = []
for v in words:
    for b in basis:
        v = min(v, v ^ b)
    if v:
        basis.append(v)
        basis.sort(reverse=True)
pivots = [b.bit_length() - 1 for b in basis]
free = [i for i in range(31) if i not in pivots]
print(f"    pivot bit positions (0=LSB): {sorted(pivots)}")
print(f"    free bit positions: {sorted(free)}")
# verify free bits are actually constant-zero across all words (vs truly free)
for i in free:
    vals = {(w >> i) & 1 for w in words}
    print(f"    bit {i}: values seen across all words = {vals}")

# ---------------- (b) sparse kernel relations ----------------
print("\n(b) sparse kernel relations (subsets of the 112 words XOR = 0)")
idx_of = defaultdict(list)
for i, w in enumerate(words):
    idx_of[w].append(i)
dups = {w: ii for w, ii in idx_of.items() if len(ii) > 1}
print(f"  weight-1/2 (duplicate words): {len(dups)}")
for w, ii in dups.items():
    print(f"    value {w:#010x} at {ii} (prov { [prov[i] for i in ii] })")

hits = {}
# weight 3: w_i ^ w_j == w_k
for i, j in itertools.combinations(range(N), 2):
    x = words[i] ^ words[j]
    if x in idx_of:
        for k in idx_of[x]:
            if k not in (i, j):
                key = tuple(sorted({i, j, k}))
                hits.setdefault(key, 0)
print(f"  weight-3 relations: {len([k for k in hits if len(k)==3])} "
      f"(chance expectation ~ C(112,3)/2^30 = {len(list(itertools.combinations(range(N),3)))/2**30:.4f})")

# weight 4: pair-xor dictionary
pair_dict = defaultdict(list)
for i, j in itertools.combinations(range(N), 2):
    pair_dict[words[i] ^ words[j]].append((i, j))
w4 = []
for x, plist in pair_dict.items():
    if len(plist) < 2:
        continue
    for (i, j), (k, l) in itertools.combinations(plist, 2):
        if len({i, j, k, l}) == 4:
            w4.append(tuple(sorted((i, j, k, l))))
w4 = sorted(set(w4))
print(f"  weight-4 relations: {len(w4)} (chance ~ C(C(112,2),2)/2^30 = "
      f"{(N*(N-1)//2)**2//2/2**30:.3f})")

# weight 5: 2-subset xor looked up in 3-subset xors
tri_dict = defaultdict(list)
for i, j, k in itertools.combinations(range(N), 3):
    tri_dict[words[i] ^ words[j] ^ words[k]].append((i, j, k))
w5 = []
for x, plist in pair_dict.items():
    if x not in tri_dict:
        continue
    for (i, j) in plist:
        for (k, l, m) in tri_dict[x]:
            if len({i, j, k, l, m}) == 5:
                w5.append(tuple(sorted((i, j, k, l, m))))
w5 = sorted(set(w5))
print(f"  weight-5 relations: {len(w5)}")

# weight 6: 3-subset vs 3-subset
w6 = []
for x, tl in tri_dict.items():
    if len(tl) < 2:
        continue
    for t1, t2 in itertools.combinations(tl, 2):
        if len(set(t1) | set(t2)) == 6:
            w6.append(tuple(sorted(set(t1) | set(t2))))
w6 = sorted(set(w6))
print(f"  weight-6 relations: {len(w6)} (chance ~ C(112,6)/2^31 = "
      f"{__import__('math').comb(112,6)/2**31:.2f})")

def classify(rel):
    hs = [prov[i] for i in rel]
    same_h = len({h for h, _ in hs}) == 1
    aligned = len({k for _, k in hs}) == 1
    return same_h, aligned

for name, rels in (("w3", [k for k in hits if len(k) == 3]),
                   ("w4", w4), ("w5", w5), ("w6", w6[:80])):
    for rel in rels:
        sh, al = classify(rel)
        tag = ("SAME-HEADER" if sh else ("ALIGNED-POSITIONS" if al else "mixed"))
        xs = [words[i] for i in rel]
        print(f"  [{tag}] weight-{len(rel)}: " +
              " ^ ".join(f"h{prov[i][0]}w{prov[i][1]}" for i in rel) +
              "  = " + " ^ ".join(f"{x:08x}" for x in xs) + " = 0")

# ---------------- (c) per-header subset relations ----------------
print("\n(c) per-header subset relations among w0..w3")
any_c = 0
for hi, u in enumerate(HEADERS):
    w = [x & M31 for x in u["w"]]
    for r in range(1, 5):
        for comb in itertools.combinations(range(4), r):
            x = 0
            for k in comb:
                x ^= w[k]
            if x == 0:
                any_c += 1
                print(f"  hdr {hi}: w{comb} XOR = 0")
print(f"  total per-header zero-XOR subsets: {any_c} "
      f"(28 headers x 15 subsets; chance = 15/2^31 per header)")

# also: full 27-byte-level sanity — do tail bytes share the 31-bit word law?
out = {"rank": rank, "pivots": sorted(pivots), "free_bits": sorted(free),
       "dups": {f"{w:08x}": [list(prov[i]) for i in ii] for w, ii in dups.items()},
       "n_w3": len([k for k in hits if len(k) == 3]), "n_w4": len(w4),
       "n_w5": len(w5), "n_w6": len(w6), "per_header_zeroXOR": any_c}
json.dump(out, open(os.path.join(HERE, "_sub_alg_gf2_out.json"), "w"), indent=1)
print("\nwrote _sub_alg_gf2_out.json")
