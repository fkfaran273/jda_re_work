#!/usr/bin/env python3
"""_sub_alg_bitbias.py — follow-up on the two bit-bias leads from attack 6:
bit13 ones=77/112 (3.97 sigma), bit25 ones=71/112 (2.83 sigma).

  a) per word-slot and per-bit ones counts (28 samples per slot-bit);
  b) joint distribution of the biased bits (independent?);
  c) pattern of bit13 within each header (how many of w0..w3 set);
  d) synthetic calibration: same statistics for
       - uniform random 31-bit words (MC, 200 reps)
       - bionic Random3 draws, direct layout  (28x4 words, random seeds)
       - bionic Random3 draws, pair-XOR layout (the Android model)
       - MINSTD raw draws (a=16807 mod 2^31-1), direct and pair-XOR
     -> does the observed bias happen naturally in these families?
Writes _sub_alg_bitbias_out.json.
"""
import json, os, random, struct, sys, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
H = json.load(open(os.path.join(HERE, "_sub_alg_headers.json")))
HEADERS = H["headers"]

spec = importlib.util.spec_from_file_location("signer", os.path.join(HERE, "adj9_signer.py"))
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)

flat = [w for u in HEADERS for w in u["w"]]
N = len(flat)

def ones_per_bit(ws, nbits=31):
    return [sum((w >> b) & 1 for w in ws) for b in range(nbits)]

def max_z(c, n):
    from math import sqrt
    return (c - n / 2) / (sqrt(n) / 2)

obs_bit = ones_per_bit(flat)
print(f"observed ones-per-bit (n={N}): max |z| = "
      f"{max(abs(max_z(c, N)) for c in obs_bit):.2f} at bit "
      f"{max(range(31), key=lambda b: abs(max_z(obs_bit[b], N)))}")
print("   full:", {b: c for b, c in enumerate(obs_bit)})

# per-slot
print("\nper-slot ones-per-bit (28 samples each), z>2 marked:")
for k in range(4):
    ws = [u["w"][k] for u in HEADERS]
    oc = ones_per_bit(ws)
    hot = {b: c for b, c in enumerate(oc) if abs(max_z(c, 28)) > 2}
    print(f"   w{k}: hot bits {hot}")

# joint of bit13/bit25
b13 = [(w >> 13) & 1 for w in flat]
b25 = [(w >> 25) & 1 for w in flat]
n11 = sum(x & y for x, y in zip(b13, b25))
p13, p25 = sum(b13) / N, sum(b25) / N
exp11 = p13 * p25 * N
print(f"\njoint bit13&bit25 = 1: {n11} (independent expectation {exp11:.1f})")

# within-header bit13 pattern
pat = {}
for hi, u in enumerate(HEADERS):
    m = tuple((w >> 13) & 1 for w in u["w"])
    pat[m] = pat.get(m, 0) + 1
print("within-header bit13 patterns (w0,w1,w2,w3):", pat)

# ---------- synthetic calibration ----------
def synth_words(gen, layout, n_words, rng):
    ws = []
    while len(ws) < n_words:
        d = [gen(rng) for _ in range(8)]
        if layout == "direct":
            ws += d[:4]
        else:
            ws += [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return ws[:n_words]

def rand3_gen(rng):
    r = signer.Random3(rng.getrandbits(31) | 1)
    return r.next()

def minstd_gen_factory():
    state = {"x": None}
    def g(rng):
        if state["x"] is None:
            state["x"] = rng.getrandbits(31) | 1
        else:
            state["x"] = (16807 * state["x"]) % ((1 << 31) - 1)
        return state["x"]
    return g

def lrand48_gen_factory():
    state = {"x": None}
    def g(rng):
        if state["x"] is None:
            state["x"] = (((rng.getrandbits(32)) << 16) | 0x330E) & ((1 << 48) - 1)
        state["x"] = (0x5DEECE66D * state["x"] + 0xB) & ((1 << 48) - 1)
        return state["x"] >> 17
    return g

rng = random.Random(20261001)
REPS = 200
results = {}
fams = {
    "uniform": lambda rng: rng.getrandbits(31),
    "rand3_direct": lambda rng: rand3_gen(rng),
    "minstd_direct": minstd_gen_factory(),
    "lrand48_direct": lrand48_gen_factory(),
}
for name, g in fams.items():
    for layout in ("direct", "pair"):
        maxz_list = []
        bit13_list = []
        for _ in range(REPS):
            ws = synth_words(g, layout, 112, rng)
            oc = ones_per_bit(ws)
            bit13_list.append(oc[13])
            maxz_list.append(max(abs(max_z(c, 112)) for c in oc))
        results[f"{name}/{layout}"] = {
            "bit13_mean": round(sum(bit13_list) / REPS, 1),
            "bit13_min": min(bit13_list), "bit13_max": max(bit13_list),
            "maxz_mean": round(sum(maxz_list) / REPS, 2),
            "maxz_p95": sorted(maxz_list)[int(0.95 * REPS)],
        }
        print(f"   {name}/{layout}: bit13 ones mean {results[f'{name}/{layout}']['bit13_mean']} "
              f"[{results[f'{name}/{layout}']['bit13_min']}..{results[f'{name}/{layout}']['bit13_max']}], "
              f"max|z| mean {results[f'{name}/{layout}']['maxz_mean']} "
              f"p95 {results[f'{name}/{layout}']['maxz_p95']}")

print(f"\nobserved: bit13 ones = 77, max|z| = {max(abs(max_z(c,112)) for c in obs_bit):.2f}")
out = {"obs_ones_per_bit": obs_bit, "joint_b13_b25": n11, "exp_joint": exp11,
       "within_header_bit13_patterns": {str(k): v for k, v in pat.items()},
       "synthetic": results}
json.dump(out, open(os.path.join(HERE, "_sub_alg_bitbias_out.json"), "w"), indent=1)
print("wrote _sub_alg_bitbias_out.json")
