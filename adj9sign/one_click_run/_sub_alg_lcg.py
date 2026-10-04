#!/usr/bin/env python3
"""_sub_alg_lcg.py — attacks 1, 2 and 4.

Attack 1: algebraic LCG solve, direct-draw model. Per header assume
w0..w3 are 4 consecutive draws of x' = a*x + c (mod M). Solve (a,c) from
w0,w1,w2 (general solver handling non-invertible differences), verify w3.
Collect solution sets; intersect across headers. ANY (a,c) reproducing >=2
headers identifies the generator.

Attack 2: same on M = 2^32 (full words), on little-endian word packing,
and (bonus) M = 2^31-1, the MINSTD prime (a multiplicative-mod-p LCG is
what MINSTD family really is; pure mod-2^31 tests would miss it).

Attack 4: cross-second stream test. Headers sorted by signing second;
words of header t and t+1 treated as 8 consecutive draws -> solve (a,c)
from draws 0,1,2, verify draws 3..7. Mod 2^31, 2^32 and 2^31-1.

Reads _sub_alg_headers.json. Prints findings; writes _sub_alg_lcg_out.json.
"""
import json, os
from math import gcd

HERE = os.path.dirname(os.path.abspath(__file__))
H = json.load(open(os.path.join(HERE, "_sub_alg_headers.json")))
HEADERS = H["headers"]


def val2(x):
    return (x & -x).bit_length() - 1 if x else None


def solve_lcg_pow2(w0, w1, w2, m):
    """All (a,c) mod 2^m with w1 = a*w0+c, w2 = a*w1+c (mod 2^m).
    Returns list of (a,c); may be large if w1-w0 is very even (capped)."""
    M = 1 << m
    D = (w1 - w0) % M
    E = (w2 - w1) % M
    if D == 0:
        return [("UNDER", E)]  # any a with c = w1-a*w0 if E==0; else none
    k = val2(D)
    if E % (1 << k) != 0:
        return []
    mk = m - k
    Dp = D >> k
    Ep = E >> k
    inv = pow(Dp, -1, 1 << mk)
    a0 = (Ep * inv) % (1 << mk)
    out = []
    step = 1 << mk
    for t in range(1 << k):
        a = a0 + t * step
        if a >= (1 << m):
            break
        c = (w1 - a * w0) % M
        out.append((a, c))
        if len(out) > (1 << 20):
            break
    return out


def solve_lcg_prime(w0, w1, w2, p):
    """All (a,c) mod p (p prime) with w1=a*w0+c, w2=a*w1+c (mod p)."""
    D = (w1 - w0) % p
    E = (w2 - w1) % p
    if D == 0:
        return [("UNDER", E)]
    a = (E * pow(D, -1, p)) % p
    c = (w1 - a * w0) % p
    return [(a, c)]


def verify(w, a, c, m):
    """Check w[i+1] = a*w[i]+c (mod 2^m if m int else mod m) for all i."""
    p = (1 << m) if isinstance(m, int) else m
    for i in range(len(w) - 1):
        if (a * w[i] + c) % p != w[i + 1] % p:
            return False
    return True


def run_model(name, words_key, mod, solver, m_repr):
    """Attack 1 per-header solve + cross-header intersection."""
    print(f"\n=== Attack 1: {name} ===")
    per_header = []
    n_self_ok = 0
    for i, u in enumerate(HEADERS):
        w = u[words_key]
        sols = solver(w[0], w[1], w[2], mod)
        ok_sols = []
        under = False
        for s in sols:
            if s[0] == "UNDER":
                under = True
                continue
            if verify(w, s[0], s[1], mod):
                ok_sols.append(s)
        if ok_sols:
            n_self_ok += 1
        per_header.append((i, w, ok_sols, under))
        if ok_sols and i < 6:
            print(f"  hdr {i}: SELF-CONSISTENT (a,c) count={len(ok_sols)} e.g. "
                  f"{ok_sols[0][0]:#x},{ok_sols[0][1]:#x}")
    print(f"  headers with >=1 self-consistent (a,c) through w3: "
          f"{n_self_ok}/{len(HEADERS)}   (expect ~{len(HEADERS)/(1<<62):.3g} by chance)")

    # cross-header intersection: exact (a,c) shared by >=2 headers
    from collections import defaultdict
    cnt = defaultdict(list)
    for i, w, ok, under in per_header:
        for a, c in ok:
            cnt[(a, c)].append(i)
    hits = {k: v for k, v in cnt.items() if len(v) >= 2}
    if hits:
        print("  *** (a,c) shared by >=2 headers ***")
        for (a, c), idxs in hits.items():
            print(f"    a={a:#x} c={c:#x} headers={idxs}")
    else:
        print("  no (a,c) shared by any two headers -> direct-draw LCG of this "
              "modulus is RULED OUT for all headers simultaneously")
    return n_self_ok, hits


def run_stream(name, words_key, mod, solver, m_repr):
    """Attack 4: consecutive headers as 8 consecutive draws."""
    print(f"\n=== Attack 4: cross-second stream, {name} ===")
    order = sorted(range(len(HEADERS)),
                   key=lambda i: HEADERS[i]["sec_min"])
    any_hit = 0
    pairs = 0
    for j in range(len(order) - 1):
        ia, ib = order[j], order[j + 1]
        wa, wb = HEADERS[ia][words_key], HEADERS[ib][words_key]
        d = wa + wb  # 8 draws
        sols = solver(d[0], d[1], d[2], mod)
        pairs += 1
        good = []
        for s in sols:
            if s[0] == "UNDER":
                continue
            # verify draws 3..7
            ok = all((s[0] * d[i] + s[1]) % ((1 << m_repr) if isinstance(m_repr, int)
                                             else m_repr) == d[i + 1]
                     for i in range(2, 7))
            if ok:
                good.append(s)
        if good:
            any_hit += 1
            print(f"  *** STREAM HIT hdr {ia}->{ib}: a={good[0][0]:#x} c={good[0][1]:#x}")
    print(f"  stream-consistent consecutive pairs: {any_hit}/{pairs}")
    return any_hit


if __name__ == "__main__":
    results = {}
    # Attack 1 + 2 — big-endian words
    results["be_m31"] = run_model("BE words, mod 2^31", "w", 1 << 31,
                                  lambda a, b, c, m: solve_lcg_pow2(a, b, c, 31), 31)
    results["be_m32"] = run_model("BE words, mod 2^32", "w", 1 << 32,
                                  lambda a, b, c, m: solve_lcg_pow2(a, b, c, 32), 32)
    # Attack 1 + 2 — little-endian words
    results["le_m31"] = run_model("LE words, mod 2^31", "w_le", 1 << 31,
                                  lambda a, b, c, m: solve_lcg_pow2(a, b, c, 31), 31)
    results["le_m32"] = run_model("LE words, mod 2^32", "w_le", 1 << 32,
                                  lambda a, b, c, m: solve_lcg_pow2(a, b, c, 32), 32)
    # bonus: MINSTD prime modulus (multiplicative LCG mod 2^31-1)
    P = (1 << 31) - 1
    results["be_mp"] = run_model("BE words, mod p=2^31-1 (MINSTD prime)", "w", P,
                                 lambda a, b, c, m: solve_lcg_prime(a, b, c, P), P)
    results["le_mp"] = run_model("LE words, mod p=2^31-1 (MINSTD prime)", "w_le", P,
                                 lambda a, b, c, m: solve_lcg_prime(a, b, c, P), P)

    # Attack 4 — cross-second streams
    results["stream_be_m31"] = run_stream("BE, mod 2^31", "w", 1 << 31,
                                          lambda a, b, c, m: solve_lcg_pow2(a, b, c, 31), 31)
    results["stream_be_m32"] = run_stream("BE, mod 2^32", "w", 1 << 32,
                                          lambda a, b, c, m: solve_lcg_pow2(a, b, c, 32), 32)
    results["stream_be_mp"] = run_stream("BE, mod p=2^31-1", "w", P,
                                         lambda a, b, c, m: solve_lcg_prime(a, b, c, P), P)
    results["stream_le_m32"] = run_stream("LE, mod 2^32", "w_le", 1 << 32,
                                          lambda a, b, c, m: solve_lcg_pow2(a, b, c, 32), 32)

    json.dump({k: ({"self_ok": v[0], "hits": {str(kk): vv for kk, vv in v[1].items()}}
                   if isinstance(v, tuple) else {"stream_hits": v})
               for k, v in results.items()},
              open(os.path.join(HERE, "_sub_alg_lcg_out.json"), "w"), indent=1)
    print("\nwrote _sub_alg_lcg_out.json")
