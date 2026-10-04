# T_LAW.md — the whitening S-box T, in closed form (SOLVED 2026-10-01)

## The law

    T[v] = AES_SBOX[v] XOR 0x55          for all v in 0..255

The S-box of this cipher IS the AES S-box, stored XOR-0x55-obfuscated —
exactly like the key-schedule constants KB (pure_sign.py: `_KEYTAB = KB ^ 0x55`,
and the cipher consumes it as `S(v) = T[v] ^ 0x55` in `whiten_chunk`).

Equivalently, with no table at all (v^-1 taken in GF(2^8) modulo the AES
polynomial m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B), with 0^-1 := 0):

    T[v] = L(v^-1) XOR 0x36

where L is the AES S-box affine linear part

    L(x) = x ^ rotl8(x,1) ^ rotl8(x,2) ^ rotl8(x,3) ^ rotl8(x,4)

(a byte-circulant, first row 0xF1; rows f1 e3 c7 8f 1f 3e 7c f8), and
0x36 = 0x63 ^ 0x55 (AES round constant XOR the store-time obfuscation).

So the generative formula is the textbook AES S-box affine/inverse construction
with one extra XOR of 0x55 at storage time:

    AES_SBOX[v] = L(v^-1) ^ 0x63        =>        T[v] = L(v^-1) ^ 0x63 ^ 0x55

## Generator (regenerates all 256 bytes of T from scratch)

```python
POLY = 0x11B  # x^8 + x^4 + x^3 + x + 1

def gf_mul(a, b, m=POLY):
    r = 0
    while b:
        if b & 1: r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100: a ^= m | 0x100
    return r

def gf_inv(a, m=POLY):                    # 0^-1 := 0
    return gf_pow(a, 254, m) if a else 0  # gf_pow = square-and-multiply

def rotl8(x, r):
    r &= 7
    return ((x << r) | (x >> (8 - r))) & 0xFF if r else x

L_TAB = [x ^ rotl8(x,1) ^ rotl8(x,2) ^ rotl8(x,3) ^ rotl8(x,4) for x in range(256)]
T = bytes(L_TAB[gf_inv(v)] ^ 0x36 for v in range(256))

# verification against the extracted table:
#   >>> T == bytes.fromhex(pure_sign.T_HEX)
#   True                                    (256/256 bytes)
```

## Verification (hunt_t2.py — all green)

- V0: `S = T ^ 0x55 == AES_SBOX` on all 256 values: **True**.
- V0: raw `T == AES_SBOX ^ 0x55` on all 256 values: **True**.
- V1: algebraic regeneration `T[v] = L(v^-1) ^ 0x36` == pure_sign.T, 256/256: **True**.
- V2 (spectral confirmation): DDT spectrum of S = {2: 32130, 4: 255}; Walsh
  spectrum multiset and row-signature multisets identical to the AES S-box
  (they are the same box). The only power maps x^e (1 <= e <= 254, AES field)
  passing the DDT + Walsh + row-signature gates are e in
  {127, 191, 223, 239, 247, 251, 253, 254} — exactly the Frobenius orbit of
  the inversion exponent 254, i.e. all linearly equivalent to v^-1.
- V3 (complete affine-equivalence search, LAT row/pair-invariant
  backtracking, run against the AES S-box as core): finds M1 = M2 = identity,
  t1 = t2 = 0 in 0.2 s — S **is** the AES S-box verbatim; 256/256 functional
  verification: **True**.
- V4 (corrected power-map audit): with the FIXED solver (see below),
  S(v) = M . (v^-1) ^ c over the 30 irreducible degree-8 polynomials hits
  exactly one field: 0x11B, with M = L (rows f1 e3 c7 8f 1f 3e 7c f8) and
  c = 0x63. No other field hits (a field isomorphism would be a non-scaling
  input linear map, outside that audit's model).
- ST: tool self-tests — solve_affine round-trips on random planted affine
  decompositions (10/10), planted AES-equivalences recovered and verified
  (3/3), negative control (random permutation vs AES) rejected (1/1).

## Correction to the previous hunt (hunt_t.py battery 2)

The earlier battery 2 reported "no (poly, exponent) with S affine-equivalent
to v^e". That was a FALSE NEGATIVE caused by a solver bug: when re-assembling
the candidate output byte it OR-ed the parity bits into the constant
(`y = sbox[0]; y |= b << j`) instead of building the linear part and XOR-ing
the constant. A correct solution with S(v) = M.(v^-1) ^ 0x63 was rejected at
verification whenever a parity bit collided with a constant bit (240/256
points for the true M). hunt_t2.py `solve_affine` fixes this
(`acc ^ t != Y[v]`), after which the hit appears immediately at e = 254,
poly 0x11B. Consequently the prior refutation list ("NOT affine-equivalent to
any pure power map ... input-scaling only") does not stand: S is
affine-equivalent to v^-1 in the AES field with M = L, c = 0x63 — in fact it
IS the AES S-box.

## Consequences

- All previously measured properties follow from S = AES S-box: bijective,
  not an involution, 0 fixed points (S form), differential uniformity 4,
  differential spectrum {(2,32130),(4,255)}, 8 ANF degrees 7, max |LAT| 32.
- T is fully regenerable — one line plus the AES polynomial; no table needs
  to be extracted from libsigner.so:
      T_ROWS/T = (AES S-box) ^ 0x55 = L(v^-1) ^ 0x36.
- Consistent with the cipher's design language: the XOR-0x55 store-time
  obfuscation matches KB; the linear layer F is built from xtime in the same
  AES field (F_LAW.md). Curiosity: in this field ord(x) = 51 (0x11B is
  irreducible but NOT primitive; 0x03 is the usual generator), so xtime^51 is
  the identity map.
- pure_sign.py / adj9sign files were not modified; T stays derived data.
