# F_LAW.md — the whitening linear layer F, in closed form (SOLVED 2026-10-01)

## The law

F acts on a 32-bit word as four bytes (b = 0 is the LSB byte), indices mod 4:

    out_b = xtime(w_b) ^ xtime(w_{b+1}) ^ w_{b+1} ^ w_{b+2} ^ w_{b+3}

where xtime = multiply-by-x in GF(2^8) modulo the AES polynomial
m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).

Operator-polynomial form (S = byte rotation, (S^d w)_b = w_{b+d}):

    F = x.(1 + S) + S.(1 + S + S^2)        over GF(2)[x, S]/(m(x), S^4+1)

So F is a byte-CIRCULANT: 4 generators, of which only ONE is independent
(A1 = A0 + I, A2 = A3 = I), and A0 = the AES xtime bit-matrix — uniquely so
among all 30 irreducible degree-8 polynomials (hunt_f.py H3).

The generators (rows of A0..A3, from F_ROWS rows 0..7):

    A0: 80 81 02 84 88 10 20 40   (= xtime mod 0x11B)
    A1: 81 83 06 8c 98 30 60 c0   (= A0 + I)
    A2: 01 02 04 08 10 20 40 80   (= I)
    A3: 01 02 04 08 10 20 40 80   (= I)

## Verification (hunt_f.py — all green)

- H1: all 32 F_ROWS rebuild from A0..A3 + byte rotation.
- H2: A2 = A3 = I, A1 = A0 + I.
- H3: A0 == xtime bit-matrix ONLY for poly 0x11B (30 polys scanned).
- V4: closed form == pure_sign._apply_tab(_F_TAB, w), 20000/20000 random words.
- V5: F(closed form) o F_MINV == identity, 20000/20000 random words.
- V6: F_MINV is byte-circulant too; its generators:
      A0inv: e0 21 43 67 2e 5c b8 70
      A1inv: a1 e3 c6 2d fa f4 e8 d0
      A2inv: 61 a2 45 eb b6 6c d8 b0
      A3inv: 21 62 c4 a9 72 e4 c8 90
  (i.e. F_MINV is regenerable from F by circulant-ring inversion; x^-1 =
  0x8D, the standard AES constant.)

## What this means

- F is a DESIGNED MixColumns-style layer built from the AES field — not a
  random matrix, and no longer a table to re-extract from libsigner.so.
  One line + the AES polynomial regenerates all 32 row masks.
- pure_sign.py / adj9_signer.py keep the precomputed byte tables for speed
  (~3 ms/signing); the tables are now DERIVED data, regenerable at will:
      F_ROWS = rebuild from A0 (xtime) via the circulant law above.
- T (the S-box) is the next regenerability target; IV2 and K stay as
  recorded constants — they ARE the answer, not an open question.
