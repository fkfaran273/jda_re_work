# adj9 signature — what is actually verified (corrected)

**Date:** 2026-09-25
**Method:** full-envelope replay of 40 genuine captures in `rev/fill_runs/*.json`.
Each replay feeds the REAL captured descriptors + REAL signing second (`srand`)
through our FinEx / header / assembly and compares byte-for-byte to the REAL
192-byte `blob`.

## Verdict per envelope component

| component        | byte-exact vs real captures? | evidence |
|------------------|------------------------------|----------|
| 16-byte header   | **YES** (40/40)              | `blob[:16] == make_header(srand[0])` holds for every capture |
| d10 claim string | **YES**                      | already proven; roundtrips exactly (360/387/360 B) |
| FinEx body       | **NO** (0/40)                 | first normal mismatch at envelope offset 64; `env_val` at offset 16. Wrong even when fed the real descriptors -> the keystream/assembly is wrong independent of the region |
| region d2        | **YES** (38 normal captures)  | exact, once the harness's required +4 ms fill offset is applied |
| region d4        | **YES** (38 normal captures)  | exact, same +4 ms offset |
| region d0        | **NO**                       | real d0 begins with a 6-word prefix `W0, X, U0..U3` that `F._d0_words` never models; bytes from offset 24 match. No head value (H4/H5 or any of 65536) reproduces the first captured dword. |

## The d0 prefix (the concrete gap)

For `T+2` the real first 24 bytes are:
`a3ca4a0f fbab9166 bfc7c907 e7a64dc2 6363d2c7 7afb88cf`
(= `W0, X, U0, U1, U2, U3`)

`F._d0_words(d4, head)` produces only the repeated whitener *tail*; it has no
model for that 6-word prefix. This is the region defect — not the whitener head
and not the tail.

## L3 is NOT the bug

The dry-run's `L3 (X == U[3])` failure is **not** an emulator-only artifact: the
REAL captured d0 also fails L3 in every non-gated fill_run (only the zero/gate
`env_val` case passes L1/L2/L3). L1 and L2 pass on both real and generated
regions. So L3 is a non-issue; the d0 prefix is the real gap.

## What this means

My earlier "byte-exact signature" framing was too strong. In truth:
- **Proven byte-exact:** the header and the d10 claim.
- **Unverified / wrong:** the FinEx body (the 176-byte keystream) and the first
  six words of the d0 region.

Both unverified pieces sit *inside* the 192-byte envelope the server verifies,
so the signature is **not** fully reproduced. The server-side Organic default is
still unexplained, but the open signature work is now concrete: reconstruct the
d0 6-word prefix and fix the FinEx body keystream/assembly.

## Files
- Replay inputs: `rev/fill_runs/*.json` (each has real `blob`, `srand`, `descs`, `region`).
- Code: `rev/mint_pipeline.py`, `rev/fin_vm2.py`, `rev/F.py`, `rev/header_gen.py`.
- Region must use the +4 ms fill offset (`V = sec ^ (usec + 4000)`, carry into sec) or d2/d4 mismatch.
