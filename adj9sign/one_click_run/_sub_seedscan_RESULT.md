# _sub_seedscan — iOS adj9 header PRNG wide seed scan

Run: 2026-10-01 20:47:42  (python 3.14.7, numpy 2.5.3, wall 600.2 s)

## Data extracted

Source: `cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz` — 30 signed requests, **28 unique 16-byte headers** (ClientBeginRequest, +05:30, floored to unix seconds).

| approx unix second | reqs | header16 (hex) |
|---|---|---|
| 1787553341 | 3 | `3be1d83d6b8eae543eb1a8a5757ca3d6` |
| 1787553343 | 1 | `7032bfb41df49d64635f7fdf77692880` |
| 1787553345 | 1 | `1e81a0e358d3435d53e19372326ae6cc` |
| 1787553734 | 1 | `2aa273867af137e645c00ff372140080` |
| 1787555530 | 1 | `445f276a44223915169583790e380479` |
| 1787555694 | 1 | `1ce776e8624d3f484b17fb9c40f720c9` |
| 1787555749 | 1 | `3adbbd0759adff20262f526c2109d6b7` |
| 1787555752 | 1 | `6f5f4b1f4beb933e27e018ab13adc93b` |
| 1787555854 | 1 | `12eaa7fd20919ccf207c6ae955a028b5` |
| 1787555856 | 1 | `34b9910157bf2ae7500a6c541263f6c7` |
| 1787555857 | 1 | `476489b5738b89fb28cc910a7f465e21` |
| 1787556043 | 1 | `036ca82810a27af207a753a402a64c11` |
| 1787556293 | 1 | `729afe9c161726a64f75a6ba3fec087d` |
| 1787556408 | 1 | `735662911f2170f664b7694e1f60ff21` |
| 1787556874 | 1 | `3b2821db5616cf396f85b2d31f1f8ea8` |
| 1787557023 | 1 | `74720810129ebec14c964a612ae13c2c` |
| 1787557041 | 1 | `274681592263be742291b34f39687c94` |
| 1787557198 | 1 | `0a1b66ae13cd36ee477b73072626bd45` |
| 1787557216 | 1 | `2507395c6995ba9a1442323631a7fc0c` |
| 1787557237 | 1 | `1b906c1b49bc684b7fddb2e25cf6662f` |
| 1787557248 | 1 | `519834e200c5d00642c7666b03f42c1f` |
| 1787557264 | 1 | `6239e07c20154509440db2c774acbeab` |
| 1787557279 | 1 | `6f875f641afb7b44219daf767b8c2a9c` |
| 1787557292 | 1 | `072738427633346a502600121257ab23` |
| 1787557309 | 1 | `47c27b427fa169186ff0e1ce72fd7b03` |
| 1787557326 | 1 | `506235a4489efc155203f69a01448c9f` |
| 1787557446 | 1 | `5ac321ee407b691b6e40838d3a6ab159` |
| 1787557518 | 1 | `06bf02d81386784b19b1aee71947b4f9` |

Capture-second span: 1787553341 .. 1787557518 (4177 s).  All 28 headers have every word < 2^31 (consistent with XOR of two 31-bit draws).

## Vectorization cross-checks (all PASS, run before any scan)

1. Vectorized TYPE_3 (31xN uint32 state matrix, 30-step MINSTD Schrage init incl. negative-r[0] branch, 310+8 vectorized feedback steps) vs `adj9_signer.Random3`: **113 seeds (100 random + edge/epoch cases), all 8 draws AND 4 XOR words equal.**
2. Vectorized TYPE_3 header vs `adj9_signer.make_header` on the 9 genuine ANDROID gold seconds: **9/9 byte-exact**.
3. Vectorized srand48/lrand48 (48-bit LCG, exact 24/24-bit split multiply) vs scalar reference: **106 seeds x 72 draws equal**, XOR words equal for warm-ups 0..64 spot checks.
4. Scalar arbitrary-warm-up TYPE_3 vs Random3: 20 seeds equal.
5. End-to-end scan machinery sanity: a planted known Android header was recovered by the scan at K=0, warm-up 310.

## Scans executed (exact coverage)

| generator | warm-ups | seed law | K window | seeds scanned | (second,K) header evaluations | candidates prefiltered | exact hits |
|---|---|---|---|---|---|---|---|
| bionic TYPE_3 | 310 | second + K | -5000000..+5000000 | 10004178 | 280000028 | 16 | 0 |
| srand48/lrand48 | 0..64 | second + K | -100000000..+100000000 | 200004178 | 5600000028 x 65 W = 364000001820 | 21596 | 0 |

Union seed range TYPE_3: 1782553341..1792557518 (covers K in [-5000000,+5000000] for every capture second).  Union seed range LCG48: 1687553341..1887557518 (K in [-100000000,+100000000]).  Prefilter = 24-bit Bloom over the 28 observed w0 values (false-positive rate 1.67e-06 per test); every candidate re-verified exactly (all 4 words) with the scalar ground-truth generator.

## Targeted tests (exact seeds, no scan)

For every capture second T: seed = T-978307200 (Apple epoch), T+2082844800 (1904 epoch), (T*1000)&(2^31-1), (T*1000)&(2^32-1) against TYPE_3 (310 warm-up) and LCG48 (warm-up 0..64); plus warm-up sweeps W=0..4096 for TYPE_3 and LCG48 at seed = T and each epoch seed.  (Exact, vectorized over W.)

## Result

**NO MATCH.**  Zero exact 4-word (128-bit) header matches anywhere in:

- bionic TYPE_3 with 310 warm-up, seed = capture_second + K for all K in [-5000000, +5000000] — 10004178 seeds, 10000001 (second,K) evaluations per header.
- srand48/lrand48 with warm-ups 0..64, seed = capture_second + K for all K in [-100000000, +100000000] — 200004178 seeds x 65 warm-ups.
- targeted Apple/1904/millisecond-epoch seeds (both generators) and warm-up sweeps 0..4096.

Therefore the iOS header is NOT produced by the bionic TYPE_3 rand nor by lrand48 under any second-derived seed within +/-58 days (TYPE_3) / +/-3.2 years (LCG48) of the captures, nor by any of the targeted epoch conversions.  The iOS PRNG law remains unidentified; next probes should target generator FAMILIES outside these two (e.g. xorshift/PCG/xoshiro, iOS arc4random/ChaCha20-based, Swift/objc RNGs, or a seeded shuffle-based law like the Android region PRNG).

## Notes

- Requests in the same capture second can share a header (observed: header `3be1d83d…` spans capture seconds 1787553341-342), consistent with the per-second header law.
- Only this script and `_sub_seedscan_RESULT.md` were written; `adj9_signer.py` was imported read-only (bytecode writing disabled).
