# algo_practice — the adj9 algorithm in closed form: COMPLETE

Goal (achieved): replace the FinEx VM execution (10M steps, 15–25 s per
signing) with a closed-form pure-Python implementation, byte-exact against
genuine device blobs — and make every constant regenerable/derivable rather
than a captured dump.

## THE LEDGER — current status of every piece

The 192-byte blob = header(16) || whitened-record(144) || digest(32).

| piece | size | status | law lives in |
|---|---|---|---|
| header | 16 B | **FORMULA** — bionic srand/rand (MINSTD 16807), 310 warm-ups, 8 draws pair-XORed BE | `pure_signer/pure_sign.py` |
| record [0:46) | 46 B | **FORMULA** — magic `01 00 08`, d0 head (selector phases), `02`, **BE32(S)**, `03`, D9 = cert SHA-1 | same |
| record [46:78) block | 32 B | **FORMULA (SOLVED)** — SHA-256 with the standard padding/constants but chained from custom IV2, over `D9 ‖ 00 08 ‖ head16 ‖ LE32(S) ‖ sha256("") ‖ 01 ‖ 00*16 ‖ claims(unpadded)`. Note the record's S is BE, the block message's is LE — both serialisations are real | `pure_sign.py`, `block_law2/LAW.md` |
| record [78:144) | 66 B | **FORMULA** — `05`, SHA256(""), `06 01 07`, zeros, `0000`, `0e*14` | same |
| whitening (body) | 144 B | **FORMULA** — 14-round SPN, CBC from the header IV: S-box T = AES S-box ⊕ 0x55 (generated), round keys KB (extracted from bytecode, see below), permutation PI = 4×4 rows rotated right by row index (generated), linear F = AES-xtime byte-circulant (generated); inverse F_MINV derived by GF(2) inversion | same + `F_LAW.md`, `T_LAW.md` |
| digest | 32 B | **FORMULA** — two-pass SHA-256 MAC (pads hashed twice, NOT standard HMAC): `sha256((K^opad)‖opad‖sha256((K^ipad)‖ipad‖body))` | `digest_law/LAW.md` |
| claims (#10) | var | **ACTUAL WORDS** — one presence-filtered union law for SDK 5.7.0 AND 5.8.0: sorted profile + pinned `1500000` + sorted tail + `activity_kind, client_sdk, headers_id, native_version`. Kinds covered: session, click, attribution | `desc10_law.py` (5.7.0), `../creditsea/desc10_58.py` (5.8.0) |
| region d0/d2/d4 | — | **FORMULA** — seed S → shuffle+transpose (d4), selector halfwords `(s<<1)+3` (d0), d2 = LE32(S) re-read BE; head phases (0x2B,) / (0x2B,0x48) are per-request VM state the server cannot verify (proven live) | `pure_sign.py` |

## CONSTANT PROVENANCE — nothing is a black-box dump

Rodata finding: T/KB/IV2/K/PI appear NOWHERE in libsigner.so's file image
(packed executable PT_LOAD, filesz=0 — and the constants live as instruction
immediates anyway, never as data).

- **T (256 B)** — generated: `T[v] = AES_SBOX[v] ^ 0x55`; table-free
  `T[v] = L(v^-1) ^ 0x36` (L = AES affine, first row 0xF1), field 0x11B.
  INDEPENDENT CONFIRMATION: the VM trace caught the runtime building T in
  GF(2^8) multiplicative-group order (the AES inverse walk) — two mechanisms
  cleanly separated in the same trace. (`hunt_t2.py`, `T_LAW.md`)
- **F (32 words)** — generated: byte-circulant, sole generator A0 = xtime
  bit-matrix mod 0x11B (unique among all 30 irreducible deg-8 polys);
  A1 = A0+I, A2 = A3 = I. `F_MINV` derived by GF(2) matrix inversion,
  verified 32/32 vs the VM's table. (`hunt_f.py`, `F_LAW.md`)
- **PI (16 B)** — generated: 4×4 ShiftRows-style, rows rotated right by row
  index (offsets 0,3,2,1), verified 16/16. (`hunt_f.py` lineage, in
  `pure_sign.py::_derive_pi`)
- **KB (240 B)** — NOT computed; a literal table embedded in the VM bytecode
  as 481 unrolled `mov w2,#imm16 ; bl OP_PUSH` sites (pc 0x119bb8..0x11c94c;
  240 value/offset pairs + count 240), LIFO-queued into scratch RAM slots
  949..1188, read per-byte by the cipher. `derive_kb()` re-extracts all 240
  bytes from the program image with NO hardcoded key bytes + self-validating
  gates — MATCH 240/240; input-independence proven across seconds.
  (`kb_derive/KB_DERIVED.md`, `kb_derive/derive_kb.py`)
- **IV2 (32 B)** — bytecode immediates (movz/movk, pc 0x105894..0x105b14)
  XOR-0xCC-whitened per byte; de-whitened at runtime by the shared
  0xCCCCCCCC loop (pc 0x12483c..0x124994). FIPS-180-4 anchors self-validate
  the scheme (std IV stored ^0xCC, round constants ^0xAAAAAAAA in the same
  code: `e8208532^aaaaaaaa = 428a2f98`). `derive_iv2()` 32/32.
  (`iv2k_derive/IV2K_DERIVED.md`)
- **K / DK (32 B)** — bytecode immediates stored PLAIN (pc 0x1061e4..0x106464),
  staged raw into the MAC message. `derive_k()` 32/32.
- REPRESENTATION IN THE SIGNER (pure_sign.py / one_click_run/adj9_signer.py):
  `_K256` is GENERATED from the FIPS definition (first 32 bits of fractional
  cube roots of the first 64 primes, exact integer arithmetic); IV2 is stored
  in its NATIVE whitened form (8 dwords ^0xCCCCCCCC) and derived by the
  native's own de-whiten logic; DK stored as its plain immediates; KB as the
  240-B table with its bytecode provenance in the comment. Gate 15/15 after
  the change; live penti NON-ORGANIC again (funnel_pure_run3.log).
- Runtime staging chains proven at instruction level; **3/3 genuine blobs
  rebuilt byte-exact with the derived constants** (iv2k_derive/hunt_iv2k.py).

## THE PURE SIGNER — delivered and live-verified

- `pure_signer/pure_sign.py` — the complete 192-B signer, stdlib only, NO VM:
  **15/15 byte-exact** (3 creditsea golds + 6 penti wins + 6 VM probes),
  ~2–3 ms/signing (VM: 15–25 s). T/F/PI/F_MINV are GENERATED inside it
  (`_derive_aes_tables`, `_derive_pi`, `_invert_rows`); KB/IV2/K stay as
  recorded bytes (their bytecode provenance is above).
- Last blocker solved en route: record[20:24) = **BE32(S)** (d2 = LE32(S)
  re-read big-endian).
- `adj9sign/one_click_run/` — the deliverable package: `adj9_signer.py`
  (rebuilt from the pure law, ~52 KB vs the 546 KB VM file; API
  `configure(campaign_data)` → `sign(params, kind)` → `auth_header(blob)`;
  `--selftest` = 9/9 law + 9/9 full-blob byte-exact) + `adj9_funnel.py`
  (JSON-driven: fresh GAID, click → session → sdk_click → attribution).
  Swap apps = swap `campaign_data.json`. See `one_click_run/README.md`.
- **LIVE: penti NON-ORGANIC twice** with the pure signer
  (`one_click_run/funnel_pure_run1.log`, `funnel_pure_run2.log` —
  VKM Digital Yeni, fresh GAIDs, ~2 ms signings).
- VM fast path (`vm_fast/`): 5/5 byte-exact at 1.4–3.5 s — superseded by the
  pure signer, kept as comparison.

## THE LAST VM LITERAL IS PROVEN FREE (2026-10-01)

Full literal audit of the built signer: every numeric is either wire-format
structure, standard constants (MINSTD/FIPS/AES), proven logic, key material,
or embedded test vectors.  Three native-pool survivors were examined:
  - the 0x40|(i&7) selector cycle — VM behavior VERIFIED by the 6 probes
    (full d0 match); it never reaches the wire (only head16 is serialized)
  - the zero-state seed 123459876 — the native's chosen constant, reachable
    only on a zero seed (2^-32)
  - the head-phase selector literal 43 — **PROVEN FREE**: a live funnel run
    with a NON-POOL value (selector 200) converted NON-ORGANIC
    (one_click_run/funnel_random_phase.log).  The server cannot verify the
    phase.  The one-click signer now generates a fresh random selector per
    signing; the genuine pool literals remain documented reference values.

## OPEN ITEMS

1. **Event claims law** (`activity_kind=event`) — the ONE decoded surface
   gap. No captured event signing exists in any LSPosed log (only
   session/click/attribution). Needs one device capture (manual: LSPosed
   module active, trigger an event, e.g. creditsea's 78v7mj); the unified
   presence-filtered law structure should then slot in immediately.
2. **Creditsea conversions** need 30–60 min spacing per tracker/IP: after
   ~10 test conversions from one IP, BOTH the funnel AND the previously
   proven `run_creditsea.py` returned Organic (A/B-proven environmental, not
   the signature). Morning runs converted 2/2 (Tarsan1).

## COMPRESSED HISTORY (refutations that closed wrong paths)

- Block refuted as: blob self-copy; sha256/sha512/blake2s/md5/sha1 chains
  over 17 compositions; second whitener pass (no consistent selector);
  digest-law-style two-pass MACs keyed by d4/d0/sha256(d4)/S. Dependence
  mapping: block = f(region(S), claims), NOT the second (`probe_runs.py`).
- Digest solved first (7/7) via the two-pass MAC with hardcoded K.
- Head-phase notes: 6/9 genuine captures (0x2B,), 3 penti wins (0x2B,0x48);
  `_step`/bionic constants = Park–Miller MINSTD (16807/127773/2836 mod
  2^31-1), 0x075BD924 = zero-state default seed; `_K256` = FIPS 180-4.

## ALGORITHM CLASSIFICATION (2026-10-01): what is standard, what must stay raw

Verified by direct comparison against the standards/prebuilt modules:

- **The whitening cipher IS AES-256 in structure**, with two proven
  deviations that make it a VARIANT (so no prebuilt AES can emit these
  bytes — pycryptodome/cryptography would produce different output):
    1. S-box == the AES S-box (already known),
    2. MixColumns == FIPS-197 [2,3,1,1] over GF(2^8) mod 0x11B — verified
       500/500 random chunks,
    3. 14 rounds, last round skips MIX, 15 x 16-B round keys (AES-256
       schedule size), CBC from the header IV,
    4. **permutation = INVERSE ShiftRows** (col-row; our PI is exactly
       inverse(AES ShiftRows), not AES's col+row),
    5. **custom key schedule** — KB is NOT the FIPS-197 AES-256 expansion
       of any 32-B key (expand(KB[0:32]) != KB; the standard word
       recurrence matches only 32..46 of 52 transitions = noise).
- **The block hash IS standard SHA-256**, re-chained from the custom IV2:
  the compression is byte-identical to hashlib.sha256 (200 random inputs
  with the FIPS IV injected) and the round constants are the FIPS ones
  (generated from the first 64 primes).  It is hand-rolled ONLY because
  hashlib exposes no custom-IV entry point.
- **The digest already uses the prebuilt module**: two hashlib.sha256
  calls (inner/outer pass of the two-pass MAC).
- Imports are stdlib only (base64, hashlib, json, os, struct, sys, time);
  no third-party crypto anywhere.
