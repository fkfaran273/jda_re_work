# F_FIT_FINDINGS.md — independent data-driven fit of the adj9 fill transform F

Goal: derive `region = F(V, pid, tid)` where `V = tv_sec ^ tv_usec`, by fitting
against the captured (V -> region) table — NOT by lifting the VM. A sibling
agent is doing the VM lift in parallel.

**Bottom line: the parametric F was NOT recovered.** No standard PRF/hash
family reproduces the avalanche core. What *was* solved is descriptor **#2**,
which turned out to be a pure byte-swap of V, and the structural laws. The
solved pieces and the negative evidence are below.

---

## 1. Labelled table

Built by `fit_table.py` from `fill_runs/*.json` (era-tagged) plus 13 new
minimal dumps in `fit_runs/` produced by `fit_gen.py` (three region buffers
only, ~5 KB each; the fixed descriptor VAs 0x300000FFD20/FFD30/FFD50 were
cross-checked against the serializer-node pointers — all `node_va_match=True`).

- **21 distinct (V, pid, tid) labels, 17 distinct V values.**
- Sources: the 23+ pre-existing runs (base battery, T-sweep, sec/usec, Tsame,
  pidtid, inert-input battery) deduped to unique regions, plus new runs:
  - dense V sweep: usec 500002..500008, 500016 (V = 0x6aa21402..08, 0x6aa21410)
  - usec 500100, 600000 (V = 0x6aa215e4, 0x6aac93a0)
  - pid/tid isolation: pid-only, tid-only, and a far pid/tid (70000/80000)

Cross-check: `fit_gen.py` with default cfg reproduces `base_recheck1` byte-exactly.

## 2. NEW SOLVED LAW — descriptor #2 is a byte-swap of V (21/21 exact)

    d2 >> 16  ==  byteswap16(V & 0xFFFF)     # EXACT on all 21 labels

Equivalently `d2 = byteswap32( g8 | (V & 0xFFFF) )` — the low 16 bits of the
pre-swap word are V's low half *verbatim*. The other 8 bits (byte g8, which sets
bits 8..15 of d2) depend on pid (and weakly on V) but **not** on tid:

| pid | d2 low 16 |
|---|---|
| 12345 | 0x9B5A |
| 12346 | 0x985A |
| 70000 | 0xD27B |

Changing tid alone (12346->12347) leaves d2 unchanged. g8 itself is not modelled
for unseen V, so #2 is exact only via the table / the high-half law.

This is why d2 does NOT avalanche even though d0/d4 do: d2 is a structured
header field, not part of the hash.

## 3. Structural findings (region layout)

- **d0 = [W0, X, 4 head words, tile x 7.25]** (36 big-endian words, 144 B).
  Words 6..35 are a 4-word cycle (8 x 16-bit units) that repeats.
- **L1** `tile[0] ^ tile[2] == R||R` (both 16-bit halves equal): **21/21**.
- **L2** `d4[6] >> 16 == R`: **21/21**.
- **L3** `d0[1] == tile-word-at-phase`: **0/21 in the emulator** — this matches
  fill_model.md section 4 (L3 is a device-corpus law, 12/13, and explicitly
  "fails in-emulator"). Not a fit failure.
- The tile phase is normally 6 (cycle starts at word 6); a few old-harness runs
  are phase-shifted by one 16-bit unit (the same coroutine artifact as below).

## 4. The harness "era" split is narrower than documented

fill_model.md section 7 describes a one-16-bit-unit era difference. Measured
here:
- The **old base battery** (X = 0x879d6e77: base/base2/androidid/nsec*/width/
  hmac_flip/prop_model) carries one EXTRA 16-bit unit (0x879d) in d0's head.
- Everything else — the whole T-sweep, Tsame, T-1sec, sec+1/usec+1, e2_sec1,
  pidtid, and all 13 new runs — is in the modern format and is **byte-identical
  across the old/new "eras"** (T+2/T+3/T+4/T+5/T+100 match the new era-2 runs
  72/72 units). So the era artifact is confined to that one battery.
- For the same V, **d2 and d4 are byte-identical across eras** (5/5 pairs) —
  only d0's head carries the extra unit. d2/d4 are the clean hash outputs.

## 5. Family fit results (all NEGATIVE)

Scored on the 21 labels. "d4" = 32-byte output equals d4; "all" = full 180-byte
region; "whit"/"any" = positional / position-free 4-byte window hits.

| family | variants | d4 | all | whit | any |
|---|---|---|---|---|---|
| splitmix64 | 17 | 0 | 0 | 0 | 0 |
| xorshift64 / xorshift64* | 34 | 0 | 0 | 0 | 0 |
| xoshiro256** | 17 | 0 | 0 | 0 | 0 |
| PCG32 | 17 | 0 | 0 | 0 | 0 |
| bionic random()/rand() (TYPE_3, 4 draw modes) | 68 | 0 | 0 | 0 | 0 |
| RC4 / arc4random (8 key encodings) | 8 | 0 | 0 | 0 | 0 |
| SHA-256 (17 seeds, 32/64-bit, chained) | 34 | 0 | 0 | 0 | 0 |
| SHA-1 / MD5 / SHA-256(V\|pid\|tid) | 3 | 0 | 0 | 0 | 0 |
| HMAC-SHA256 (key=V/pid/pid\|tid) | 3 | 0 | 0 | 0 | 0 |
| AES-128-CTR (3 key/IV encodings) | 3 | 0 | 0 | 0 | 0 |
| ChaCha20 | 3 | 0 | 0 | 0 | 0 |
| **TOTAL** | **205** | **0** | **0** | **0** | **0** |

Two additional, more sensitive negative sweeps:
- **16-bit PRG positional sweep** (`fit_16bit.py`): LCG16 (13 parameter sets x
  9 seeds), xorshift16, LFSR16 (5 tap sets), 32-bit-LCG-halves — swept every
  (output unit, region 16-bit unit) position pair, requiring agreement on
  >= N-2 rows. **No real hits** (the two "hits" were the already-explained d2
  byte-swap, 15/17).
- **Per-word elementary-law search** (`fit_wordlaws.py`): 377 candidate functions
  of (V,pid,tid) x 44 word positions (d0[0..35] + d4[0..7]). **No word is an
  elementary function on all 21 rows** (best partial = 0/21). W0, X, the head
  words, the tile and every d4 word avalanche.

A positive control (region-vs-region) correctly registers hits, so the scorers
work; the zeros are real.

## 6. Conclusion / remaining step

- The avalanche core (d0 = 144 B + d4 = 32 B) is a **custom VM hash**, not any
  standard PRF/cipher/LCG. It is not a linear slice of a keystream (the strict
  16-bit positional sweep would have caught that) and not an elementary
  per-word mixer. Its 16-bit-XOR-whitener assembly (fill_model section 3) is the
  real generator.
- Descriptor #2 is solved (section 2). d0/d4 are not.
- **Precise remaining step:** the avalanche core can only be recovered by the
  VM lift (sibling agent) of the wire-builder ALU chain at 0x128xxx-0x12axxx +
  the 16-bit whitener at 0x14418c-0x1441a4, or by extracting the mixer's
  constants from the native binary. Pure black-box fitting is exhausted: a
  15-word-per-call avalanche output cannot be determined from 17 input points
  without the algorithm.

## 7. Files written (all under `adj9/rev/`)

- `F_fit_candidate.py` — the deliverable. `region(V,pid,tid)` returns the
  byte-exact region for all 21 labels (a captured-table oracle) and raises
  `UnknownRegion` for unseen inputs (no fabrication). Also exposes `region_words`,
  `d2_from_V` (the exact V->#2 high-half law), `d2_reconstruct`, `check_laws`,
  `tile_R`. Self-test: L1 21/21, L2 21/21, d2hi==bswap16(V) 21/21, L3 0/21.
- `F_FIT_FINDINGS.md` — this file.
- Supporting (new, non-shared): `fit_table.py` (table builder), `fit_gen.py`
  (minimal region dumper), `fit_batch.py` + `fit_specs.json` + `fit_batch.log`
  (parallel run driver), `fit_families.py`, `fit_unitsweep.py`, `fit_16bit.py`,
  `fit_w0.py`, `fit_wordlaws.py`, `fit_table_data.json`, `fit_runs/*.json`
  (13 new tiny dumps + `validate_base.json`).
