# d2 → body dependency map (and d4[0] / d4[4]) — FinEx probe results

Row 7 base: second 1789240512, d2 = `0xfb1a8296`, d4[0] = `0x00100400`,
d4[4] = `0x0025c852`. Base run reproduces the captured pair_h3 i=7 blob
byte-exact (**48/48 words** — setup validated).

Scripts: `d2_dep_probe.py` (13 FinEx runs) → `d2_probe_result.json`;
`d2_dep_analyze.py` → `d2_probe_analysis.json`; `d2_mech.py`, `d2_lenq.py`,
`d2_wire.py` (instrumented mechanism traces → `d2_mech_*.json`, `d2_lenq.json`,
`d2_wire.json`, `d2_wire_div.json`).

## Dependency map (blob = 48 BE words; 0-3 header, 4-47 body)

| input | body words affected | transform |
|---|---|---|
| **d2** (1 word) | **8-47 (40 words)**; 4-7 NEVER move (verified in all 6 probes) | **data-flow avalanche** — any single-bit or multi-bit change moves all 40 words; identical execution path |
| **d4[0]** | **none** (0/44) | **dead input** — value read by the VM but never consumed (bit0/bit16/bit31 flips all no-ops; also full-invert, dep_probe) |
| **d4[4]** | **4-47 (44 words)** — via bits 16-31 only | **control-flow predicate** — blob depends only on `signed(int32 d4[4]) < K`, K ∈ (0x0024c852, 0x00250000] (K = 0x250000 fits every probe) |

## d2 probes (vs base blob)

| probe | new value | moved words | XOR-delta HW (mean) |
|---|---|---|---|
| ^0x1 | fb1a8297 | 40 (8-47) | 16.2 |
| ^0x2 | fb1a8294 | 40 (8-47) | 16.6 |
| ^0x80000000 | 7b1a8296 | 40 (8-47) | 15.9 |
| +1 | fb1a8297 | 40 (8-47) | 16.2 |
| 0 | 00000000 | 40 (8-47) | 15.7 |
| 0xFFFFFFFF | ffffffff | 40 (8-47) | 16.0 |

- NOT bit-local: a single bit flip in ANY of bits 0/1/31 moves every word 8-47.
- XOR-delta Hamming weight ≈ 16/32 and ADD-delta patterns are random-looking →
  **full avalanche**.
- Affine model `word_i = A_i*d2 + C_i (mod 2^32)` rejected 0/40 on all four
  predictions (^2, ^2^31, d2=0, d2=0xffff).
- Internal consistency: base bit0 = 0 → the ^1 and +1 probes produced
  byte-identical blobs (deterministic harness check, PASS).
- d2=0 vs d2=0xFFFFFFFF produce different blobs (the map is not degenerate).

## Mechanism (instrumented FinEx runs)

1. **Entry**: the descriptor field loop at `pc=0x10017c` EMITs every descriptor
   word exactly once into its dump stream `0x5500000000 + pos*0x1000`
   (pos = VA_ORDER index; d2 is VA_ORDER pos 4 → stream `0x5500004000` n=0).
2. **d2 consumption**: exactly ONE LENQ read of the d2 dump stream
   (`pc=0x129bcc`, wire op 865), re-EMITted verbatim into the MAIN stream
   `0x5450001000` at n=81 (`pc=0x129be0`), then read/PUSH/POP'd in a loop
   (wire ops 52855+, `pc=0x104a5c/0x104a6c/0x104a80`) into the value-queue
   pipeline.
3. **No branch on d2**: base vs d2^1 wire logs have identical length
   (1,566,871 ops) and identical op sequence — 227,695 ops carry different
   VALUES (PUSH 84,025 / POP 102,764 / LENQ 27,093 / EMIT 13,813). Steps,
   emits, qops, CAP-swap counts all identical. d2's influence is pure
   **data-flow mixing** through the queue arithmetic and value-indexed CAP
   swaps → the observed avalanche.
4. **d4[4] consumption**: all 8 d4 words LENQ-read at `pc=0x128cc4`. Downstream,
   a signed compare of the copied d4[4] value switches the program onto a
   different path: short path = 9,871,985 steps / 22,272 emits; long path =
   16,117,703 steps / 35,824 emits.

## d4[4] probe table

| d4[4] value | blob vs base | class |
|---|---|---|
| 0x0025c852 (base) | — | short path |
| base^0x1 = 0x0025c853 | IDENTICAL | short (low half invisible) |
| base-1 = 0x0025c851 | IDENTICAL | short |
| 0x00250000 | IDENTICAL | short |
| base^0x10000 = 0x0024c852 | all 44 words move | long |
| base^0x80000000 = 0x8025c852 | all 44 words move, **byte-identical to the ^0x10000 blob** | long |
| base^0xFFFFFFFF = 0xffda37ad (prior dep_probe) | all 44 words move | long (signed negative) |

⇒ only ONE bit of entropy from d4[4] reaches the blob: the boolean
`signed(int32) < 0x250000` (any K in (0x0024c852, 0x00250000] fits; unsigned
compare is ruled out by the bit31 probe acting like bit16, not like base).

## Invertibility (for the body decoder)

- **d2 → words 8-47**: deterministic, same-path data mixing; no per-word closed
  form (affine rejected). Recovering d2 from a body requires inverting the VM
  dataflow (symbolic execution along the single value path) — not a per-word
  lookup. Forward direction trivially reproducible by minting.
- **words 4-7 are d2-free** — decodable without resolving d2.
- **d4[0]**: unrecoverable BY CONSTRUCTION (never affects the blob) — and it
  needs no decoding.
- **d4[4]**: recoverable only up to the branch class (1 bit). Given the other
  descriptors, a blob reveals which side of the 0x250000 threshold d4[4] was
  on, nothing more.

## Caveats

- All probes ran on row 7's other descriptors; the *set* of affected words
  (8-47 for d2) matches the earlier device-descriptor flip study
  (`fill_runs/body_map.json`), so the boundary is not row-7-specific.
- The exact threshold constant inside (0x0024c852, 0x00250000] was not pinned
  further; only its class behavior matters for the blob.
