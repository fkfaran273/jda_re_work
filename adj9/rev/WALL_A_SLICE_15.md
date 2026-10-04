# Wall A — slice 15: differential localization DEAD — diffusion is total (2026-09-11)

`diff_masks.py` over `probe_blobs.json`: 4 runs × 10 controlled calls
(real / A1∼A2 same-in / B1∼B2 h-zero / C1 h-flip / D1∼D2 mapX / E lv30 /
F lv31), all 192 B.

## Masks (body dwords /48, header bytes /16)

| pair | run0 | run1 | run2 | run3 |
|---|---|---|---|---|
| A1∼A2 (identical input!) | 48/48, 16/16 | 48/48, 16/16 | 48/48, 16/16 | **44/48, 0/16** |
| B1∼B2 (H=0, identical) | **44/48, 0/16** | 48/48, 16/16 | 48/48, 16/16 | 48/48, 16/16 |
| D1∼D2 (same mapX) | 48/48 | 48/48 | 48/48 | 48/48 |
| A∼B (H: synth→0) | 48/48 | 48/48 | 48/48 | 48/48 |
| A∼C (1-bit H flip) | 48/48 | 48/48 | 48/48 | 48/48 |
| E∼F (level 1 dw) | 48/48 | 48/48 | 48/48 | 48/48 |
| B1×B1 cross-run | 48/48 | — | — | — |

## Verdicts

1. **No pair type leaves any body dword stable** (within-second: 44/44;
   cross-second: 48/48) — not even a 1-bit H flip (C1) or a 1-dword level
   change (E/F) localizes. Field→region mapping by stability is impossible:
   the LENQ-feedback diffusion is total. Statistical shortcuts are closed.
2. **Two new same-second pairs** (B1∼B2 run0, A1∼A2 run3: header 0/16,
   body 44/44) join the blobset pair (slice 7) → 3/3 confirm body entropy =
   ns+env, never rand. The `15/16` rows (run1 B, run2/3 real∼F) are
   cross-second chance matches, not structure.
3. The B-corpus (H≡0 known!) still can't be forward-matched: 7 unknown
   payloads + ns stamps + merge tail (EMIT grow/`0xbb548`) remain. It stands
   ready as the simplest resimulation target (8 zero dwords) for R4.

## Path from here (unchanged, now exhaustive of alternatives)

Direct (exact) only: stream-struct resimulation with real bytes (R4: #0
layout, #2/#3/#6/#7/#8/#10 + ns) + EMIT/`0xbb548` lifts. Ruled out:
raw containment (H, cert-SHA1, backups — 0/38), structural counts/XOR
(0/38), heap recovery (0 hits), stability masks (this slice). No key ever
needed; one device run (R2-pattern) supplies real bytes cheapest.
