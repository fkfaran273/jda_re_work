---
title: WALL_A_SLICE_135
---

# SLICE 135 — LENQ proves seg27's descriptors are memory-built (and #2 IS cd9d3a91)

## 0. What the LENQ plane shows (`lenq_probe` → `lenq4_probe`, `app_dump.json`)

* Seg27 is the ONLY signing-like segment (36w+48w co-occur nowhere else);
  11 distinct singles total, 9 of them inside seg27 itself.
* The VM reads descriptors as **streams**: stream `..4bc0` walks the #0
  tile (`fdda97ce b559bc7d 4f8635e7 c61cd669` at slots 0-3, then the tile
  again at 5-7, 9-11, 13-15…); streams `..cf0`/`..4950` walk #4
  (`00010201 00080801 08882281 4a0962c8` at slots 0-3, then the tail
  `6898201b 72ca1951 7345899a f3fba7a0` at 4-7); stream `..36c0` reads the
  claims head (`4b6c6341` at slot 0).
* The TRUE #2: stream `..3b70` = **1 read, slot 0, `cd9d3a91`** — the #2
  descriptor as the VM sees it — PLUS 4 more reads of the same value at
  slot 81 of the main stream `..4380`. So `cd9d3a91` IS read as a
  descriptor (5 LENQ reads), even though it never crosses EMIT.
* 1-read snapshot streams also cover `#7=00000183` (`..3d50`), `0x90`
  (`..16b0`), and two zeros (`..3570`, `..3cc0`) — the singles family.
* 233 stable `(stream,slot)→value` slots on the main stream; its top
  values are queue indices (`0xc9/0x89/0x69/0x59` = 201/137/105/89), i.e.
  VM queue positions, not data. Memory-sourced (never emitted) values: 45
  distinct — `0x20202020` (ASCII spaces, x11) and Java-signature fragments
  (`e3b0c442 98fc1c14 9afbf4c8 996fb924` = sha256("") head, x1 each).

## 1. What this corrects

Slice 134 §1 ("`cd9d3a91` is NOT #2") is **retracted as a mechanism claim**:
the FinEx 44/48 result stands (that input set does not reproduce the blob),
but the reason is NOT "wrong #2". The value IS the descriptor the VM reads
— so the 44/48 must come from another slot in that arm (prime suspect: the
17-word stream I fed as nothing / the `#7`/claims-length handling for the
97-word click claims, or a misassigned #10 tail word).

## 2. Next (concrete)

Re-run the seg27 FinEx arm with (a) `#2=cd9d3a91` KEPT, (b) the claims
length variants (`#7` = 387 unpadded vs 388 padded; `#10` = 97w as-is vs
96w+pad), and (c) the tail singles (`0x19`/`0x1de` family) in slots #5/#6 —
the only remaining degrees of freedom in an otherwise fully-labelled
signing. The LENQ walk above gives the exact slot each descriptor occupies,
so misassignment is now checkable rather than guessed.

## 3. Artifacts

* `rev/lenq_probe.py`+.log, `rev/lenq2_probe.py`+.log,
  `rev/lenq3_probe.py`+.log, `rev/lenq4_probe.py`+.log
* `rev/app_dump.json` (2.16 MB — EMIT 18965 + LENQ 53172, run7)
* `device/appcap_run{2..7}.log` (guard-timing series)
