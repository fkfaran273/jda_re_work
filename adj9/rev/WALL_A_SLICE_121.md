---
title: WALL_A_SLICE_121
---

# SLICE 121 — byte-order correction, and the sections that ARE the blob

## 0. Two corrections that invalidate earlier conclusions

**(1) LENQ/EMIT values are big-endian dwords.** The VM does `LDR w8,[mem]` (little-endian)
then `REV w3,w8`, so every value that crosses the hooks is the **byte-swapped** dword.
My slice-118/119 searches compared **little-endian** dwords of the blob/descriptors, hence
"blob dwords in EMIT: 0/48" and "descriptors not in the trace 0/36" were **artefacts of
byte order**, not facts. Corrected searches (this slice) show the blob and the section
words *are* in the captured plane, word for word.

**(2) `rev/fin118.py`'s 0/4 is explained:** it built descriptor bytes with
`struct.pack("<I", v)`, i.e. byte-swapped relative to the plane. Its arms were wrong for
that reason (they also all step-capped, which the corrected arms do **not** — see §3).

## 1. The decisive structure: length-prefixed sections

LENQ plane of the labelled mint (62 510 reads), 658-slot stream `…c99364d0`:

```
slot 321 000000a4
slot 322 00000027
slot 323 00000090     <- len_B = 144
slot 324 00000024     <- len_dw = 36
slot 325 3aa06f11     <- blob[0]  (BE)      ...
slot 360 ...          <- blob[35]           (325+36 = 361)
slot 361 b4c11b83     <- blob[36]
slot 372 0663b794     <- blob[47]
```

`len_B = 144 = 4 × len_dw = 4 × 36` ✓, and the 36 words that follow are **`blob[0..35]`
verbatim**. This is the same `[len_B][len_dw]` record shape that slice 118 saw as a
"36-slot stream with a `0x90` length word" and that `fin_descs.json` calls **`#0`** —
i.e. **the "descriptors" are length-prefixed output SECTIONS, not inputs.**

The arithmetic closes exactly: `144 B + 48 B = 192 B` = the blob, so the body is assembled
as **two sections** (36 dwords + 12 dwords), each introduced by its `[len_B][len_dw]` pair.
That is also what `PUSHS/POPS` mean in `vm_exec.py` ("push section-start").

## 2. Consequence for the region question

* `fin_descs.json`'s `#0` (36 words with a repeated 16-byte tile) is a **section of the
  assembled body** — which is why feeding it to FinEx reproduces the blob (it *is* the
  answer, not an input).
* Our captured 36-word tile stream (`…94c4f0`, tile ×7) is a section of *our* signing in
  the same way; our blob's own section-1 is `blob[0..35]`.
* Therefore the earlier framing "derive `#0/#2/#4` from (claims, H, second)" was aiming at
  the wrong object: those values are **outputs**. The genuine inputs are whatever the
  builder consumes before the VM runs (map + H + sdk + the small control words `#2/#5/#6/#7`
  and the constants `#8/#9`).

## 3. The corrected FinEx arms (real results, not artefacts)

`rev/wh_fin.py` — descriptors rebuilt from the captured plane with **correct byte order**,
`#8 = CONST8`, `#9 = CONST9`, `#10` = the 84-dword claims stream, `#7 = 0x150` (=336 =
claims length), `#2 = 0x8833afb3`:

```
[EMIT] 36-word streams by tile reps: [(7, '970160'), (1, '858992')]   <- #0 identified
[EMIT] singles: 8833afb3, 00000150, 00000010, 00000000
[EMIT #5/#6 swap=False] status=exit-clean steps=10520246 diff 44/48
[EMIT #5/#6 swap=True ] status=exit-clean steps=10519666 diff 44/48
[LENQ] 36-word streams by tile reps: [(7, '94c4f0'), (1, '9312b0')]
[LENQ] singles: 8833afb3, 00000150, 00000000, 00000000
[LENQ #5/#6 swap=False] status=exit-clean steps=10520131 diff 44/48
[LENQ #5/#6 swap=True ] status=exit-clean steps=10520131 diff 44/48
=== RESULT: 0 byte-exact arm(s) ===
```

Note what changed: with the corrected byte order **every** arm terminates cleanly (≈10.52 M
steps, no step-cap), where the byte-swapped arms ran to the 20 M cap. Routing is accepted;
only the body differs — exactly what §2 predicts (the section values are *outputs*, so
substituting them as *inputs* cannot reproduce the body). The 44/48 pattern = the 4 header
dwords match (Random3(second) is computed identically) and all 44 body dwords differ.

## 4. Where this leaves the pure-Python question

| item | status |
|---|---|
| header law | done; a second inverts **uniquely** (this round: 1789894178, verified against the device clock 1789894527) |
| claim laws | done (session byte-verified; attribution derived) |
| blob ↔ captured plane | **done**: blob and its sections appear word-for-word in the LENQ/EMIT plane |
| sections | **done**: `[len_B][len_dw]` + content = the assembled body (144 B + 48 B = 192 B) |
| inputs to the builder | **still the target** — read them where the builder writes them (a memory hook on `sub_95fc4`/`sub_bb548`), not from the EMIT/LENQ plane |
| final proof | unchanged: device-free mint + send on a fresh clicked GAID |

## 5. Artifacts

- `rev/wh_out.json` (2.5 MB) — LENQ (62 510 reads) + EMIT (21 654 writes) + blob + map + H of a labelled mint
- `rev/agent/whlive_src.js` → `whlive.js`; `device/whlive_run.py`
- `rev/wh_an.py` + `wh_an.log` — plane census, tile detection
- `rev/wh_fin.py` + `wh_fin.log` — corrected-byte-order FinEx arms
- `rev/rec_scan.py` + `rec_scan.log` — the `[len_B][len_dw]` section discovery
- `rev/mem_scan.py` + `mem_scan.log`, `rev/dmp_out.json` — builder-argument windows (slice 120)