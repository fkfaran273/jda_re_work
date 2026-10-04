# SLICE 146 — the builder is a pure function; per-call variation = the C rand() stream

Date: 2026-09-23. Agents: state-walk (`rev/state_walk.md`), Unicorn emulator
(`rev/emu_8d6f4.py`, `rev/emu_findings.md`), corpus analyst (`rev/corpus_seed.md`),
Java dumper (`device/java_dump/REPORT.md`), JNI-name decoder (`rev/jni_names.md`),
Java decompiler (`rev/java_signer.md` + `rev/java_src/`, 128 files).

## 0. Headline

The signing blob's builder is a **pure function of its inputs** — proven by
emulation: two byte-identical runs (13,626,815 instructions, identical ctx,
identical full memory image, identical 251-call JNI sequence). There is no
hidden entropy inside the builder. The per-call variation of descriptors
#0/#2/#4 (which differs even for identical claims+second) is the **advancing
C-library `rand()` stream**:

```
nOnResume (0xda4b0) → 0xdafe4 → 0x12cb74: bl time @0x12cbbc → bl srand @0x12cbc0
                                  (srand(time(NULL)), once per resume)
wire builder consumes rand(): bl rand @0x12a2fc and @0x12a31c (append via 0x147630)
```

Bionic semantics: `srand→srand48`, `rand→lrand48` (31-bit). The stream is NOT
reseeded per signing — so same-second, same-claims signings draw different
values (different stream position). These are the only rand/srand sites in the
library; no tid/pid/counter feeds the wire (the ±1 ns clock sensitivity the
emulator measured lands in anti-tamper words ctx+0x718/+0x788, not the wire;
stack-guard words are per-process, not per-call).

## 1. Full input map of the region (all offline-computable in principle)

| input | source | offline? |
|---|---|---|
| 13 device property strings (manufacturer, brand, model, device, display.id, fingerprint, build.type, hardware, bootloader, build.user, host, cpu.abilist, +1) | `__system_property_get` chain (0xe2948; ctx+0x00..0x68, malloc'd copies) | yes — from the request's own device fields |
| widthPixels / heightPixels | DisplayMetrics via GetIntField (ctx+0x60/0x64) | yes — request display params (moto g42: 1080×**2237**, not 2400) |
| package name | getPackageName (0xbf588/0xbf6c8) | yes |
| APK cert SHA-1 | signatures/signingInfo → toByteArray → SHA-1 (consts 0x3610..) | yes — constant per app build |
| claims bytes + 32-B HMAC H | Java passes ONLY this byte[] into nSign | yes — we compute both |
| per-call words (W0, tile, #2, #4) | mix(rand() stream, per-site constants — 474 mov/movk sites) | **yes iff the draw-count/mix is recovered** (in progress) |

## 2. Corrections to earlier slices

* `Signer.sign([B)[B` does NOT exist in this build (R8; the class-string was an
  orphan in the string table). Real surface: `sign(Context,Map,String,String)`.
  Signer has **no int fields at all** — the GetIntField targets are
  **DisplayMetrics.widthPixels/heightPixels** on an object the native side
  fetches itself. (`rev/jni_names.md`, `device/java_dump/REPORT.md`)
* All prior .data string VAs were shifted 0x1E0 low (program headers say
  file_off = VA−0x8000, not −0x7E20) — the "multi-pass obfuscation" was an
  artifact; each blob has ONE XOR key, its decryptor sits in its consumer.
  (`rev/jni_names.md`, corrected table `rev/blob_table_true.log`)
* ctx+0x08 is the **manufacturer pointer**, not claims-length (claims len is
  descriptor #7). sub_8d6f4 = 0x8d6f4..0x95fc4 (8756 insns), TWO entries
  (0x8d6f4 build; 0x956e0 destructor freeing the 13 strings); 296 dispatch
  tags. (`rev/state_walk.md`)
* `adjust_keys.xml` does not exist on API≥23 devices (the RSA-wrapped software
  key is an API 18–22 fallback, handled entirely in native).
* Region corpus: S0/S1/S2 in desc_det_result.json are byte-identical duplicates
  of rows 7/8/9 — the corpus is 10 unique rows, not 13.

## 3. Corpus laws (new instrumentation: the oracle probe B1~B2)

* B1~B2 (identical map, same second, H=0, identical 16-B headers) differ in
  175/176 body bytes ⇒ the per-call entropy is in **descriptor fill**, not the
  header or merge — directly consistent with the rand-stream model.
* The one real constant law on the region: tile satisfies
  **U[2]^U[0] == R‖R** (both 16-bit halves equal), 13/13 rows; R (16 bits/call,
  per-call even at the same second) is the first brute-forceable quantity.
* Fresh 3-signing corpus captured (one process, UI-triggered addToCart/
  productView events): canonical + H + 192-B blob + header-inverted seconds
  1790106110/176/196 (`device/java_dump/signings_extract.json`).
* No constant XOR component on the wire (body^H, body^canon, body^header,
  body^sec — all differ across signings; zero dictionary hits) — the wire is
  whitened by the rand mix.

## 4. What this means for the goal

If the draw-count per signing is constant (fixed by code) and the mix() is
recovered, then **every blob is reproducible offline in pure Python**:
`srand48(resume_second≈signing second) → advance(k) → mix → region words`. The
server side can do the same (it knows the SDK's constants and the request's
second) — which would finally explain slice 144's booking gate (crafted blobs
with random regions fail the recomputation) and slice 143's byte-match
observation (the app's own bytes ARE the recomputation, matched exactly).

## 5b. Pair-XOR validation — the anchor was NOISE; the opcode pin stands (2026-09-23)

Static disasm (orchestrator): the wire builder's rand opcode at 0x12a2fc/0x12a31c
is **pair-XOR** — `bl rand` (PLT 0x148d10) → push → `bl rand` → push → pop → pop
→ `eor w2,w0,w21` @0x12a368 → push. Primitive semantics proven by
`emu_helpers.py` (Unicorn): 0x147630=push(prepend), 0x147a20=swap-elem-n-with-top,
0x14784c=dup-over, 0x147734=pop.

An initial membership hit — row 7 W0 = `lrand48_214220 ^ lrand48_214221`
(srand48(1789240512), pair k=107110), ~200× above the chance of that specific
test — was **falsified as noise** by the full validation (`l48_pairs.py`,
`l48_pairs.log`, `l48_sweep.md` §Pair-XOR validation): Pass A 6010 seed-cells
sit exactly on the chance line (275 pure vs 305.6 expected; no cell clustering);
no stride g0 over g=1..256; cross-signing continuation for rows 7/8/9 (same
process, same second) fails with zero hits and broken k-ordering.

⇒ the region words are NOT lrand48-after-srand48(signing-second) at any
recoverable position ≤10M draws. Live explanations: seed ≠ second; rand() not
bionic lrand48 in-process; interleaved consumers; or the pair-XOR opcode is not
on the signing path at all. The deciding instrument is the logged-rand
emulation (in flight).

* **l48 empirical sweep (`lcg_run.log`, `corpus_seed_lcg.log`, `l48_sweep.py`):
  NEGATIVE.** Inverted-membership sweep of simple mixes (r^C, C−r, r−C,
  (r*C)>>32, r*C, pair-halves) over the 474 site constants, seeds
  second−0..−600, 50k draws, all region words + the fresh-3: only chance-level
  scatter (~130 isolated "hits", no cross-row seed/k consistency, no
  constant draws-per-signing gap g; header words — provably NOT lrand48 —
  "hit" at the same rate = the hits are noise). ⇒ the rand→wire relation is
  NOT a simple near-second-seeded mix: either the stream is seeded/consumed
  differently (extra consumers, different seed source) or the mix is compound
  (multi-op). Deciding instruments: logged-rand emulation + static pin (below).
* **VM opcode map (interim, `_vm_entry.log`, `_vm_loop.log`, `_vm_arith.log`,
  `vm_*.py`):** the whitening machine's ALU opcodes live at 0x128xxx–0x12axxx
  (`add w2,w0,w21`, `mul w2,w0,w21`, `eor w2,w0,w21` families), each producing
  w2 consumed by the append primitive `0x147630(ctx, value, idx)`; the emit
  serializer is 0x146ed8. `cert_signer1.der` extracted (the APK cert, for
  #9 verification).
* Still open: draws-per-signing count + consumption order; exact mix; the
  emu replay of a captured signing (quota-blocked, prompts preserved here).

## 6. Artifacts

`rev/state_walk.md`, `rev/emu_8d6f4.py` + `emu_findings.md` + `emu8_*.json`,
`rev/corpus_seed.py/.log/.md`, `device/java_dump/{REPORT.md,signings_extract.json,
adj9_capture_run*.log}`, `rev/jni_names.md`, `rev/blob_table_true.log`,
`rev/emu_be168.py`, `rev/java_signer.md`, `rev/java_src/` (128 decompiled files).
