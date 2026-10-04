# IV2K_DERIVED — how the FinEx VM "generates" IV2 and DK

**VERDICT: it doesn't.** Neither IV2 (the custom SHA-256 chaining IV) nor DK
(the digest MAC key) is *computed* from any input. Both are **build constants
embedded in the VM's own bytecode** as unrolled `movz/movk` immediate pairs —
IV2 **stored XOR-whitened with `0xCC` per byte**, DK stored **plain**. The
"generation" the VM performs at runtime is: stage the literals through its
value queue into scratch, copy them into the SHA-256 state slot, and
(de-whiten IV2) with an `eor` loop whose mask is itself a literal
`mov w2, #0xCCCCCCCC`.

This resolves the CRITICAL FACT exactly: an 8-byte window of either constant
cannot appear in the 1.37 MB file because each 32-bit dword lives as two
16-bit halves inside **two separate instruction encodings** (and, for IV2,
the halves are additionally XOR-0xCC images of the real halves). It also
explains why every derivation battery failed: there is no derivation.

Verification: **IV2 32/32, DK 32/32** against `pure_signer/pure_sign.py`'s
recorded constants; all four runtime emit-trace cross-checks OK; **3/3
genuine blobs** (creditsea + penti vectors) rebuilt byte-exact with the
*derived* constants patched into the pure signer. Run `python hunt_iv2k.py`.

---

## 1. The bytecode layout (static, from `_LIB_SPANS` in signer_simple.py)

`hunt_iv2k.py` decodes every 32-bit `movz wX,#imm16` + `movk wX,#imm16,lsl#16`
pair (same Rd, within 16 B) and groups adjacent pairs into blocks:

| block (pc) | n | raw dwords | identity |
|---|---|---|---|
| `0x105894..0x105b14` | 8 | `276e08f9 c38cce10 53641609 debcf976 b6fc215f ef8bfc98 772f01cc 3df99269` | **IV2 ⊕ 0xCCCCCCCC** (unique in text) |
| `0x1061e4..0x106464` | 8 | `690f6094 4dddd984 7db55cd7 d2d576b3 0451723f bcfa92df 62b55f6f ec60f2de` | **DK, plain** (unique in text) |
| `0x108524..0x1087a4` | 8 | `a6c52aab 77ab6249 f0a23fbe 698339f6 9dc29eb3 57c9a440 d34f1567 972c01d5` | standard SHA-256 IV ⊕ 0xCC (1st program) |
| `0x11ef50..0x11fc28` | 64 | `e8208532 db9dee3b …` | SHA-256 round constants ⊕ 0xAAAAAAAA (1st program) |
| `0x125d80..0x126a58` | 64 | same 64 | round constants ⊕ 0xAA (2nd program) |
| `0x126c24..0x126d9c` | 8 | same 8 | std IV ⊕ 0xCC (2nd program) |

Mask literals (`mov wX,#imm`, ORR-bitmask, Rn=xzr) found in text:
`0x10adf8`, `0x10f648` = `#0xAAAAAAAA`; `0x1248a8`, `0x126f2c` = `#0xCCCCCCCC`.

**FIPS-180-4 anchors (self-check, no ground truth needed):** the two 64-dword
blocks XOR-0xAA to the standard round-constant table, and the duplicated
8-dword block XOR-0xCC to the standard IV `6a09e667…5be0cd19` (e.g.
`e8208532 ^ aaaaaaaa = 428a2f98 = K[0]`; `a6c52aab ^ cccccccc = 6a09e667`).
That proves the obfuscation scheme and the extractor's pairing/ordering;
IV2 is then *the remaining unique XOR-0xCC block*, DK *the remaining unique
plain block*.

## 2. The runtime provenance chain (r0 sample run, second=1790625704)

From `digest_law/digest_emits.json` (22 272 emits with step numbers) plus the
instruction-level windows in `prov_*.txt` (this directory):

**IV2** (producer `0x105894..0x105b14`, one `movz; mov; movk; bl PUSH` group
per dword, pushed forward onto LIFO queue `0x5400000000`):

1. steps 540036–540190 — the 8 whitened dwords CAP-swap into MAIN
   scratch `idx 612..619` (reverse order → `MAIN[612]=276e08f9 …
   MAIN[619]=3df99269`); cadence 22 steps/dword.
2. steps 540247–540352 — copied to sink stream `0x5500002000` idx 0..7.
3. steps 558605–558717 — `LENQ(sink,0..7)` + `EMIT MAIN[65..72]` copy loop
   (pc `0x11fe7c/0x11fe90`); cadence 16 steps/dword.
4. steps 558762–559427 — the **de-whiten loop** (pc `0x12483c..0x124994`,
   cadence 87 steps/dword), per dword:
   `POP idx; LENQ(MAIN, idx); PUSH v; PUSH 0xCCCCCCCC (mov @0x1248a8);
    POP mask; POP v; eor w2,w0,w21 (@0x1248e8); PUSH v^mask; POP;
    EMIT MAIN[idx] = v^mask; idx+1; ITERNEXT` (count 7 → 0).
   → `IV2[0] = 276e08f9 ^ cccccccc = eba2c435` … all 8 dwords land in
   MAIN[65..72] as the chaining IV of the block-hash SHA-256 program
   (`IV2 → blk0 → … → blk7 → BLOCK`, per block_law2/LAW.md).

The **same subroutine** de-whitens the standard IV earlier: the whitened
std-IV block is staged at steps 37995–38107 (copy, 16-step cadence) and the
unmasked `6a09e667…` appears at steps 38208–38817 through the identical pc
range `0x12483c..0x124994` — i.e. one shared de-whitener serves the 1st
program's IV and IV2; the 2nd program copy has its own mask site (`0x126f2c`).

**DK** (producer `0x1061e4..0x106464`, same unrolled pattern):

1. steps 8204932–8205089 — per dword `mov w2,#imm16; movk w2,#imm16,lsl#16;
   bl PUSH` with the **raw** halves (e.g. `mov w2,#0xf2de @0x106458;
   movk w2,#0xec60,lsl#16 @0x106464; PUSH @0x106468`) — no mask anywhere.
2. steps 8205502–8205656 — popped via the EMIT loop at `0x1067e0..0x10682c`
   into MAIN `idx 612..619` (reverse), 22 steps/dword.
3. steps 8205713–8205818 — copied to sink `0x5500000000` idx 0..7, then
   staged (steps 8206785–8206897, MAIN top=628 idx 0..7) into the outer
   MAC message `(K^opad)‖opad‖inner`; the inner pass derives `K^ipad`
   from the same values by CAP-swap XOR with `0x36363636` (digest_law).

Side observations (not part of the constants): MAIN[65..72] is reused as
scratch through the run — it also carries a staged device string
(`…S2SE32.28-28-4…`, the `os_build`, steps 541515+) between the sha256(b"")
run (state `e3b0c442…` written at step 310424, 183-step compression cadence)
and the IV2 re-staging; none of it feeds IV2 or DK (both are seed-, second-
and claims-independent — confirmed by block_law2's r2/r3 emit dumps and the
cross-device blob validations).

## 3. Why the file contains neither constant

The on-disk `libsigner.so`'s executable PT_LOAD has `filesz=0` (the real
`.text` is packed; only the memory-dumped spans embedded in
`signer_simple.py` are plaintext). Even in the plaintext `.text`, IV2/DK
exist only as 16-bit immediate halves of `movz/movk` encodings — IV2's halves
further XOR-0xCC — so no 8-byte window (and no 4-byte window of the true
dwords for IV2) can occur anywhere in the file.

## 4. The deliverable functions (stdlib only, in `hunt_iv2k.py`)

```python
derive_iv2()  # -> 32 B: lowest-pc 8-dword mov/movk block, each dword ^0xCCCCCCCC, BE-packed
derive_k()    # -> 32 B: next 8-dword mov/movk block, raw BE dwords
```

Both parse `_LIB_SPANS` from `signer_simple.py` (read-only), decode the
immediates by bit-twiddling (no capstone), and self-check against the
FIPS-anchored blocks before returning.

**Verification (hunt_iv2k.py output):**

```
IV2 32/32: True   DK 32/32: True          # == pure_sign.IV2 / pure_sign.DK
iv2_emits(MAIN[65..72])               OK     # step 558818+ == IV2 dwords
iv2^cc_copy(MAIN[65..72])             OK     # step 558605+ == IV2^cc
iv2^cc_literal(MAIN[612..619])        OK     # step 540036+ == IV2^cc
dk_emits(MAIN[612..619])              OK     # step 8205502+ == DK dwords
end-to-end genuine-blob rebuild: 3/3 byte-exact (derived constants patched in)
```

## 5. Files

| file | purpose |
|---|---|
| `hunt_iv2k.py` | the extractor + `derive_iv2`/`derive_k` + all verifications (run it) |
| `span_scan.py` | exploratory static scanner (superseded by hunt_iv2k.py) |
| `prov_windows.py` | windowed per-step prover (adapted from block_law2/block_prov.py) |
| `prov_8204800_38900.txt/.json` | instruction windows: K staging @8205089, IV2 unmask @558818, std-IV unmask @38208 |
| `prov_539900_540300.txt/.json` | instruction window: the IV2^cc literal staging @539907+ (`movz/movk` + PUSH) |
| `IV2K_DERIVED.md` | this note |
