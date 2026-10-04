# digest_law — SOLVED: the 32-byte digest (blob[160:192), sink words 40..47)

## The law (pure Python, no VM)

```python
K    = bytes.fromhex("690f60944dddd9847db55cd7d2d576b3"
                     "0451723fbcfa92df62b55f6fec60f2de")   # 32-B VM constant
IPAD = b"\x36" * 32
OPAD = b"\x5c" * 32

inner  = sha256((K ^ IPAD) + IPAD + blob[16:160))    # 208-byte message
digest = sha256((K ^ OPAD) + OPAD + inner)           #  96-byte message
```

`digest = blob[160:192)` (NOT whitened). `blob[16:160)` is the whitened record
already produced byte-exactly by `whiten_decoder.whiten_forward`.

Validation: **7/7 byte-exact** — the controlled `streams_sample0` run and all
6 genuine winning blobs (different devices, seconds, claims).
Implementation: `digest_law.py::predict_digest(body)`.

This is a custom two-pass SHA-256 MAC. It is NOT standard HMAC (which would be
`sha256((K^opad)||sha256((K^ipad)||m))`): the raw pad block is hashed a second
time after the keyed block, which is exactly why `hunt_quick.py`'s standard
HMAC/sha compositions were refuted.

## Mechanism in the VM (from full_emit_trace + windowed provenance)

1. `K` is pushed onto LIFO queue `0x5400000000` by an UNROLLED program block:
   8× `mov w2,#imm16; movk w2,#imm16,lsl #16; PUSH` — the 8 dwords are literal
   code immediates (steps 8204932–8205089 in the sample run; evidence kept in
   `evidence_k_movmovk.txt`). K is therefore constant per VM build, NOT
   derived from (claims, second, S). Proof: the 6 genuine blobs from different
   devices/seconds all validate with the same K.
2. Inner message assembly on MAIN stream `0x5450001000`, words 0..51
   (word 0..7 = K^ipad written via CAP-swap XOR of K with 0x36363636 in the
   queue, words 8..15 = ipad, words 16..51 = whitened body), copied to words
   73..136 with SHA-256 padding (`0x80000000`, zeros, bit-length 0x680).
3. The VM's SHA-256 program stages: K-constants at words 1..64, the standard
   IV `6a09e667 bb67ae85 ... 5be0cd19` at words 65..72 (output overwrites the
   IV slot), message at words 73..136. It runs ~272k VM steps per 64-B block
   (inner = 4 blocks ≈ 1.09M steps, outer = 2 blocks ≈ 0.54M steps).
4. Inner output ("hashB" in the analysis) → words 65..72 → sink words 0..7
   (scratch) → re-staged as words 16..23 of the outer message
   `(K^opad) || opad || inner` (words 0..23, copied to 73..96, padded to
   word 104, bit-length 0x300).
5. Outer output → MAIN words 0..7 and 377..384 → **sink words 40..47** as the
   final 8 EMITs of the whole run (last-write-wins; the sink's earlier
   incarnations — ASCII claims text, whitened-body staging, HMAC staging —
   are all overwritten by the final assembly at sink words 0..47).

### Dependence (probes r0..r5)

All 8 digest words fully avalanche on `second` (+1 s), seed (d0/d2/d4 region),
and claims — consistent with the law: the body (whitened record) contains the
header(S), S, and the 9-dword block, all of which depend on those inputs.
K itself is constant, so `predict_digest` needs ONLY `body = blob[16:160)`.

## Remaining gap for pure_mint (outside this directory)

Only the 9-dword block `record[46:78)` (block_law/) plus the record assembly
(already closed-form) stand between `forward_known.py` and a full no-VM mint.

## Files

| file | purpose |
|---|---|
| `digest_law.py` | the law + 7/7 validation (run it) |
| `analyze_trace.py` | replay/inspect the emit trace (tail/snap/find modes) |
| `digest_trace.py` | pass-1 emit spy with VM step numbers → `digest_emits.json` |
| `digest_prov.py` | pass-2 windowed per-step provenance runner |
| `k_spy.py` / `k_spy_hits.json` | full-run spy that located the K pushes |
| `evidence_k_movmovk.txt` | provenance text showing the mov/movk K immediates |
| `test_groups.py`, `find_prefix.py`, `k_hunt.py` | hypothesis tests that pinned the chain |
| `digest_emits.json` | 22,272 emits with step numbers (sample0 run) |
