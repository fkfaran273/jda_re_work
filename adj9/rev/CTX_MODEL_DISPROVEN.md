# adj9 — the ctx/fold model is DISPROVEN (2026-09-11)

## Why this matters
The 09-10 working model said: `nSign` builds a 0x148-byte "ctx" on the stack,
seeded from one 32-bit `/dev/urandom` value, and the 176-byte body is the output
of the `fold16`/`driver` machinery run over that ctx. **That is wrong.**

## What was actually done (new this session)
1. **Fixed the root memory-capture pipeline.** Three separate real bugs:
   - `toybox dd` silently mis-parses a hex `skip=` → must use
     `skip=<decimal> iflag=skip_bytes`; all address maths via `printf %d 0x..`
     and `awk` (32-bit shell overflows; `awk` has no `0x` literals).
   - the `---p` guard page precedes each `rw-p` stack body — reading it gives
     `I/O error`; select `rw-p` only.
   - the sampler counted *idle* iterations in its pass counter, so the `MAXP`
     break fired the instant the app appeared (only 1 real pass). Count active
     passes only.
2. **Found a deterministic signing trigger:** delete
   `/data/data/com.penti.app/files/AdjustIoActivityState`, then launch → fresh
   Adjust session → a genuine `nSign` within seconds (verified 8→10→14→16→26).
   No more guessing when the app signs.
3. **Rebuilt the LSPosed module with a tight burst** (`Hook.java`,
   `BURST_ITERS = 40000`, a loop of `callNSign(...)` on the thread named
   `adj9-oracle`, inserted right after `probe_start`). Built with
   `adj9/module/build.sh`, installed with `adb install -r`.
4. **Sampled the oracle thread while the burst ran.** TID located with
   `grep -l adj9-oracle /proc/PID/task/*/comm` (TID 17126). 25 dumps of its
   full stack, plus a 587 MB sweep of *all* `rw-p` regions ≤ 32 MB.

## The evidence
| probe | result |
|---|---|
| `ctx_wrapper 0x143794` return addr on any stack | **0 hits** |
| `ctx_init 0x1437ec` return addr (`0x1437c8`) | **0 hits** |
| `get8random 0x13e0e4` return addr (`0x1437bc`) | **0 hits** |
| `shuffle16 0x143c88`, `driver 0x144214`, `fold_word 0x1441e4` | **0 hits** |
| ctx anchor (16 u16, high-bit positions = perm of 0..15) in 587 MB + 479 MB | **0 hits** |
| module oracle `A1~A2 (same in)` | `n_diff=191` of 192 |

The anchor's false-positive rate is ~2^-92, and the scanner was validated
against a synthetic ctx (found at exactly the injected offset). So "0 hits" is
a real absence, not a broken detector.

`A1~A2 n_diff=191` confirms the body **is** fully re-randomised per call — a
per-call random source exists. It simply is not this code.

## Conclusions
1. `ctx_wrapper`/`ctx_init`/`shuffle16`/`fold16`/`driver` are **not** executed
   during signing. They belong to a separate consumer — most plausibly the
   obfuscated string/table decryptor (`fold_word` has ~47 callers, matching a
   string-decrypt sweep).
2. `get8random 0x13e0e4` — the only `/dev/urandom` reader reachable from
   `ctx_wrapper` — is never called during signing, so the "one 32-bit urandom
   seed feeds the body" claim is void.
3. The `nsign_in`→`nsign` gap of ~730 ms is **the module's own logging**
   (7883 `jca_*` events), not native execution time. The native call is ~1 ms.
   This is why random stack sampling could never catch anything.
4. Everything from 09-10 that does **not** depend on this code still stands:
   the 16-byte header law, `adj_verification`, the Java→native pipeline, the
   `H` = `HMAC-SHA256(key2, canonical_map)` construction, the TEE `key2`
   finding, and the SAZ live-traffic validation.

## Revised next step
Identify the real body-construction path from the code that *is* live during a
signing. Two concrete leads, both cheap to chase now that the trigger + burst +
root-sampling harness works:
- the 2048-byte `read(fd, buf, 0x800)` at `0xe3c44` (the only other entropy
  read in the library) — resolve its `openat` path register (`x22`);
- the one-shot SHA-1 at `0xe57c` in function `0xe3c4` (sole caller of the SHA-1
  init `0x12e5f4`) — this is a plausible MAC/compression step for the body.

Then repeat the burst experiment, but histogram **code-aligned** return
addresses (4-byte aligned, not persistent data pointers) to walk the true call
chain, and re-run the anchor/anchor-like detectors against that path.
