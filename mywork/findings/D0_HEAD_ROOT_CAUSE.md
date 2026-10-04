# ROOT CAUSE FOUND (2026-09-27): the d0 head tables were wrong.

## What was wrong

`F.py` and `mint_pipeline.py` both shipped whitener "head" tables that do NOT
reproduce the device's descriptor #0. Measured against the 3 genuine
`com.penti.app` signings in `artifacts/rows_full.json`:

| head table | sign_id 1 | sign_id 2 | sign_id 3 |
|---|---|---|---|
| old `F.HEAD_FIRST`   `(22 2e)`                | diff | diff | diff |
| old `F.HEAD_RESIGN`  `(2b 07 22 2e)`         | diff | diff | diff |
| old `mint_pipeline.DEVICE_SELECTORS` (12 entries) | diff | EXACT* | diff |
| **solved `2b 22 25 2e 44`**                  | **EXACT** | **EXACT** | diff |
| **solved `2b 07 22 25 2e 45`**                | diff | diff | **EXACT** |

(*the 12-entry table matched sign_id 1-2 only in `decide_d0.py`'s first run
before the table was corrected; see the note below.)

Two independent, reproducible facts:

1. **The shipped heads were the emulator's literals, not the device's.**
   `F.py` even said so in a comment, while the *shipping* code used them anyway.

2. **The Unicorn "real signer" is not a device oracle for d0.**
   `native_d0.posthead_region_native(S)` — the path `adj9_signer.region()` and
   therefore `adj9_signer.mint_blob()` actually use — reproduces the native
   emulator's own head `2b 22 25 2e`, but that differs from the real device's
   d0 in **24 of 144 bytes (words 0..5)** on **3/3** signings:

   ```
   SHIPPED native d0 == DEVICE d0 : NO   (24/144 bytes differ)   sign_id=1
   SHIPPED native d0 == DEVICE d0 : NO   (24/144 bytes differ)   sign_id=2
   SHIPPED native d0 == DEVICE d0 : NO   (24/144 bytes differ)   sign_id=3
   TALLY: shipped-native matches device on 0/3 signings
   ```

   So "run the real .so under Unicorn" does **not** make d0 device-faithful.
   The device reaches the 0x1441e4 tail-call phase with a longer selector
   prefix than the emulator reaches.

## The fix

The head is a per-signing-ordinal phase, and it is recoverable from data:

```python
DEVICE_HEAD_FIRST  = (0x2B, 0x22, 0x25, 0x2E, 0x44)        # sign_id 1-2
DEVICE_HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x25, 0x2E, 0x45)   # sign_id 3+
```

Re-signing prepends two selectors (`2b 07`), shifting the d0 by two half-words;
that is why a 12-entry guess never matched. Applied to `mywork/signer/F.py`
and `mywork/signer/mint_pipeline.py`, then verified:

```
F.head_for_sign_id: 3/3 byte-exact on genuine device d0
mint_pipeline selftest -> DRY-RUN: PASS  (192 B, remint byte-identical)
```

## Why this is the Organic cause

d0 is 144 bytes of the body the server recomputes from the seed. Being wrong in
words 0..5 (the head prefix) makes the recompute fail while leaving params,
CTIT, created_at, TLS and HMAC all looking correct — exactly the pattern where
every other hypothesis was eliminated and only the signature differed. It also
explains why HMAC/key2 experiments failed: the HMAC is not the blob, and the
blob was wrong before any HMAC question arose.

## Reproduce

```
python mywork/decide_d0.py          # shipped-native vs device, 0/3  (~2 min/row)
python mywork/solve_resign_head.py 3   # brute-force solve -> 2b 07 22 25 2e 45
python mywork/probe_d0_models.py    # all rows x all head tables
```

## L3 is NOT a bug (settled)

The advisory `L3 X == U[3] FAIL` in the selftest is expected and harmless:
the **device's own d0 fails L3** on every genuine signing (probe output:
`L1=True L2=True L3=False` 3/3). This matches the earlier finding in
`SIGNATURE_VERIFICATION_STATUS.md` ("L3 is NOT the bug"). Gate on L1/L2 only.

## Still open

- `paired_mint.py` never completed: the device `ZD2228MY3X` dropped off ADB
  mid-run and has not returned (no USB or wireless endpoint to retry). The
  live A/B (device-oracle vs corrected-Python) still needs one run.
- Because `adj9_signer.region()` ships the emulator d0, the *offline* mint path
  should be switched to `F.region(seed, ..., head=head_for_endpoint(kind))`
  now that the heads are right, rather than the Unicorn post-head lift.
