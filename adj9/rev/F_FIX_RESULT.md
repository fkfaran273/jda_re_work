# F.py DEVICE-REGION FIX + RESULT (2026-09-24)

## What was wrong

`_d0_words` in `F.py` built the last twelve whitener calls with an **emulator-fitted**
`post_x1` sequence `(0x30,0x2B,0x34,0x37,0x38,0x3B,0x3C,0x35,0x36,0x2D,0x48,0x05)`.
The **real device** uses a different sequence. Consequently every Python-minted
region was wrong in `d0` **words 0..5 (24 bytes)** — and failed the device law
**L3 (`d0[1] == U[3]`)**, which holds 8/8 on genuine device captures but 0/32 for
the emulator-fitted mint.

## The fix

`F.py:131-138` now uses the **device-derived** sequence
`(0x22,0x2E,0x42,0x43,0x44,0x45,0x46,0x47,0x40,0x41,0x42,0x43)`.

Verified independently against the 8 genuine device captures in `pair_h3.json`:

    DEVICE d0/d2/d4 byte-exact on all rows: True
    L3 holds 32/32 on fresh F.region (was 0/32)
    mint_pipeline.py selftest -> DRY-RUN: PASS (L1/L2/L3 all PASS)

(The `fit_runs`/`fill_runs` captures are **emulator** runs; F.region no longer
reproduces their `d0[0..5]`, and that is now EXPECTED — the device is ground
truth. Do not "fix" this back. The `validate-corpus` check is unaffected: it
drives captured device descriptors through the FinEx engine, not F.region.)

## The result: it did NOT flip attribution

A fresh, full Python install with the corrected device-faithful region:

    click 200 (reftag cLnIguD8uowfV)
    /session   200 adid=4fba6663ae638b0b70c90155b1998375
    /sdk_click 200 same adid
    /attribution x3 -> wy7261z / Organic / eng=0001-01-01  (all 3 polls)

**Organic, exactly as before.** The corrected region is necessary but not
sufficient. This is the single strongest result of the session:

- Our blob can now be made **device-faithful** (byte-exact region, L3 32/32,
  claims byte-exact) — the "something wrong in the signature" hypothesis had a
  real bug and it is fixed.
- But attribution still did not join. So the gate is **not** a recomputable
  structural property of the blob (the server does not simply test L3, d0, or
  the region laws).

## What this rules in / out

- **Rules out:** "the server gates on a recomputable signature property" (L3,
  d0 shape, region laws). A device-faithful, L3-passing blob is still Organic.
- **Reinforces:** the gate is tied to the session being sent by the **real app on
  the real device** (transmission provenance / app lifecycle), not to blob content.
- **Reinterprets slice 143:** the `400 ask_in:7200000` from a verbatim replay is
  classic **replay/rate protection** ("you already sent these exact bytes"), NOT
  signature-provenance validation. Its "byte-match = recognition" conclusion was
  a misread; the one-bit flip simply produced a non-duplicate request.

## Honest status of "make non-organic from scripts"

A pure-Python path is now strongly disfavored: we can mint a device-faithful,
L3-passing, claim-exact blob and the server still will not join the click. The
remaining difference is *who transmits the session* (the app), which is not a
value we can compute. The one genuinely open question is whether Python joins
are happening but hidden behind the read gate (see the passive-read experiment);
that has not been cleanly tested because the "app reads the record" step is not
passive (it sends a second session).
