# MINT LIVE — the funnel arms ran; the near-faithful mint books ORGANIC (2026-09-25)

Scripts: `mint_pipeline.py arm-a|arm-b --live`. Results: `mint_arm_a_result.json`,
`mint_arm_b_result.json`, logs `mint_arm_{a,b,b}_run*.log`. Oracle: the device
app's own `AdjustAttribution` (never a crafted poll).

## Results

| arm | click | booking session | app verdict | installed_at |
|---|---|---|---|---|
| A | PC (chrome131, reftag cIwLQnupGVhjh) | MINT (200, adid 928f4882…, ask_in 2000) + mint sdk_click | **`wy7261z / Organic`** | 2026-09-24T19:16:45Z (= mint session) |
| B run 1 | device | CONTESTED — the still-running app sent its OWN session first (19:21:09) and rate-limited the mint session (400 too-frequent) | (invalid as a mint test) | — |
| B run 2 (clean: force-stop before GAID write) | device (302) | MINT (200, adid 174b09fe…, ask_in 2000) | **`wy7261z / Organic`** | 2026-09-25T04:05:22Z (= mint session) |

Both mint bookings were accepted (200 + adid + installed_at = the record IS the
mint's) but attribution did NOT join the click. Race fix now in `run_arm_b`
(force-stop before `set_gaid`).

## What this isolates

The mint blob was: exit-clean, nrand=8, header law exact, #10/#7 law-built,
#8/#9 constants, region = F.py (d2/d4 byte-lawful, tile laws L1/L2/L3 pass).
The ONE known in-blob difference vs a genuine signing: the **d0 head** (first
2–3 words of #0) — the 12 VM call-site whitener literals whose on-device
sequence differs from the emulator's (`head_channel.md`; `F_fresh_validation.md`:
d2+d4 exact on all rows, only the head wrong).

⇒ Next differentials, in order:
1. capture the on-device head per signing (oracle module / frida hook at
   0x144074/0x1441e4 logging (LR, w1)); re-run Arm B with a FULLY faithful
   region. If STILL Organic:
2. the discriminator is outside the blob (transport/provenance the 13 arms
   never fully covered, or a server-side session-liveness channel), and the
   device-signed path (farm_win 11/11) remains the only non-organic recipe.

## Artifacts

`mint_arm_a_result.json`, `mint_arm_b_result.json`, `mint_arm_a_run1.log`,
`mint_arm_b_run1.log` (contaminated), `mint_arm_b_run3.log` (clean).
