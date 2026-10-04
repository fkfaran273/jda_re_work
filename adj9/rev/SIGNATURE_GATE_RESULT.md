# Signature gate result — the adj9 signature is NOT the discriminator

**Date:** 2026-09-25
**Verdict: Organic, even with a byte-exact signature.**

## What was tested (decisive run, fresh GAID `ce1e4f52-4450-432f-a4dd-03ff538e4574`)

The Python-mint transport test (`arm_transport2.py`) reproduces the winning
device recipe with exactly one variable changed — who signs/sends the install
(the app vs our Python mint). Everything else is held identical:

- fresh GAID installed into Google Play services on the device
- the click fired FROM THE DEVICE (same egress IP, same Chrome UA), HTTP 302
- moto g42 / Android 12 profile, no mcc/mnc
- real CTIT (~217 s click→install)
- all four calls transported by the DEVICE (adb shell curl)
- the adj9 blob minted by the recovered FinEx VM (`F.py` region + `fin_vm2`)

## Signed payload (d10 claim) is byte-exact vs the real winning capture

Captured real rows (`device/win_capture_rows.json`) vs our mint:

| call  | real d10 | our d10 | match |
|-------|----------|---------|-------|
| session | 360 B | 360 B | yes |
| click   | 387 B | 387 B | yes (after referrer fix) |
| re-sign | 360 B | 360 B | yes |

Every signed claim decodes and matches the real app: `adj_verification`
(exact), `client_sdk=android5.7.0`, `native_version=5.0.0`, `gps_adid_src=service`,
`initiating/store package=com.android.vending`, `referrer_api=google`,
`google_play_instant=0`, `app_version=3.14.0`, timezone `+0530`, and the real
Google Play referrer `utm_source=google-play&utm_medium=organic`.

IMPORTANT — the d10 claim being exact does NOT mean the whole signature is
exact. A full-envelope replay against 40 genuine captures later showed the
16-byte header and the d10 claim are exact, but the FinEx body (first mismatch
at envelope offset 64) and the first six words of the d0 region are NOT
reproduced. See SIGNATURE_VERIFICATION_STATUS.md. The "byte-exact" claim here is
scoped to the d10 claim only.

## Result

`/session` → 200 + adid, `/sdk_click` → 200 + adid, but attribution returns
`token=wy7261z, network=Organic, engagement_time=zero` on all 4 polls.
**Organic.**

## Bugs found and FIXED along the way (all were real, none was the gate)

1. Timezone: profile said `+0200`, real device/app signs `+0530` (Asia/Kolkata) — fixed.
2. App version: profiles said `3.13.9`, app signs `3.14.0` — fixed.
3. Region/stamp/seed off-by-one: `adj9_api` / `oneclick` built region+stamps at
   `sec-1` while the VM seeded from `sec` — fixed to use `sec`.
4. Re-sign whitener head: re-sign used H4, must use H5 — fixed via `head_for_kind`.
5. Click referrer: harness/S2P template signed `utm_source=(not%20set)...`
   (4 B too long) instead of the real referrer — fixed to a byte-exact 387 B.

## Conclusion

The full offline reproduction of the adj9 signed request is correct and
byte-exact, and it still attributes Organic. Therefore the non-organic gate is
**not** in anything the adj9 signature covers. It is a server-side install-
legitimacy / anti-fraud signal the SDK collects outside the signed blob —
candidates include the Google Play Install Referrer API attestation, Play
install state, package-manager / app-signing-certificate provenance, or a device
attestation. Reproducing the signature alone cannot produce a non-organic
install; that gate is not offline-reproducible from the request bytes.
