# APK signing certificate — descriptor #9 CONFIRMED (2026-09-24)

**Verdict: descriptor #9 is the SHA-1 of the installed app's signing certificate,
and it matches the real APK byte-for-byte.** This closes the certificate
question. Reproduce with:

    python adj9/rev/cert_verify.py devpull/base.apk

## What descriptor #9 is

Descriptor #9 of the adj9 signature blob is
`SHA1(cert_s0_0.der)` — the SHA-1 of the leaf (only) signing certificate of the
installed APK. Two independent sources agree:

1. **Runtime** — a live JCA `MessageDigest` trace inside the nSign window on
   device produced `fad0f10d…74bd` (see `WALL_A_SLICE_101.md`, `STATUS.md` R1).
2. **Static** — the certificate extracted from the actual installed APK's v2
   signing block hashes to the same value.

## The certificate

    subject  = L=Istanbul, O=Penti
    issuer   = L=Istanbul, O=Penti          (self-signed)
    notBefore= May 15 06:41:04 2020 GMT
    notAfter = May  9 06:41:04 2045 GMT
    length   = 745 bytes (DER)
    SHA-1    = fad0f10d60f93c17937b2f1eb6c09691ae7d74bd   <== descriptor #9

One certificate, self-signed, long-lived. This is the APK the SAZ was captured
on (device `firstInstallTime=2026-09-14 17:52:12` == SAZ `installed_at`), so
the runtime JCA trace and the static APK are provably the same app build.

## Source APK

    devpull/base.apk    79,142,801 bytes  (pulled off ZD2228MY3X)
    signing block: v2 (0x7109871a) + v3 (0xf05368c0) + dependency-metadata (0x6dff800d)

## Two parsing traps hit while verifying this

1. **The `certificates` field is a SET, and its length INCLUDES each cert's own
   4-byte prefix.** The field's length is 749 = 4 (this cert's length prefix) +
   745 (the cert). Adding a second `+4` after reading the 749 skips into the
   DER body and yields a bogus 745-byte "cert" (SHA-1 `a521bb9c…`). `cert_verify.py`
   parses entries inside the set directly to avoid this.

2. **Do not hash the whole `certificates` sequence.** Hashing all 749 bytes
   gives `ff2a16af…` — the 4-byte length prefix `e9020000` prepended to the cert.
   That value matches nothing and looks like a mismatch. It is what
   `devpull/base.apk.cert.der` actually is (a mislabeled sequence, not a cert).

The correct 745-byte certificate is `devpull/chain1.der`.
