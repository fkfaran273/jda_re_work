# Wall A — slice 11 addendum: R2 DONE — cert-SHA1 confirmed in-path (2026-09-11)

No new device run. `adj9/device/adj9_hp.log` (existing JCA trace) already
contains the ground truth.

## Evidence (`adj9_hp.log`)

- 100 `jca_md_update` blocks; **9 with 745-B input byte-identical to
  `cert_s0_0.der`** (R1) — the app cert, hashed live on-device.
- `jca_md_digest` **inside the nSign window**, ts `1789072137649`:
  `out=20 fad0f10d60f93c17937b2f1eb6c09691ae7d74bd` — **exactly R1
  candidate #1**.
- `jca_md_digest_b` same ts: `in=745 (308202e5…cert) → out=20 fad0f10d…`.
- Same ts anchors `pairs_run[0]` (ts `1789072137644`, H `efa2f9b7…`, blob
  `251adf8d…`): for triple 0 we now hold H ✓, cert-SHA1 computed live in
  its own signing window ✓, blob ✓, second ✓.
- (Neighbor digests `65f58d…`, `e3bb76…` = SHA-1 of other JCA inputs —
  GMS/TLS chain per slice-3 attribution, not ours.)

## Descriptor table update

#9: DERIVED → **CONFIRMED `fad0f10d…74bd`** (computed in the nSign window
at signing time; 20-B size matches the `0x14` descriptor). The one residual
caveat (digest computed ⇒ digest placed as descriptor 9) is structural:
the `0x14` slot is the only 20-B field and the only SHA-1-sized claim in
the 11. R2 closed.

## Scoreboard (11 descriptors, one event)

KNOWN: #1 empty, #4 H, #5 level(31), #9 cert-SHA1. DERIVABLE: none left.
UNKNOWN: #0 layout, #2/#6/#7/#8 values, #3/#10 runtime ptrs, R3 ns stamps.
Next: stream-struct resimulation with 4 knowns (slice-10 order), then R4.
