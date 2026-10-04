# Wall A — slice 11 addendum: R1 DONE — app cert recovered (2026-09-11)

`r1_signblock.py` (Signing Block parser, all 4 APKs).

## Pairs found (same signer on all APKs)

| id | meaning | len |
|---|---|---|
| `0x7109871a` | V3.1 signer block | 1403 |
| `0xf05368c0` | V3 signer block | 1403 |
| `0x6dff800d` / `0x2146444e` / `0x42726577` | rotation / SourceStamp attrs | — |

## The cert (from `0x7109871a`, signer0)

- `cert_s0_0.der`, **745 bytes** (`30 82 02 e5…`) — byte-exactly the 745-B
  cert of the JCA trace (`SHA-1(app cert)` once per process, then
  `getKey(key2)` → `Mac(H)→arg3`).
- Subject: **Istanbul / Penti** (matches the live note).
- `SHA-1 = fad0f10d60f93c17937b2f1eb6c09691ae7d74bd`
- `SHA-256 = 9a47a1add482982394feb353cabbc66921b1fae8144483e54e4f2d5a9fe37e68`

## Descriptor-9 (20 B = SHA-1 size) candidates, ranked

1. **cert-SHA1 `fad0f10d…74bd`** — primary. It is the only 20-B digest the
   library demonstrably computes in the signing path (JCA order proves it
   runs immediately before the HMAC that feeds nSign).
2. `SHA-1(oracle canonical event1) = f9560385…ef0b`
3. `SHA-1(SAZ S1 param body) = 8691cb13…54cb`

## Descriptor table update (slice 11 §2)

#9: was DERIVABLE → **DERIVED (3 candidates, #1 strongly favored)**.
#4 H: KNOWN (pairs_run 34×). #5 level: const (31 moto / 30 OnePlus).
Remaining unknowns unchanged: #0 layout, #2/#6/#7/#8 values, #3/#10
runtime pointers, R3 ns stamps. Next: R2 (one-run MessageDigest hook
disambiguates #9) or straight to resimulation with #9:=cert-SHA1.
