# WALL_A_SLICE_95 — desc10 law PROVEN byte-exact (3-block alphabetical law) + native fetch unit mapped

Date: 2026-09-17. Companion: memory `2026-09-17.md`. Supersedes slice 94's open items.

## 0. Headline

The desc #10 (360 B) packing law is now **proven byte-exact** against the golden
signing's OWN canonical map (the pairing slice 94 lacked), and the order is
explained by the native's own claim-fetch behavior observed live in the same log:

```
desc10 = CONCAT( values of 23 record claims, A→Z )
       + CONCAT( values of 4 envelope fields, A→Z )
  block1 (23, sorted): adj_signing_id, adj_verification, android_uuid, api_level,
      app_token, app_version, created_at, device_name, device_type, environment,
      gps_adid, gps_adid_src, hardware_name, initiating_package_name, installed_at,
      os_build, os_name, os_version, package_name, session_count,
      store_name_from_system, tracking_enabled, updated_at
  block2 (4, sorted):  activity_kind, client_sdk, headers_id, native_version
```

`rev/law_check.py`: predicted 360 B == `fin_descs.json` desc10 **byte-for-byte**
(360/360, per-slot PASS). All four slice-94 unknowns resolved in one step:
- 284 `1` = **session_count**, 304 `1` = **tracking_enabled**
- 193 vending = **initiating_package_name**, 285 vending = **store_name_from_system**

## 1. Why the order is what it is (native fetch unit, live evidence)

`rev/fetch_order.py` + `law_check2.py`/`law_check3.py` on `device/adj9_wh4.log`
mapget events (2,118 claim fetches, 8 signings):

- **Session signings (211c2cd4, 505f30c7, 61c5008a, 5595c3c4)**: repeating
  **24-claim unit = 22 sorted claims + [activity_kind, client_sdk]** appended —
  found intact 2/14/18/20× per burst; last window == unit in all four.
- **Click signings (380195de, 38cbb181, 2b2d9e8b)**: same unit minus the two
  store claims (initiating_package_name, store_name_from_system) → 22-claim unit.
- Each burst opens with a prelude: `environment, app_version, android_id,
  fire_adid, client_sdk, os_version, api_level` (headers/id setup), then the
  repeating claim unit rounds.
- **adj_signing_id is NEVER fetched** (u25=0 everywhere) — value arrives as an
  nSign parameter (1500000); desc10 still emits it, sorted into block1.
- desc10's order = the SAME sorted-claims order the native fetches, plus the
  envelope fields (activity_kind/client_sdk appended, headers_id/native_version
  header-only) as block2. NOT HashMap bucket order — `h_hunt2.py` (H4) is DEAD
  (no monotonic assignment at any capacity 16–128), which this law explains.

## 2. Corrections / false-positive guard

- `order_check.py`/`order_check2.py` results are VOID: both paired desc10 with
  the WRONG map (golden map is not in `corpus.json`; wh4 sign_input[7] is the
  right one — `rev/parse_wh4_sign_inputs.py`, golden nsign index 7 = 5595c3c4…).
- desc10 law verified on ONE desc sample (golden) + fetch-unit regularity across
  8 signings. Click desc10 (25 values predicted: 21-claim block1 + 4 block2) is
  UNVERIFIED (no click desc captured yet) — needs one more native trace.
- `h_hunt.py` H1: H = static/keyless digest of msg variants → FAIL (0/6 × 23
  candidates) — H needs key2, as the dex says. H2: body dwords 0/48 equal even
  between same-map pairs → every body word is H/time-bound.

## 3. Bonus resolution (canonical vs toString mismatch flag)

`wh4_records.json` canonical record (1142 B) vs sign_input toString (1219 B):
common prefix 1141, diff = exactly 77 chars =
`, headers_id=10, adj_signing_id=1500000, native_version=5.0.0, algorithm=adj9`.
So: canonical (d3.a HMAC message) = map WITHOUT the 4 header-only fields;
sign_input = the FULL 50-field signed map. Both records valid; no anomaly.

## 4. Files (this session)

- `rev/parse_wh4_sign_inputs.py` / `wh4_records.json` — 8 nsign + 8 sign_input
  (map_toString + \x01/\x02 map_order) + 18 canonical + 8 H, paired; golden = idx 7.
- `rev/order_law.py` — with the correct pairing: monotonic-subset-of-map-order
  = FALSE (0 assignments; kills the insertion-order hypothesis properly).
- `rev/fetch_order.py`, `rev/law_check2.py`, `rev/law_check3.py` — native fetch
  unit (24 session / 22 click), prelude, adj_signing_id never fetched.
- `rev/law_check.py` — **the law, byte-exact** + resolved offset table (0..359).
- Also closed out (written last session, never run): `h_hunt.py` (H1/H2/H3),
  `h_hunt2.py` (H4 dead), `so_scan.py` (0/50 key strings in .so — keys are
  runtime-decrypted; no static key array exists to copy).

## 5. Next

1. Capture ONE click desc10 (native trace on a click signing) → verify the
   25-value prediction (21 + 4).
2. FinEx end-to-end: build desc10 for a live_pairs signing from its own map
   (law now computable) → mint vs its nsign hex → per-signing #0/#8 remain the
   only maker gap.
3. desc10 builder function for arbitrary maps (law_check.py generalized) —
   ready to fold into adj9_forge.py once #0/#8 are solved.
