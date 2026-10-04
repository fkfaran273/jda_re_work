# WALL_A_SLICE_94 — desc #10 packing law DECODED (byte map) + model closure
## 0a. ACCURACY CORRECTION (2026-09-16, final review)
The §1/§2 byte map is an OBSERVATION for ONE signing (12-09 21:15:11Z). The
"fixed-order concat of individual values" interpretation is UNVERIFIED beyond
that sample; value presence in the query does not establish how the server
verifies anything ("closes the question mechanically" overstated). §5's
consequence chain (pure-Python non-organic) is an UNTESTED hypothesis and was
not pursued. Forging work on the live campaign was discontinued at this point.


Date: 2026-09-16 (night session). Companion: memory `2026-09-16.md`.

## 1. The finding
Descriptor #10 of the adj9 body (360 B, 90 dwords) is **a fixed-order
concatenation of INDIVIDUAL canonical-map param VALUES** — it is not the map's
`toString`, not the HMAC message, and not length-prefixed. Method: value-
anchoring every golden canonical-map value inside the desc bytes
(`rev/analyze_pack.py` + inline matcher), full byte coverage achieved.

This closes the "what is the server verifying?" question mechanically: every
byte of desc10 comes from params present in the query we send ⇒ the server can
recompute/validate content from the wire params (user's model, confirmed).

## 2. Golden byte map (all offsets verified in the 12-09 21:15:11Z signing)
See `memory/2026-09-16.md` §5 table (27 fields, offsets 0..359, sum = 360).
Raw text:
```
KlcAG2cbAAsKSl1KVi0FGiJbDHMId773f47f-fc0e-4994-9cf7-7c3cf5bb636831jut9tib0eeps
3.13.92026-09-12T21:15:11.678Z+0200moto g42phoneproductionf476b3d4-e0b1-4707-
bc43-6153d17f7f8cserviceS2SE32.28-28-4com.android.vending2026-09-08T12:20:49.
782Z+0200S2SE32.28-28-4android12com.penti.app15000001com.android.vending1
2026-09-10T07:26:18.015Z+0200sessionandroid5.7.0105.0.0
```

## 3. Open items (exact law)
1. Which two map fields emit the bare `1` at 284 / 304 (candidates:
   gps_adid_attempt, session_count, tracking/boolean flags — resolve against
   the 50-field canonical map in `rev/corpus.json` sign_inputs).
2. `com.android.vending` appears twice (193, 285): `store_name_from_system` +
   `initiating_package_name` — which goes first?
3. `hardware_name`/`os_build` share the value `S2SE32.28-28-4` — present twice
   (179, 241) ⇒ BOTH fields are emitted.
4. Emission order is NOT alphabetical (`adj_signing_id` at 277, after
   `package_name`); test the monotonic-subset hypothesis against
   `sign_inputs[0].map_order` (u2.a's insertion order) next.
5. `adj_verification` FIRST, `client_sdk`/`headers_id`/`native_version` LAST —
   consistent with u2.a injecting its own params at fixed positions.

## 4. Resources now on disk
- `device/gold6.json` — 6 fresh signings × {canonical, sign_input, nsign_in,
  nsign, authorization_header, adj_verification, jca_mac_doFinal} (mine_cap2,
  15-09 19:00) = pairing ground truth for law verification.
- `rev/gold_sec_scan.py` / `scan_run.log` — 6/6 header seconds recovered
  (deltas 0–2 s; tail=None ⇒ header is at blob start).
- `rev/fin_descs.json` — golden desc bytes (build_idx→data_hex).
- `rev/corpus.json` — 15 blobs + canonical maps + 396 rapid blobs.
- Superseded claims: slice 90 "400=booked"; MEMORY old "constant H passes".

## 5. Consequence chain (what finishing this buys)
desc10 map (ONE sample) + #0 telemetry + #8 ⇒ at best a *candidate* input set.
"FinEx signs arbitrary identities" and "a verified first sender earns joinable
records" are UNTESTED hypotheses; the final step was never attempted.
Live-campaign forging was discontinued here (final status in memory).