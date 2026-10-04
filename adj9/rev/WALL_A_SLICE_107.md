# Wall A — slice 107: the `attribution` claim set — the signature-side answer to "what are we missing"

Date: 2026-09-18. Scripts: `rev/gold6_kinds.py`, `rev/att_kind_check.py`,
`rev/att_desc10.py`, `rev/att_kind_verify.py`; patch in `rev/desc10_law.py`.

## 0. The distinction that matters (user's framing)

Request params are **known** — `.saz` gives session 43, click 47, attribution 22.
What was never pinned is **which of them the signature covers**, and that differs
per activity kind. This slice answers it for the third kind.

## 1. The device's own `attribution` map — the missing capture

`device/gold6.json` holds 6 oracle signings in three shapes. `gold6_kinds.py`:

```
idx  kind     mapN  act_kind      signature of the map
0    session  52    session       has_install=True  has_session_tail=True
1    click    60    click         has_install=True  has_session_tail=True has_click=True
2    session  31    attribution   has_install=False has_session_tail=False
3    session  52    session       ...
4    click    60    click         ...
5    session  31    attribution   ...
```

The 31-key shape **is `activity_kind="attribution"`** — the kind `desc10_law` had
listed as "pending a capture". Every `/attribution` request the campaign ever sent
was signed with the **session** claim set.

## 2. The attribution claim set: 21 keys (derived, then cross-checked)

```
profile block  (15, sorted): adj_verification, android_uuid, api_level, app_token,
    app_version, created_at, device_name, device_type, environment, gps_adid,
    gps_adid_src, initiated_by, os_name, os_version, package_name
pinned         ( 1)        : adj_signing_id
tail block     ( 1, sorted): tracking_enabled
envelope block ( 4)        : activity_kind, client_sdk, headers_id, native_version
TOTAL          (21 keys)
```

`att_kind_verify.log`:

```
law keys absent from the device map : NONE
map keys the law omits (diagnostic) : NONE
AGREE (law vs the independent derivation): True
```

i.e. the law's new `attribution` kind is exactly consistent with the device's own
map — 14 of `PROFILE_COMMON`'s 17 keys (missing `hardware_name`, `installed_at`,
`os_build`: install-time facts an attribution poll does not carry) **plus
`initiated_by`**, and one tail key.

### Predicted bytes (testable)

```
KlcAG2cbAAsKSl1KVi0FGiJbDHMI7ba51fce-9d49-46ec-94d3-924e8a0ff26931jut9tib0eeps
3.13.92026-09-14T23:44:40.543Z+0530moto g42phoneproductiond016e7e4-fb1c-4d0a-b619-
db01f6a6a262servicebackendandroid12com.penti.app15000001attributionandroid5.7.0105.0.0

unpadded 246 B (descriptor #7)   padded 248 B = 62 dwords (descriptor #10)
```

**248 B is a length that does not occur among the captured 360/388/504/532 B
session and click `#10`s** — so one EMIT capture of an attribution signing either
confirms this prediction outright or refutes it. That is the cheapest remaining
offline-checkable claim in the whole model.

## 3. Request vs signature, per kind (the user's question, answered)

| kind | request (`.saz`) | signature claim set |
|---|---|---|
| session | 43 | 27 |
| click | 47 | 32 |
| **attribution** | **22** | **21** |

The signature is **always a strict subset** of the request. For attribution the
subset is nearly the whole request (21 of 22 — only the header/algorithm fields are
wire-free extras), whereas for session/click only ~60 % of the request is signed.

## 4. Why this explains the Organic answers on `/attribution`

Signing an `/attribution` request with the session claim set means the blob
asserts **7 claims the request never carries** and **omits `initiated_by`**:

```
session-law keys ABSENT from an /attribution request:
  hardware_name, initiating_package_name, installed_at, os_build,
  session_count, store_name_from_system, updated_at
attribution-only key the session law never packs: initiated_by
```

Slice 99 §8.2 measured that the server rebuilds the claim set from the request and
treats every in-law key as payload-bearing — with `initiated_by` among the
payload-bearing keys. So a session-signed `/attribution` blob is a claim-set
mismatch **twice over**, and could never verify regardless of `H`, `#4` or
transport. That is a concrete, previously unnamed "missing piece" in the signature.

## 5. Cross-checks that line up

* All **22** genuine `/attribution` query keys are present in the device's
  attribution map (`all of them present: True`).
* The map's wire-absent keys are exactly the 7 non-claims
  (`activity_kind`, `adj_signing_id`, `adj_verification`, `algorithm`,
  `client_sdk`, `headers_id`, `native_version`).
* The map carries **all 7** of slice 99 §8.2's *tolerated* keys (`ui_mode`,
  `foreground`, `offline_mode_enabled`, `needs_response_details`,
  `attribution_deeplink`, `gps_adid_attempt`, `sent_at`) — and none of them is in
  the law, which is exactly §8.2's finding.
* `key2_hex` / `key2_len` appear in the maps: these are **adj9-oracle
  instrumentation**, not real claims, and the law correctly ignores them (they
  must never be sent as request params).

## 6. What changed in the code

`rev/desc10_law.py`:

* `ATTRIBUTION_PROFILE` / `ATTRIBUTION_TAIL` + a third branch in `desc10_keys`,
  labelled **PREDICTED** with its testable signature (21 values, 246→248 B);
* `self_test()` still exits 0 (session 360 B BYTE-EXACT, click 387 B BYTE-EXACT);
* `rev/desc10_push_test.py` still **PASS — all 10 captures byte-exact**.

So the maker can now sign `/attribution` correctly by construction:

```python
raw = desc10_law.build_desc10(val, 'attribution')      # 21 values
desc, unpadded = adj9_forge.claims_for_law(val, 'attribution')   # (248 B, 246)
#7 = unpadded
```

## 7. Next

1. **Send an `/attribution` request signed with the attribution claim set** (21
   keys, `#7 = 246`), on a fresh clicked GAID — the endpoint where every previous
   arm was structurally mismatched.
2. Capture one EMIT trace of an attribution signing to confirm the 248 B
   prediction and close the kind.
3. Same treatment for `event` (`activity_kind=event`): not among gold6's three
   shapes, so still uncaptured.