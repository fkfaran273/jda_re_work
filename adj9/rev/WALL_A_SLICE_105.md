# Wall A — slice 105: desc10 law COMPLETED — the optional `push_token` claim

Date: 2026-09-18. Scripts: `rev/att10_decode.py`, `rev/desc10_push_test.py`;
patch in `rev/desc10_law.py` + `rev/adj9_forge.py`.

## 0. Headline

The captured `#10` comes in **four** lengths, and the law only explained two. The
other two are the **same law plus an optional `push_token` claim**:

| length | kind | push_token | padding |
|---|---|---|---|
| 360 B | session | none | none needed (360 = 4×90) |
| 388 B | click | none | +1 NUL (387 → 388) |
| 504 B | session | **142 chars** | +1 NUL (503 → 504) |
| 532 B | click | **142 chars** | +2 NUL (530 → 532) |

`push_token` is not special-cased: it is an ordinary profile claim, so it simply
**sorts between `package_name` and the next key** — `adj_signing_id` for session,
`referrer` for click. The native pads the result with NULs to a 4-byte multiple,
while descriptor `#7` keeps the **unpadded** length (slice 99 §2).

## 1. Proof (`desc10_push_test.py` → `desc10_push_test.log`)

```
=== law reproduction of every captured desc10 ===
   360 B session  token=0   law=360B padded=360B  BYTE-EXACT uuid=f57fb350
   360 B session  token=0   law=360B padded=360B  BYTE-EXACT uuid=0f6469d5
   360 B session  token=0   law=360B padded=360B  BYTE-EXACT uuid=b47e3bb0
   360 B session  token=0   law=360B padded=360B  BYTE-EXACT uuid=d773f47f
   360 B session  token=0   law=360B padded=360B  BYTE-EXACT uuid=d773f47f
   388 B click    token=0   law=387B padded=388B  BYTE-EXACT uuid=d773f47f
   504 B session  token=142 law=502B padded=504B  BYTE-EXACT uuid=0e0db5f5
   504 B session  token=142 law=502B padded=504B  BYTE-EXACT uuid=4431d1eb
   504 B session  token=142 law=502B padded=504B  BYTE-EXACT uuid=171861b2
   532 B click    token=142 law=529B padded=532B  BYTE-EXACT uuid=171861b2

=== key counts ===
  session, no token : 27 keys      session, +token : 28 keys
  click,   no token : 32 keys      click,   +token : 33 keys

=== RESULT: PASS - all 10 captures reproduced byte-exactly ===
```

Ten captures, four lengths, both kinds — one law. The per-signing values
(`android_uuid`, `created_at`, `push_token`) were recovered from each capture by
generic regex / known-anchor slicing, so the test is not fitted to one signing.
`desc10_law.py`'s own `self_test()` still exits 0 (`session 360 B BYTE-EXACT`,
`click 387 B BYTE-EXACT`), so the change is backward compatible.

## 2. What was added

`rev/desc10_law.py`:

* `OPTIONAL_PROFILE = ['push_token']` — included in `desc10_keys(kind, val)` only
  when the caller's map carries a non-empty value, which mirrors the device;
* `pad4(b)` — the native's NUL padding to a 4-byte multiple;
* `desc10_keys(kind, val=None)` — now takes the map so optional claims appear.

`rev/adj9_forge.py`:

* `claims_for_law(val, kind)` — returns `(padded_desc_bytes, unpadded_len)` for
  an arbitrary map, i.e. descriptor `#10` as the native holds it plus the exact
  value for `#7`. This is the path a token-bearing map must use, because
  `claims_for()` (golden base + equal-length swaps) cannot express a
  variable-length claim inserted mid-blob.

## 3. Why this matters for the server-side question

Slice 99 §8.2 measured that the server **rebuilds the claim set from the request**
and treats every in-law key as payload-bearing. `push_token` is now known to be
part of the signed claim set whenever the app has an FCM token — and it is
*optional*, so it is a second way (besides ordering) for our blob's claim set to
differ from the server's expectation:

```
query carries push_token, blob's #10 lacks it   -> claim-set mismatch
blob's #10 has push_token, query lacks it       -> claim-set mismatch
```

Every crafted arm built from the golden 360 B base had **no** push token (the
base predates it), so any app-signed request that carried one could never be
matched by our blob. The `TODAY.md` note "random push_token | fresh FCM-shaped
token" varied the *wire* token without a law-correct *signed* token, which this
slice now makes expressible.

## 4. Next

1. Sign with `claims_for_law(val_with_token, kind)` whenever the request carries
   `push_token`, and assert `#7 == unpadded_len` — then the claim set and the
   query agree by construction (the precondition slice 102 §3 identified).
2. End-to-end VM check of the **click** path (387/388 B): confirm `FinEx`
   reproduces a captured click blob, since the session path is the only one
   verified byte-exact end-to-end so far. `wh4_records.nsigns` holds the blobs to
   pair against and slice 95 lists the click signings (`380195de`, `38cbb181`,
   `2b2d9e8b`).