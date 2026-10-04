# Wall A — slice 30: native claim list captured live (map.get hook) (2026-09-11)

Module change (`Hook.java` + rebuild + reinstall, no reboot): `get` /
`containsKey` on `LinkedHashMap`+`HashMap`, gated on the existing `inNSign`
flag, logging `(map-id, key, value)`. Deterministic trigger → 19,830 hits.

## 1. Signal vs noise

- 18,498 hits = `UTF-8` on one map (charset cache, self-induced via our own
  string logging) + JCA provider-table gets (`ServiceKey`, `Mac`,
  `MessageDigest`, `KeyStore`) — all excluded by key filter.
- REAL: 17 fetch-maps (distinct `this`), ~60 gets each over ~600–1000 ms
  spanning the native window. Per signing: SESSION 27 keys, EVENT 30 keys.

## 2. The claim list (session example, values captured)

27 keys incl. `environment, android_id(null!), fire_adid(null!),
app_version 3.13.9, client_sdk android5.7.0, api_level 31, adj_verification
KlcAG…, android_uuid, app_token jut9tib0eeps, created_at, device_name…`
(`fetch_attrib.json` has all 17 with values + nearest-blob pairing;
`+177/+190/+210 ms` rows are well-paired).

Decisive comparisons vs the 50-field header map:
- fetched ⊂ map MINUS 20 (incl. all 4 header-only: `adj_signing_id,
  algorithm, headers_id, native_version` — independent confirmation of the
  HMAC-exclusion finding) MINUS display/cpu/foreground/language/etc.
- PLUS `android_id`, `fire_adid` (null-valued!) — native reads keys ABSENT
  from the header map (a fuller pre-`u2` map or second source).
- `~2 gets/key` (get + containsKey/hasNext shape); no timestamps fetched
  (`sent_at` absent; ns stamps native-only re-confirmed).

## 3. #0-encoding battery (9 hypotheses, `r4_batt.py`)

zeros / hashCode-BE/LE / raw-bytes / lens-BE / key+value-hashes / 0xFF /
ts-fill / sha-trunc — ALL: 1253 steps, 3 merge emits, 0 blob overlap.
Raw hashCode search in 38 blobs: 0/27 + 0/27 (`h0_test.py`). #0 content
moves only emit #63's value (OUTLEN wire, slice 21); the exit needs queue
DEPTH (+1 at case `0x128838`), which no content changes (depths are
op-count-fixed pre-dispatch; `x26` walk audited clean: `0x100314 cbz`
correctly taken, `0x100338` correctly skipped as return-path).

## 4. Status

Held per signing: full Java tuple (golden_fresh) + native fetch list with
values + H + blob + second. The #0 ENCODING (144 B from ~30 fetched claims)
is the last content unknown of its class; ns stamps + #10 + `0xbb548` order
follow. Falsifiable per hypothesis via merge-emit movement (proven live).
