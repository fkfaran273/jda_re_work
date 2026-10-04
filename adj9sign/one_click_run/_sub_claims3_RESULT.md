# _sub_claims3_RESULT.md — the claims-cracking stage: real-vocabulary BLOCK search

Date: 2026-10-01.  Scope: authorized security research on our own captures;
public binaries + local analysis only.
Input ammunition: `_sub_core_diff_RESULT.md` (the decoded iOS core string
pool), `_sub_ios_claims2_oracle.py` (validated BLOCK oracle), `_sub_ios_mint.py`
(everything but claims byte-exact 30/30), `_sub_unseal_core.py` /
`_sub_unseal_ios_out.json`, `_sub_ios_seconds.json`.

---

## 0. TL;DR verdict

**The BLOCK oracle search was re-run with the true key vocabulary decoded from
the closed iOS core — 25,712,824 corrected candidates across 13 stage spaces
(orders × value bindings × memberships × serializations × BLOCK frames ×
timestamp forms) — zero `rec[46:78]` matches.**  The vocabulary alone does not
close the law.

Along the way this stage found and fixed **two harness defects that had been
silently invalidating negatives — including parts of the prior ~67M-candidate
search**:

1. **Mixed-length batch corruption in the BLOCK oracle** (CRITICAL): the
   previous `_sub_ios_claims2_oracle.oracle_batch` zero-fills all rows of a
   batch to the batch's max length; a row shorter than the max therefore gets
   extra all-zero blocks digested after its length field → **wrong digest for
   every non-longest row**.  Forged-hit positive control: a record whose block
   matches a short claim is found when batched alone and **missed** when
   batched with a longer claim.  Every prior stage that batched claims of
   different lengths (in particular the 2^18-membership stage B: 262,144
   wildly-differing-length rows per batch) was unreliable.  Fix:
   `_sub_claims3_oracle_fixed.py` groups rows by identical padded length
   (golds 9/9, positive controls pass).
2. **Authorization capture bug**: `^Authorization: (.*)$` with `re.M` includes
   the trailing `\r` in the value (`.` matches CR; `$` does not bar it) —
   every authorization-bound candidate in every earlier pass carried a one-byte
   error.  Fixed in the loader (`rstrip("\r\n")`), all auth-bound cells re-run.

With both fixes in place every stage below is sound, and the conclusion of
the previous stage stands on corrected evidence: the remaining unknown is a
value injected inside the closed core that the capture cannot show (§5).

## 1. What this stage added (the "ammunition" applied)

* **Never-before-testable claim keys with buildable values**:
  * `network_payload` = the exact urlencoded request body (POST), the raw
    query / path?query (GET attribution), the URL-decoded body, body+query,
    and sha256/sha1/md5 of the body (hex/b64/upper).
  * `authorization` = the captured header minus the `signature="…"`, field
    (with and without the `Signature` scheme), with `signature=""`, and the
    full self-referential form (tested for disproof).
  * `signature` = `""` and the captured b64 (self-referential — disproved).
  * `secret_id` = absent / `""` / `1500000` / `10` / `1` (no other constant
    exists in the decoded pool; see §4).
  * `environment` = production / sandbox / Production / Sandbox (the core
    parses the receipt's environment; literal `sandbox` is in-binary).
  * `os_name` = `ios` (wire) and `ios-simulator` (the core's own rewrite for
    simulator builds); `algorithm` = `adj9`/absent; `adj_verification` =
    captured sim-form / device form / absent; `endpoint` = base / with-path /
    absent; `control_params` = absent (empty).
* **Orders**: the Android-proven law (sorted profile + pinned `1500000` +
  sorted tail + envelope `kind‖client_sdk‖10‖5.0.0`), a single alphabetical
  run over the whole pool, wire-insertion order, and — from the binary —
  the weak hint order `signature→headers_id→adj_signing_id→native_version→
  algorithm` as prefix AND suffix, the dictionary-construction order
  `adj_signing_id→signature→headers_id→native_version→algorithm→
  adj_verification` as prefix AND suffix, the device-claims cluster order
  `bundle_id→idfv→app_version→app_version_short→os_name→adj_verification`,
  the auth-header order, vocab-only claims (cluster/sorted), 24 envelope
  permutations × extras (`+algorithm`, `+adj_signing_id`, `+adj_verification`,
  none) × pinned {mid, first, last, absent}, envelope-first.
* **Memberships**: corrected full wire lists (the first pass missed
  `started_at`/`queue_size`/`attribution_token`), then membership subsets per
  record kind (up to 2^18 masks) × 6 value bindings × 2 laws × 2 pinned, plus
  drops of `endpoint`/`adj_verification`/`os_name`/`environment`.
* **Serializations**: bare values (Android-proven), `k=v&`/`k=v;`/`k:v`,
  value-joins, 2-/4-byte length-prefixed, compact/sorted JSON dict and JSON
  value arrays, Android-canonical name translation (`package_name`←bundle_id,
  `android_uuid`←idfv, `gps_adid`←idfa).
* **Canonical timestamps**: the core imports `NSLocale en_US_POSIX` +
  `NSTimeZone(0)` + `yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'` — created_at/sent_at/
  installed_at/started_at replaced by canonical-UTC (±ms), epoch, epoch-ms,
  and `+0000` forms over all substitution masks (the server can re-derive
  these from the wire values).  Note `sent_at` truncates to the recovered
  signing second (1787553331.989 → 1787553332), so a canonical signing-time
  claim was plausible — tested, negative.
* **BLOCK frames**: 30 frames = D9 {20 zeros, empty, dev-padded} × magic
  {`00 08`, `01 00`} × tail {`02‖dev`, `01‖00*16`, `02‖00*16`, `01‖dev`,
  `06‖dev`, `07‖dev`, `dev‖02`, `02 07‖00*15`, `rec[111:130]`, dev-only}
  × 6 bindings × 11 laws (one representative record per kind — a correct law
  matches every record, so full-30 sweeps are reserved for confirmation).

## 2. Per-stage counts (corrected runs: fixed oracle + CR-fixed loader)

| stage | space | n | hits |
|---|---|---:|---:|
| R1 fixed laws (sorted split / one-run / wire order × np × auth × os), all 30 records | 2,160 | 0 |
| R2 orders (hint5 / dict6 / cluster / authhdr prefix+suffix, wire-front × 20 bindings), all 30 | 5,400 | 0 |
| R3 vocab-only claims (cluster / sorted / split × 8 bindings), all 30 | 720 | 0 |
| R4 combinatorial reps (np 6 × auth 5 × sig 3 × env 4 × os 2 × secret 5 × endpoint 2 = 7,200 bindings × 15 laws, 4 reps) | 432,000 | 0 |
| R5a full lists + canonical / k=v / len-prefixed / np-hash / injected-only / auth-only / np-only / JSON laws (48 bindings × 24 laws, all 30) | 51,840 | 0 |
| 6r BLOCK frames (30 frames × 6 bindings × 11 laws, 4 reps) | 15,840 | 0 |
| 7b membership subsets (2^11..2^18 masks × 6 bindings × 2 laws × 2 pinned; session 2^14, click 2^16, attr 2^11, event 2^19) | 14,598,144 | 0 |
| 8 **exact replication of the prior stage-B space** (2^18 masks × 5 endpoints × 4 tails × 2 pinned, session record) on the fixed oracle | 10,485,760 | 0 |
| 9 canonical/epoch timestamp substitutions (2^4 masks × 6 forms × 2 bindings × 6 laws), all 30 | 34,560 | 0 |
| 10 envelope permutations × drop-cells (10 bindings × 24 perms × 4 extras × 3 pinned), all 30 | 86,400 | 0 |
| **total corrected** | **25,712,824** | **0** |

Superseded pre-fix runs this stage (~3.0M candidates under the old oracle /
CR-poisoned auth) are excluded; every cell they covered was re-run corrected.
All stages logged in `_sub_claims3_run*.log`, per-stage JSON in
`_sub_claims3_out.json` (+ per-family files `_sub_claims3_stage*_out.json`).

## 3. String-pool crack (no new keys)

`_sub_claims3_strcrack.py` attacked every undecoded/double-XORed pool entry
(`SWQSP`, `P^U^QSPWPPP`, `knin`, `4cbfh`, `K_DIL`, …).  Result: no new claim
keys.  `K_DIL` = `frida` (second mask 0x2D) pairing the known `gadget`;
`uoksjgrity…` strings = `SIMULATOR_*` keys under constant XOR 0x26; the rest
are overlap artifacts of already-known keys at adjacent addresses.  The
vocabulary from `_sub_core_diff_RESULT.md` is complete.

## 4. Interpretation — what the vocabulary evidence now proves

* The 6+ static reference clusters repeating
  `signature→headers_id→adj_signing_id→native_version→algorithm` are, order
  as prefix or suffix, **dead** for the claims string — as is the dictionary
  order.  Combined with the open SDK's `exceptionKeys` = {secret_id,
  signature, headers_id, native_version, algorithm, adj_signing_id}, these
  clusters are almost certainly the **output-key list** (the auth-header
  family), not the claims order.  The claims order question therefore reverts
  to the Android-proven family — which has now been exhausted over the full
  vocabulary with corrected batching.
* `network_payload` and `authorization` (minus-signature) are **buildable,
  server-verifiable, core-vocabulary claims** — the single most plausible
  iOS-only bindings — and both fail across every order, placement and frame
  tested (~10M+ of the corrected candidates carry them).
* `secret_id` has **no wire source, no decoded constant, and no derivable
  value** in the pool.  It is either absent from the claims or a value baked
  into the core as obfuscated data (not a `__data` string — e.g. assembled
  from immediates), unrecoverable from the capture and from a static read of
  the public binaries' string pool.

## 5. Remaining hypotheses, ranked (after 25.7M corrected candidates)

1. **A core-internal claim value derived from the App Store receipt.**  The
   receipt path is proven in-binary (`appStoreReceiptURL`,
   `dataWithContentsOfURL:`, PKCS#7 signedData/data/rsaEncryption OIDs) and
   the receipt file is **never on the wire in this capture** — the bytes are
   unrecoverable locally.  Plausible carriers among the core-internal keys:
   `secret_id`, `signature` (e.g. a receipt hash), `environment` (the
   receipt's `Production`/`Sandbox`).  Corollary: if a receipt-derived value
   is inside the claims, the Adjust backend cannot re-derive the claims
   either — server-side BLOCK verification degenerates to the digest-MAC +
   structure checks, i.e. **fresh-minted blobs with well-formed fabricated
   claims pass the same server checks as genuine ones**.  One live
   ios-simulator mint tests this directly (as ARM run C/D did on Android).
2. **`secret_id` as a per-app constant** baked into the closed core (XOR/
   immediate-obfuscated, invisible to the string pool).  Recovery: one frida
   hook on the core's claims materialization or SHA-256 compression entry —
   exactly the instrumentation that settled the Android law in one signing.
3. **A serialization family outside §1** — e.g. per-value TLV with the VM's
   descriptor tags, or the claims materialized as the padded descriptor-#10
   record field (residual probability: low; length-prefixed/k=v/JSON already
   covered).
4. The claims use only the bridge-visible maps exactly as on Android, and the
   divergence is entirely inside an unmodelled core-internal key — subsumed
   by 1–2.

## 6. Mint readiness

`_sub_ios_mint.py` remains byte-exact 30/30 on every non-claims component.
`_sub_claims3_mint_check.py` generalizes any single-record hit: rebuild the
law's claims for all 30 records → verify the BLOCK 30/30 → mint full blobs
through the proven pipeline → score 192/192 byte-exactness.  The moment the
claims string is known (one instrumented signing), the capture is reproduced
end-to-end.

**Any future BLOCK search must use `_sub_claims3_oracle_fixed.py`** — the
previous batch oracle misses hits on every non-longest row of a mixed-length
batch.

## 7. Artifacts (all new; nothing existing modified)

* `_sub_claims3_oracle_fixed.py` — the FIXED length-grouped BLOCK oracle
  (golds 9/9 + forged-hit positive controls) — **use this, not oracle_batch**.
* `_sub_claims3_search.py` / `_search2.py` / `_search3.py` — law library
  (values, orders, serializations) + first-stage drivers.
* `_sub_claims3_rerun.py` — corrected R1–R5 driver; `_sub_claims3_stage6r.py`
  — frame matrix; `_sub_claims3_stage78.py` / `_stage7b.py` / `_stage8.py` —
  membership subsets + exact prior stage-B replication; `_sub_claims3_stage9.py`
  — canonical timestamps; `_sub_claims3_stage10.py` — envelope perms + drops.
* `_sub_claims3_strcrack.py` (+`_out.json`) — pool string cracker (§3).
* `_sub_claims3_mint_check.py` — hit→30/30→192/192 generalizer.
* `_sub_claims3_merge.py` + `_sub_claims3_out.json` — merged per-stage counts,
  hit list (empty), sources.
* Logs: `_sub_claims3_run1.log` … `_sub_claims3_run11.log`.
