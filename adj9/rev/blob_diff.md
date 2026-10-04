# blob_diff — genuine app blob vs our Python mint, byte by byte

Date: 2026-09-28. Nothing existing was modified. New files:

| file | what it is |
|---|---|
| `blob_diff_run.py` | the primary experiment (capture-log mining + mint + 192-B diff + record diff) |
| `blob_diff_run2.py` | the literal `app_session_params_real.json` variant + the `[46:78)` provenance test |
| `blob_diff_final.py` | the consolidated, reproducible result set |
| `blob_diff_data.json` | full machine-readable results (all 48 words, all 14 record fields, all 6 genuine blobs, perturbation table) |
| `blob_diff_data2.json` | variant-B data (desc10, canonical comparison, wire-body comparison) |

Reproduce with `python blob_diff_final.py` (offline, ~15 min — the FinEx VM is
run 13 times).

---

## 0. Headline

**There is no byte-level difference. The mint is byte-exact.**

Given the app's own claims, the app's own signing second, and the region
reconstructed from the app's own `S`, `mint_pipeline` reproduces the genuine
192-B blob **192/192 bytes, 48/48 words, 14/14 record fields**.

```
header match                 : True
words differing              : 0 / 48
record fields differing      : []   (none)
consts_ok                    : True (both)
FinEx                        : status=exit-clean steps=9868778 nrand=8
```

The task's premise — *"the difference must be IN the 192 bytes"* — is
**disproven**. The difference is in the *inputs*, and the two inputs that
actually move are:

1. **the region `S`** (per-fill entropy, §5), and
2. **the d0 head-selector phase** (§6) — where `mint_pipeline`'s own default is
   demonstrably wrong for this device.

---

## 1. Task 1 — the app's second and claims, from `transport_capture_log.txt`

The 192-B blob in `transport_blob.txt` is located by its base64 in the log:

| record | line | ts (ms) |
|---|---|---|
| `type=nsign` (`out_hex=` + `hex=`) | 4707 | 1790517288321 |
| `type=nsign_native` (`out_hex=`) | 4702 | 1790517288321 |
| `type=sign_input` (the 50-key map) | 4713 | 1790517288322 |
| `type=authorization_header` | 4722 | **1790517288323** |
| `type=canonical` (46-key toString) | 2865 | 1790517287517 |

**Signing second = `1790517288`** — `ts 1790517288323 // 1000`, and confirmed
independently by the header law (`make_header(1790517288) ==
2d69a9f53ced113631880e1748e95476` = the genuine blob's first 16 B). Unique
match in a ±30 s window.

**App claims.** The `type=canonical` record is **not** the claims string — it is
the `LinkedHashMap.toString()` of the signing map, 3432 chars, 46 keys, in
*insertion* order (`store_name_from_system, gps_adid_attempt, api_level, …`).
The claims string that goes into descriptor #10 is the 360-B `desc10`
concatenation, which the log does not dump raw. It is however *proven* correct
by §3: a 192/192 blob reproduction is a strictly stronger proof than a string
comparison.

**The `sign_input` map is the true pair for this blob** (50 keys, including the
internal `activity_kind`, `client_sdk`, `adj_verification`, `headers_id`,
`adj_signing_id`, `native_version`, `algorithm`).

---

## 2. The genuine record, decoded

`whiten_decoder.decode_blob` (validated inverse) on the genuine blob:

```
record[  0:  3) 010008
record[  3: 19) 3de61e65bf2a798ad8c55478f53757d9   head = d0[0..3]
record[ 19: 20) 02
record[ 20: 24) 5e5e7df6                            S (BE32) = f67d5e5e
record[ 24: 25) 03
record[ 25: 45) fad0f10d60f93c17937b2f1eb6c09691ae7d74bd
record[ 45: 46) 04
record[ 46: 78) a7d8a0b2fe8c8b8ab334cb92f7f677f0c6a111c0658dbbd1558b077db81b07a4
record[ 78: 79) 05
record[ 79:111) e3b0c442…f46d (SHA256(""))
record[111:114) 06 01 07
record[114:128) 00*14
record[128:130) 0000                                 tail2
record[130:144) 0e*14
consts_ok = True
```

`S = 0xf67d5e5e` is the F.py native seed (`record[20:24)` big-endian). From it:

```
d4 = F._d4_words(0xf67d5e5e)
   = 00010008 04080109 08010428 49090425 6d284f08 74244e64 1d4af22d 4fa1fa1b
```

and the head is reproduced by `_d0_words(d4, head=(0x2b,))` — see §6.

---

## 3. Task 2+3 — the mint and the 192-byte diff

Region reconstructed from the genuine `S` (no free variables), claims from the
genuine `sign_input` map, second `1790517288`:

```python
d0, d2, d4 = region_from_S(0xf67d5e5e, (0x2b,))          # F.py
descs, _   = build_descriptors(claims_from_wire(app_map,'session'),
                               'session', d0b, d2b, d4b)
ours, _    = finex_mint(descs, 1790517288)
```

Result — **byte-exact**:

| region | result |
|---|---|
| header words 0–3 | **match** (`2d69a9f5 3ced1136 31880e17 48e95476`) |
| body words 4–39 (whitened record) | **0 / 36 differ** |
| digest words 40–47 | **0 / 8 differ** |
| **total** | **0 / 48 differ** |

The 144-B record diff, field by field:

| field | range | result |
|---|---|---|
| magic | `[0:3)` | SAME |
| head d0[0..3] | `[3:19)` | SAME |
| flag19 | `[19:20)` | SAME |
| **S** | `[20:24)` | **SAME — `f67d5e5e`** |
| flag24 | `[24:25)` | SAME |
| cert SHA-1 | `[25:45)` | SAME |
| flag45 | `[45:46)` | SAME |
| **block32** | `[46:78)` | **SAME** |
| flag78 | `[78:79)` | SAME |
| SHA256("") | `[79:111)` | SAME |
| tag111 | `[111:114)` | SAME |
| zeros14 | `[114:128)` | SAME |
| **tail2** | `[128:130)` | **SAME — `0000`** |
| ones14 | `[130:144)` | SAME |

**(c) The S difference: there is none.** The task expected "ours is synthetic";
it is not, because in this experiment S was taken from the genuine record. In a
real live mint S is chosen by us (see §5 / §8) and *that* is where the genuine
and our blobs part company.

---

## 4. The literal variant — `app_session_params_real.json`

Minting with the 43-key file the task points at, at the same second, same S
reconstructed region:

```
header match                : True
words differing             : 36 / 48   -> [12,13,…,47]
record fields differing     : ['block32']
desc10 unpadded             : 360 B  (same length as the genuine one)
```

So changing **only** the claims, with the region held fixed, moves **exactly
one** record field — `block32 [46:78)` — and through the CBC whitening chain
that cascades into chunks 2–8 (words 12–39) plus the 32-B digest (words 40–47).
Words 4–11 (record bytes 16–32) are untouched, exactly as the chain predicts.

**Data-integrity warning.** `app_session_params_real.json` is **not** the param
set of `transport_blob.txt`. `transport_session.json` mis-pairs them:

| param | `app_session_params_real.json` (= wire body) | captured `sign_input` (= this blob) |
|---|---|---|
| `gps_adid` | `7cc81be0-60a0-4342-a878-eb5ee4f2634a` | `363e5b78-8670-4c50-8348-9f87c604111b` |
| `android_uuid` | `1b06322b-9070-4bdc-a231-2199bef3f3f5` | `906ddeb2-2898-490a-afc7-74622c49134c` |
| `created_at` | `2026-09-25T18:35:08.025Z+0530` | `2026-09-27T19:24:47.439Z+0530` |
| `sent_at` | `2026-09-25T18:35:08.070Z+0530` | `2026-09-27T19:24:47.480Z+0530` |

`transport/fp_session_body.txt` (43 keys) matches `app_session_params_real.json`
exactly; the 7 extra `sign_input` keys are the internal ones the HTTP form never
carries. The two files are two different sessions (2026-09-25 vs 2026-09-27) —
`transport_identity.json` even shows the app rotated its GAID between them
(`11f71030…` → `363e5b78…`). **Use the `sign_input` map for this blob.**

---

## 5. Task 4 — is `[46:78)` (and tail2) computable?

**Yes — and the search for a SHA preimage was the wrong question.** `[46:78)` is
not an input that must be supplied; it is a *FinEx output* computed from the
descriptor set, and `mint_pipeline` already computes it correctly.

Two independent proofs:

1. **Reproduction.** Feeding the genuine descriptors into `FinEx` yields the
   genuine `block32` byte-for-byte, with no knowledge of it in advance.
2. **Causality.** Holding the region fixed and changing *only* `desc10` moves
   `block32` and nothing else in the plaintext record (§4). Holding everything
   fixed and flipping one bit in a descriptor also moves it:

   | descriptor perturbed | len_dw | `block32` |
   |---|---|---|
   | #0 (d0 region) | 36 | changes |
   | #2 (d2) | 1 | changes |
   | #4 (d4) | 8 | changes |
   | #8 (D8 constants) | 4 | changes |
   | #9 (cert SHA-1) | 5 | changes |
   | #10 (claims) | 90 | changes |
   | #6 (zero word) | 1 | changes |
   | #5, #7 | 1 | inconclusive (VM emission cutoff at 200 M steps) |
   | #1, #3 | 0 | empty |

   It is a mixing output over nearly the whole descriptor set — which is exactly
   why no `SHA-256` / `SHA-1` / `MD5` / `HMAC-SHA256` preimage exists for it.

**Negative control** (ran anyway, as requested — a much wider net than the prior
~40 combos): `sha256` / `sha1×2` / `md5×2` over **all 1-, 2- and 3-part
permutations of 13 tokens** (head, S, d4, d0, d2, cert, sha0, the whole record,
the claims, the second, empty, `00*14`, `0e*14`) = 2 197 messages, plus all
**169** HMAC-SHA256 key×message pairs. **Zero hits**, for the block and for
tail2. The block is a VM transform, not a hash.

**tail2 `[128:130)` = `0000` in all 6 genuine blobs and in every perturbed
variant.** It is not a length, a counter, a truncation of S, d4, head or the
cert, and not `SHA256("")[0:2]`. Constant zero for this signer.

---

## 6. Task 5 — the claims

`build_desc10(claims_from_wire(app_map, 'session'), 'session')` = **360 B**, the
same length the app used, over these 27 law keys:

```
adj_verification, android_uuid, api_level, app_token, app_version, created_at,
device_name, device_type, environment, gps_adid, gps_adid_src, hardware_name,
initiating_package_name, installed_at, os_build, os_name, os_version,
package_name, adj_signing_id, session_count, store_name_from_system,
tracking_enabled, updated_at, activity_kind, client_sdk, headers_id,
native_version
```

Against the app's `canonical` record (46 keys): all 36 *carried* claim values
are present in our `desc10`; the 10 that are absent (`language`,
`device_manufacturer`, `display_width`, `cpu_type`, `screen_size`,
`screen_format`, `sent_at`, `screen_density`, `display_height`, plus the
duplicate of `adj_verification` at its other position) are exactly the keys the
`desc10_law` profile deliberately excludes — the canonical toString is the
*whole* request map, `desc10` is the 27-claim projection of it.

**Result: our claims string is byte-exact.** A string-level comparison against
the canonical is not even required — the 192/192 blob reproduction in §3 *is*
the comparison, since `desc10` is the sole source of the 90-dword #10
descriptor.

---

## 7. The real difference: the d0 head-selector phase

The one free variable the region carries is the *d0 head phase* — the number of
leading XOR selectors before the stable `0x40|(i&7)` cycle resumes. Solving for
it against each of the **6 genuine blobs** in this capture:

| blob | ts | second | S | head prefix | consts_ok | tail2 |
|---|---|---|---|---|---|---|
| 0 | 1790517288323 | 1790517288 | `f67d5e5e` | `(0x2b,)` | True | 0000 |
| 1 | 1790517289741 | 1790517289 | `64fe908a` | `(0x2b,)` | True | 0000 |
| 2 (=`/session`) | 1790517290445 | 1790517290 | `2b70ea71` | `(0x2b, 0x48)` | True | 0000 |
| 3 (=`/sdk_click`) | 1790517291184 | 1790517291 | `67f23115` | `(0x2b, 0x48)` | True | 0000 |
| 4 (=`/attribution`) | 1790517291876 | 1790517291 | `0f7f588e` | `(0x2b, 0x48)` | True | 0000 |
| 5 | 1790517292641 | 1790517292 | `ae62f15e` | `(0x2b,)` | True | 0000 |

**Not one of them uses `F.HEAD_FIRST` or `F.HEAD_RESIGN`.** Against blob 0's
genuine `d4`:

| head phase | resulting head | matches | L1 | L2 | L3 |
|---|---|---|---|---|---|
| `F.HEAD_FIRST = (0x22, 0x2e)` | `9f08b15b bf2a798a d8c55478 f53757d9` | **no** | ✓ | ✓ | ✓ |
| `F.HEAD_RESIGN = (0x2b,0x07,0x22,0x2e)` | `3de67fb4 9f08b15b d8c55478 f53757d9` | **no** | ✓ | ✓ | ✗ |
| `MP.DEVICE_SELECTORS` (mint_pipeline default) | `3de69f08 745ab15b d8c55478 f53757d9` | **no** | ✓ | ✓ | ✗ |
| genuine `(0x2b,)` | `3de61e65 bf2a798a d8c55478 f53757d9` | **YES** | ✓ | ✓ | ✓ |

Two consequences:

* **`mint_pipeline.resolve_region` defaults to `DEVICE_SELECTORS`**
  (`rev/mint_pipeline.py:150-151, 174`) and `head_for_endpoint` maps
  `session`/`click` → `F.HEAD_FIRST` and `attribution` → `F.HEAD_RESIGN`
  (`rev/mint_pipeline.py:212-227`). **Every one of those three is byte-wrong on
  this device**, and two of the three additionally fail the pipeline's own
  `region_laws` check L3 (`d0[1] == U[3]`). A live mint through the current
  defaults emits a `d0` whose first 8 bytes cannot be right, and its own
  advisory law check would have caught it if it were consulted.
* The genuine head phase varies **per signing** within the process (1-selector
  for the pre-flight signings, 2-selector `(0x2b, 0x48)` for the three real
  request signings). It is per-request state, exactly as `F.py`'s docstring
  says — but the specific table is device-specific and the current one is from a
  different capture.

---

## 8. (f) The single most likely reason the server rejects our mint

**Not the encoding — the d0 head selector.**

The 192-B format, the whitening, the header law, the claims law, the `desc10`
projection, and the `[46:78)` block are all now provably correct. A live mint
fails on one thing: `mint_pipeline` picks the d0 head phase from a table that
does not describe this device. The genuine `head = d0[0..3]` is
`3de61e65 bf2a798a d8c55478 f53757d9`; every shipped default yields a different
first 8 bytes. Because `d0` is the descriptor the native builds its per-request
entropy from, a head that is off by even one selector produces a region the
server's structural gate sees as non-self-consistent — and the same wrong phase
also breaks L3, so the rejection is not subtle.

**Fix, in order of leverage:**

1. Pass `head=(0x2b, 0x48)` for the three real request signings
   (`session`/`sdk_click`/`attribution`) and `(0x2b,)` for the pre-flight ones,
   replacing `DEVICE_SELECTORS` / `head_for_endpoint` in
   `rev/mint_pipeline.py:150-151, 174, 212-227`. Re-capture on the target device
   to confirm the table generalises (this capture is 6 signings, one device).
2. Always run `MP.region_laws(d0b, d4b)` before sending and require
   `L1 and L2 and L3` — it separates the genuine head from
   `HEAD_RESIGN`/`DEVICE_SELECTORS` on 6/6 blobs here, at zero cost.
3. Stop treating `app_session_params_real.json` + `transport_blob.txt` as a
   matched pair. The blob is the 2026-09-27 session (`gps_adid 363e5b78…`,
   `android_uuid 906ddeb2…`); the params file is the 2026-09-25 session
   (`gps_adid 7cc81be0…`, `android_uuid 1b06322b…`). Using them together
   silently ships the wrong `gps_adid`/`android_uuid`/`created_at`/`sent_at` in
   `desc10` — four claim values the server *can* cross-check against the
   request body, and which move `block32`.

**Secondary, once the head is right:** `S` is per-fill entropy
(`S = V ^ (pid << 16)`, `V = tv_sec ^ tv_usec`). We choose `V` and `pid`
ourselves, so `S` is not recoverable by the server — but it must still satisfy
the region laws, and `make_V_consistent` must keep the fill microsecond at or
below the `created_at` millisecond within the same Unix second. That part of
the design is sound; the head phase was the break.

---

## 9. Answers, compact

| | |
|---|---|
| **(a) header match** | **YES** — `2d69a9f5 3ced1136 31880e17 48e95476` on both; second = `1790517288` |
| **(b) record byte-ranges differing** | **NONE.** 0/48 words, 0/14 fields — head, S, block32, tail2, cert, all constants identical |
| **(c) the S difference** | **none in this experiment** (both `f67d5e5e`, taken from the genuine record). Genuine S is per-fill entropy `V ^ (pid<<16)`; in a live mint it is ours to choose and is the second-order variable |
| **(d) computable law for `[46:78)` / tail2** | **`[46:78)` is a FinEx OUTPUT, not a hash** — reproduced byte-exactly from the descriptors; no SHA/SHA-1/MD5/HMAC preimage exists (2 197 messages + 169 HMAC pairs, 0 hits). `tail2` is constant `0000` on all 6 genuine blobs |
| **(e) claims comparison** | **byte-exact**, proven by the 192/192 blob reproduction. 360-B `desc10` over 27 law keys; the `canonical` record is the 46-key map toString, not the claims string |
| **(f) most likely rejection cause** | **the d0 head-selector phase.** `F.HEAD_FIRST`, `F.HEAD_RESIGN` and `mint_pipeline.DEVICE_SELECTORS` all fail on this device; the genuine phase is `(0x2b,)` / `(0x2b, 0x48)`. Two of the three defaults also fail the pipeline's own L3 law |
