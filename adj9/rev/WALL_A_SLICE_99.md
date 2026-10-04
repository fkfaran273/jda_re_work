# Wall A — slice 99: OFFLINE VERIFICATION of #0 / #2 / #4 (the pure-Python-signer question)

Date: 2026-09-17. Method: pure offline analysis of the 10 live EMIT traces in
`adj9/device/whcap_hits*.json` (scripts: `rev/all_sign.py`, `rev/verify_d014.py`,
`rev/h_ten.py`, `rev/h6_tail.py`, `rev/final_d014.py`, `rev/sec_scan.py`,
`rev/rand_hunt.py`, `rev/find_words.py`, `rev/det3.py`). Nothing was sent anywhere.

## 0. Why this slice exists

Slice 98 proved the maker reproduces a 192-B blob byte-exactly given the captured
descriptor set, and that `#10` (claims) is fully computable by the desc10 law.
The three remaining per-signing inputs were `#0` (144 B), `#2` (4 B), `#4` (32 B,
"H"). Slices 80/84 declared them "per-signing entropy, not reconstructible
offline" — but those verdicts rested on `desc_det.log`, whose segmentation had a
bug (`#2` overwritten by `#7`: both fields are 1 dword). This slice re-verifies
from the raw traces with the emission order fixed.

## 1. Corpus + a corrected pairing method

* 10 signings harvested from 7 traces, each with the full descriptor set.
* `#10` lengths: 360 / 388(with 1 pad) / 504(with 2 pad) / 532(with 3 pad) B.
* True **call second** is recoverable per signing: `make_header(sec)` is a
  deterministic 4-dword pattern, so scanning every sink's `pos0..3` for a header
  match pins it (`sec_scan.py` → the hits7 burst contains exactly two signings'
  seconds: 1789240512 and 1789240514).
* **Consequence:** the two same-map signings of the burst (S7, S9 — byte-identical
  `#10`) were signed in *different* seconds, so the older "same map, same second,
  different #0/#2/#4 ⇒ entropy" claim was never actually tested. What *is* proven
  is narrower and still decisive (below).

## 2. Slot laws — re-verified on all 10 signings

| slot | verified value / law |
|---|---|
| `#10` | claims string, first 4 B = `4b6c6341` ("KlcA"); byte-exact via `desc10_law.build_desc10` |
| `#7` | **= the UNPADDED byte length of `#10`** — new: 0x168=360, 0x183=387 (388 padded), 0x1f6=502 (504), 0x211=529 (532). All 10 ✓ |
| `#8` | constant `bffffffffffffd1f0007000000000000` (all 10) |
| `#9` | constant `fad0f10d 60f93c17 937b2f1e b6c09691 ae7d74bd` (magic + cert SHA-1) |
| `#5`, `#6` | `00000000` (all 10); `#1`, `#3` empty (0 dwords) |
| `#2` | 4 B, 10 distinct values — **not** the length (that is `#7`) |
| `#4` | 32 B, 10 distinct values |
| `#0` | 144 B = prefix + a **16-byte tile repeated ~8.5×** |

## 3. #0 — the fresh surface is ~5 dwords, not 36

Every one of the 10 signings' `#0` decomposes as

```
#0 = [prefix 4 B (9/10) or 8 B (1/10)] + [16-B tile] × (~8.5)
```

so the per-signing "unknown" is **5 dwords (20 B)** — a 1-dword prefix plus a
4-dword tile — and the remaining 31 dwords are that tile repeating. All 10 `#0`
values are distinct (`final_d014.py`), so the fresh surface changes every signing.
Slice 84's open question ("does B vary signing-to-signing?") is **answered: YES**.

Where do those 5 dwords come from? Exhausted offline:

* **not** a digest of the signing's own inputs — battery over {`#10`, H, cert,
  created_at, hex forms} × {MD5, SHA-1, SHA-256, SHA-512, CRC32, Adler32, FNV1a,
  Java-hash} → 0 hits (`verify_d014.py` §3);
* **not** the header PRNG — `Random3(sec)` raw streams (both `v>>1` and full-32-bit
  variants) searched for 4000 draws × sec 1789240504..520 → 0 hits (`rand_hunt.py`);
* **not** a cached/reused value — 615 device+rev files scanned, the words appear
  only inside the trace itself; no cross-signing reuse of any tile/prefix.

## 4. #4 ("H") — NOT a uniform MAC: 8-byte structured head + 24-byte tail

Statistics over the harvested Adjust signings (`h_ten.log`, `h6_tail.log`):

| metric | observed | uniform-random baseline | ratio |
|---|---|---|---|
| zero bytes | 11.2 % | 0.39 % | **28×** |
| bytes `< 0x10` | 28.4 % | 6.25 % | **4.6×** |
| power-of-two bytes | 23.1 % | 3.1 % | **7.5×** |
| always-zero bits | **29 / 256** | 0.25 | — |

The always-zero bits are **concentrated in bytes 0–7**:

```
byte 0: bits 0,3,4,5,6,7    byte 1: bits 3,5,6,7   byte 2: bits 1,3,4,5,6
byte 3: bits 3,6            byte 4: bits 1,4,5,6   byte 5: bit 6
byte 6: bits 0,1,4,5        byte 7: bit 1
```

and the per-byte alphabets of the head are tiny (byte 0 ∈ {00,02,04} across the
samples; byte 1 ∈ {00,01,02,04,10}; byte 6 ∈ {00,04,08,40,80,84}). Bytes 8–31 are
statistically indistinguishable from random (0–1 zeros each, 9–10 distinct values).
Bit-order transforms (per-byte bit-reverse, LE16, LE32, whole-256-bit reverse) do
**not** remove the structure, so it is not a byte-order artifact.

**Conclusion:** `#4` = `[8-byte structured head][24-byte opaque tail]` — a signed
record, not a bare MAC/hash. The head is bit-flag/counter-like (consistent with a
key/algorithm/context identifier) and differs for all 10 signings, so it encodes
per-call context rather than a constant key id.

The 24-byte tail is **not** a plain digest of the signing's own inputs: 259 message
combinations × 8 digest functions = 2072 candidates per signing, all signings →
0 hits (`h6_tail.py`). A keyed function under a non-exportable key remains the
consistent explanation (slice 93), now localised to the tail only.

## 5. What this means for a pure-Python signer (the decisive part)

1. **`#0` is not server-validated.** Slice 82: a blob carrying **zero-filled `#0`**
   plus one random dword was accepted `200`; our crafted chains get `200` today.
   Slice 84: random `#2` runs **exit-clean with identical step counts** — a free
   parameter. Random `#0`/`#4` do *not* terminate the VM, so shape matters (a
   zero/tiled shape routes; an arbitrary one does not).
2. **`H` freshness is not checked.** The slice-82 acceptance carried a ~19-hour-old
   replayed `H`.
3. Therefore the *only* un-derivable byte range is `#4[8:32]` (24 B) — and a single
   captured `H` can be replayed indefinitely. Everything else is either computable
   (`#10` law, `#7` law, `#8`, `#9`, `#5`/`#6`, header = `Random3(second)`) or
   freely choosable (`#0` = zeros/tiled shape, `#2` = any value).

**So offline signing is complete for the acceptance criterion.** The exact values of
`#0`/`#2`/`#4` are *not* what decides the Organic-vs-non-organic verdict — the
device-minted blob (real keystore `H`, real native VM, our map) replayed from the PC
also read Organic (`send_mint4_result.json`), and unsigned requests still get `200`
(`unsigned_test.py`). The verdict is decided by the attribution graph (click join /
first session / GAID freshness / submission path), per slices 97–98.

## 8. SERVER-SIDE VERIFIED PAYLOAD — mapped by live probing (2026-09-17 late)

Method (`rev/recog_probe.py`, `recog_probe2.py`, `recog_probe3.py`): take the
byte-exact **genuine** blob captured from the wire (`fresh_genuine.json`) and change
**one** thing per request; the signal is HTTP **400 `ask_in` = the server
RECOGNIZED the package** vs **200 + `wy7261z` Organic = it did not**. `/attribution`
polls are not interval-limited (unsigned_result.json: attr1-3 all 200), so 400 is
specific. Nothing here needs the device except the transport.

### 8.1 The whole blob must be the genuine one (header included)

| probe | result |
|---|---|
| genuine blob + genuine query (control) | **400 — recognized** |
| **crafted header (Random3(now)) + genuine body** | 200 Organic — NOT recognized |
| genuine header + crafted body (slice 92, variant D) | 200 Organic |
| 1-bit flip anywhere (slice 92, 61 measurements) | 200 Organic |

⇒ earlier "crafted header accepted" reading of slice 92's variant E was WRONG:
`sig_probe` printed `crafted_header_equals_genuine: true` — E's header was the
genuine one, so E was verbatim. **The 16-byte header is verified too.**

### 8.2 The server rebuilds the claim set from the request (18 single-param probes)

| param changed | verdict |
|---|---|
| `initiated_by`, `api_level`, `app_version`, `os_version`, `created_at` | **payload-bearing** → Organic |
| `device_type`, `environment`, `gps_adid_src`, `tracking_enabled` | **payload-bearing** → Organic |
| `device_name`, `session_count` (added), `android_uuid`, `gps_adid` | **payload-bearing** → Organic |
| `ui_mode` (dropped or changed), `foreground`, `offline_mode_enabled`, `needs_response_details`, `attribution_deeplink`, `gps_adid_attempt`, `sent_at` | tolerated → still **400 recognized** |

**Every tolerated key is absent from our proven desc10 claims law; every
payload-bearing key is in it.** (e.g. `created_at` in the law → payload;
`sent_at` not in the law → tolerated; `session_count` in the law → adding it breaks
verification.) So: the server derives the signed claim set from the request and
verifies the blob against exactly that. `rev/recog_probe3.log`.

### 8.3 BUT recognition is not "payload-consistency + valid signature"

* `rev/final_offline_test.py`: our maker's blob over the app's real session map, sent
  with a query built from the law's claim keys → **200 Organic** (V2/V3 controls
  likewise; the V4 control was invalidated by a header monkey-patch — rerun needed).
* **`rev/mint_exact_send.py` (the decisive one):** a blob minted **by the device's own
  SDK signer** (real keystore, same install, our map — `mo1.json`) sent with a query
  built from **exactly the pairs the device signed** (43 keys, first-wins and
  last-wins variants, plus a missing-key variant) → **all three 200 + Organic**. GAID
  `e7262a88`, whose true state is VKM non-organic (`2456eyqn`), answered `wy7261z`
  Organic.

⇒ A real-keystore signature over a payload we chose is **not recognized**. Combined
with §8.1 (any changed byte → Organic) and slice 92 (verbatim genuine → true
verdict, stable for hours; 3/3), the only model that fits everything is:

**the server recognizes the packages the app itself transmitted** (stored bytes /
stored digest bound to the request), and answers every other package with the silent
Organic fallback. Signature validity alone is not sufficient; transmission is.

### 8.4 What that means (final)

* **Offline generation of a recognized package is impossible** — not because the
  blob is uncomputable (we compute it byte-exactly) but because recognition is bound
  to the app's own transmission.
* **Offline verdict READING works** iff you hold bytes the app transmitted and replay
  them within their window (slice 92: `fresh_ab` F1/F1b → 200 TRUE).
* **Winning non-organic** = the app must transmit the install's calls, with the click
  already joined to that GAID → `rev/farm_win.py` / `rev/amc_final.py` (9/9).
* **Remaining test to close the last confound:** mint with a map whose claim set is
  exactly the ATTRIBUTION kind's (order unknown → decode the 502/529-byte `#10`
  variants captured in whcap_hits/wchcap_hits2/3, which are the big claim sets), then
  send with the exactly-matching query. Expected outcome per §8.3: Organic.


1. Decode `#4`'s 8-byte head (bit-packed; 29 fixed-zero bits, 2-value alphabets).
   If it is a context counter/flags record, a *synthetic* head may pass the VM's
   routing, which would remove the last captured input.
2. Capture two signings **in the same second with the same map** (the one
   configuration still missing) to close determinism formally — though §5 shows it
   no longer gates anything.
3. Non-organic: `run_funnel.py --via-device --referrer <real reftag>` on a **fresh**
   GAID whose click precedes its first session.

## 7. Reproduce

```
cd adj9/rev
python all_sign.py        # harvest 10 signings from all 7 traces -> all_signings.json
python final_d014.py      # slot-law table + #0 shape + #4 head groups
python verify_d014.py     # #0 structure + digest battery
python rand_hunt.py       # PRNG-stream hunt
python find_words.py      # 615-file containment hunt
python h10 / h6_tail.py   # #4 statistics + tail digest battery
python sec_scan.py        # true call seconds via the header law
```
