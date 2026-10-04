# block_pattern_analysis — the 32-byte block at `record[46:78)`

Produced by `block_pattern_analysis.py` (new file). Machine-readable companion:
`block_pattern_analysis.json`.

## TL;DR

| question | answer |
|---|---|
| Are the 6 genuine blocks all different? | **Yes — 6/6 distinct.** Only 2 of 192 byte positions repeat a value across the set, and each repeat is a 1-in-256 coincidence between two specific blobs. |
| Is there an exploitable pattern (sequential / shared bytes / counter)? | **No.** Every pairwise XOR is dense. |
| Do genuine and instrumented blocks differ structurally? | **No — statistically indistinguishable.** 0 cross-family collisions, 0 shared 8-byte windows, identical `tail2`, identical record layout, identical entropy profile. |
| Can the block be computed from known inputs in Python? | **Yes. 5 of 6 reproduced byte-exactly** by driving the FinEx VM over descriptors rebuilt from the device's own `sign_input` claims. It is **not** a hash, not a secret, and carries **no** un-reproducible entropy. |

The single most important consequence: **the block is a pure function of inputs we
already have, and it does not distinguish genuine from instrumented runs.** It is
not the gate.

---

## 1. Extraction and decode

Six `Signature signature="…"` headers in
`win_capture/module_win_capture.log`, each base64 of a 192-B blob. Decoded with
`whiten_decoder.whiten_body_inverse(body, header)` where `header = blob[0:16]`.
**`record_checks` passes 6/6** — all magic/tag bytes, the constant
`SHA256("")` at `[79:111)`, the `00*14` / `0e*14` runs, and the cert SHA-1 at
`[25:45)` are byte-correct, so these are genuine signer output, not noise.

| win | signing second | S (`rec[20:24]` BE) | head (`rec[3:19]`) | tail2 |
|---|---|---|---|---|
| 0 | 1790341508 | `a9cf7053` | `9e7f83cdbfbdd231ee419c5da02d8737` | `0000` |
| 1 | 1790341509 | `c426af1c` | `8d1a93efeff4e52b993023ff5fe4258f` | `0000` |
| 2 | 1790341510 | `a52febdb` | `c9eaebf976be1db9a3c0dedd60a45580` | `0000` |
| 3 | 1790341511 | `80dd19f6` | `7c0f16bdf580fe40ffbdd814d9e91740` | `0000` |
| 4 | 1790341512 | `a81eafd9` | `db59d7f63c55085aa493a55a09937b3f` | `0000` |
| 5 | 1790341513 | `6e8d51e9` | `f3bcaef7e77772d23b52258f6c0ffbd4` | `0000` |

The `S` values are in signing-second order but are **not** the seconds — they are
the F.py native seed (`V ^ (pid<<16)`), which is why they look like noise.

`tail2 = record[128:130)` is `0000` in **all 6** genuine blobs and in **all 8**
instrumented blobs.

The 32-byte blocks:

```
win0  5502974ee7fe8fc2b5a4cf7fca0324b251af9bc3c051ff3cc56c90f341fe7ce8
win1  6ea16d087c375229e60e069b70ec54600afbce1c0f02a2b7b9d294351ba6e396
win2  0a04927339faf4f2d8c40e178138e72c6036606a410a231bd03d50ab65a97fdb
win3  cb40ddd9e4ab52dc4f690527392f65006d90db754a86577d0f7d87b945b2fbaf
win4  5da5e5709c09e6d511f91b3beafc5562598c03358916bb2104bf036265dbc346
win5  c2465e316bc47588782ee5fd7a080ca72940416e91eb85565eb40ebd7ca0674e
```

---

## 2. Distinctness and pairwise structure

* **6/6 distinct.**
* Per-byte-position distinct-value counts across the 6 blocks:
  `[6,6,6,6,6,6,5,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,5,6,6,6]`
  — 30 of 32 positions take 6 different values across the 6 blobs; positions 6
  and 28 take 5 (one coincidence each, expected at this sample size).
* **14 of 15 pairwise XORs have zero agreeing bytes.** The exception is
  `win1^win5` (agree at position 6) — one byte.
* Consecutive-signing mod-256 deltas are dense, not ±1 or counter-like:
  * `win0→win1` `09fa7fa879e7dd54…`
  * `win1→win2` `3fc4b59a554fa216…`
  * `win2→win3` `53a153fd630ff2e3…`
  * `win3→win4` `f85db2de4bf5a9ed…`
  * `win4→win5` `199fd6ba9539c367…`
* Entropy 6.9975 bits/byte over the 192 pooled bytes; bit-1 fraction 0.4954.

**Conclusion:** no sequential, no counter, no shared prefix/suffix, no
structural regularity. The block looks like a hash or a VM mixing output.

---

## 3. Is the block anywhere in the capture log?

Searching the 2.2 MB log for each block's hex, and for each of its 25 possible
8-byte windows:

| win | full 32 B present | 8-byte windows found |
|---|---|---|
| 0–5 | **No** (6/6) | **0 / 25** for every block |

The block is never emitted in the clear anywhere in the capture — it exists
only inside the encrypted blob. So it is a *derived* value; there is no
side-channel leak of it to crib from.

---

## 4. Simple compositions of (S, head, cert, d0, d4, sha0) — all fail

Roughly 40 candidate laws per blob, over `S` (BE and LE), `head`, the cert
SHA-1 `fad0f10d…`, `SHA256("")`, the reconstructed `d0` (144 B) and `d4` (32 B):

* repetition/padding: `S*8`, `S*8_le`, `S||00*28`, `00*28||S`, `S*4||08*4`, …
* hashes: `sha256` / `sha1` / `sha1×2` / `md5×2` / `sha512-lo` over each of
  `head`, `S`, `d9`, `head+S`, `S+head`, `head+d9`, `d9+head`, `S+d9`, `d9+S`,
  `S_le`, `sha0`, `d0`, `d4`, `d0+S`, `d4+S`
* XORs: `head*2 ^ S*8`, `d4 ^ S*8`, `sha0 ^ sha256(S)`, …

**Result: 0 hits on all 6 genuine blobs, and 0 hits on all 8 instrumented
blobs.** In particular the block is *not* the cert SHA-1 XOR S, *not* S padded,
*not* head XOR S, and *not* d4 (d4 is 32 B and looks superficially similar, but
`blk ^ d4` is dense for all 6).

This matches the prior wider sweep in `blob_diff.md` §5 (2 197 permutation
messages + 169 HMAC pairs, zero preimages) — the search for a SHA preimage was
the wrong question.

---

## 5. Does the block change with S?

* Genuine: 6 distinct S, 6 distinct blocks.
* Instrumented: 7 distinct S over 8 rows. The one repeated S
  (`2949302830`, rows i=2 and i=4) is a **literal duplicate capture** —
  identical `blob` hex, identical `second`, identical `nsign_ts`, identical `H`.
  So the corpus contains **no** controlled same-S/different-block pair, and
  S-alone as the determinant is neither confirmed nor refuted.
* Across all distinct-S observations (14 of them) the block is always distinct.
* S overlap between the two families: **empty**.

---

## 6. Genuine vs instrumented — no distinguishing signal

| metric | genuine (6) | instrumented (8) |
|---|---|---|
| distinct blocks | 6 | 7 (one is the duplicated capture) |
| byte alphabet | 139 | 158 |
| bit-1 fraction | 0.4954 | 0.5151 |
| entropy (bits/byte) | 6.9975 | 7.1184 |
| zero bytes in pool | 1 | 2 |
| unique 8-byte windows | 150 | 175 |
| `tail2` | `0000` only | `0000` only |
| distinct heads | 6/6 | 7/8 |

* Cross-family block collisions: **0**
* Cross-family shared 8-byte windows: **0** (out of 150 and 175 respectively)
* Both families: identical record layout, identical cert SHA-1, identical
  constant runs, `tail2 = 0000`, same full-entropy profile.

**Conclusion: the server cannot distinguish a genuine from an instrumented blob
by inspecting the block, and neither can we.** Whatever separates them lies
elsewhere — consistent with `blob_diff.md` §8, which identifies the d0 head
selector phase as the failing variable.

---

## 7. Is the block encrypted in the blob?

`blob[46:78] == record[46:78]` is **False for all 6**. The ciphertext shares no
byte with the plaintext block. Forward round-trip
`whiten_forward(record, blob[:16]) == blob[16:160]` is **True 6/6**, confirming
the block sits inside the CBC whitening chain (chunks 2–3, so perturbing it
also perturbs every later chunk plus the 32-B digest). **The block is encrypted
in the wire blob; it is not stored in the clear.**

---

## 8. The answer: yes, Python computes it — it is a FinEx VM output

Driving `fin_vm2.FinEx` over descriptors rebuilt from scratch:

1. `S` read from the genuine record → `F._d4_words(S)` → `d4` (32 B);
2. `d0` head phase solved by search against the record's own head, then
   `F._d0_words(d4, head=phase)` → `d0` (144 B);
3. `d2` = the record's d2 word;
4. the claims string rebuilt from the device's own `sign_input` block via
   `desc10_law.build_desc10(map, kind)` → descriptor #10 (360 / 387 / 246 B);
5. constants: cert SHA-1 (d9), `bffffffffffffd1f0007000000000000` (d8),
   #5 = #6 = `00000000`, #7 = unpadded #10 length, #1 = #3 = empty;
6. descriptors in FinEx `VA_ORDER = [0,9,8,4,2,7,10,5,1,6,3]`, seeded with the
   signing second; blob taken from the canonical sink `0x5500000000`.

Result — **no knowledge of the block is fed in; it is predicted:**

| win | second | kind | desc10 | head phase | VM | block reproduced |
|---|---|---|---|---|---|---|
| 0 | 1790341508 | session | 360 B | `0x2b` | exit-clean | **YES** |
| 1 | 1790341509 | click | 387 B | `0x2b` | exit-clean | **YES** |
| 2 | 1790341510 | session | 360 B | `0x2b,0x48` | exit-clean | **YES** |
| 3 | 1790341511 | click | 387 B | `0x2b,0x48` | exit-clean | **no** (see below) |
| 4 | 1790341512 | attribution | 246 B | `0x2b,0x48` | exit-clean | **YES** |
| 5 | 1790341513 | attribution | 246 B | `0x2b` | exit-clean | **YES** |

**5 / 6 byte-exact.** `win0` predicted
`5502974ee7fe8fc2b5a4cf7fca0324b251af9bc3c051ff3cc56c90f341fe7ce8` — identical
to the captured block.

The `win3` miss differs in **exactly the 32 block bytes `[46:78)` and nowhere
else** — the rest of the 144-B record, including the independently-derived
`head`, `S`, and cert, all match. That localises the error to the claims string
for that one click, not to the block law. The two click signings (`win1` and
`win3`) use the same 32-key click profile and both yield 387 B, but they differ
in 92 characters of content (`android_uuid`, `app_version` 3.14.0 vs 3.13.9,
`created_at`, `gps_adid`, `installed_at`, `updated_at`), so the residual miss is a
`desc10` content/projection issue on that record, not a mystery in `[46:78)`.
A follow-up sweep re-ran the VM for all 32 single-key-drop variants of that
record's click profile: **none** reproduced the captured block, so the residual
is a multi-key content difference (that click was signed from a stale
3.13.9-era session with a different `gps_adid` and `android_uuid`), not a
wrong key set.

Note the solved head phases confirm the per-request phase table from
`blob_diff.md` §7: `(0x2b,)` for the pre-flight signings, `(0x2b,0x48)` for the
real request signings.

---

## 9. Bottom line for the Python goal

* The block is **fully computable** from inputs the pipeline already has:
  `S` (⇒ d0/d2/d4), the claims map (⇒ desc10), the signing second, and four
  pinned constants. **No unknown key, no server nonce, no hidden state.**
* `mint_pipeline` / `fin_vm2` already contain the machinery; the 5/6 result is a
  direct end-to-end proof on the un-instrumented winning capture.
* The block is **not** the discriminator between the booking and
  non-booking families. If the server rejects our mints, the block is not why
  — consistent with the existing conclusion that the **d0 head-selector phase**
  is the variable that must be supplied per request, since it is per-request
  device state that no existing code path derives.

## Files

* `block_pattern_analysis.py` — this analysis (`--nofinex` skips the ~90 s VM stage)
* `block_pattern_analysis.json` — machine-readable results
* Inputs: `win_capture/module_win_capture.log`, `pair_h3.json`,
  `win_capture/winning_material.json`
* Tools used: `whiten_decoder.py`, `F.py`, `fin_vm2.py`, `desc10_law.py`
