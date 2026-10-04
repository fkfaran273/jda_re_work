# _sub_unseal_RESULT.md — adj9 body-whitening inversion and iOS decryption

Date: 2026-10-01. Assets: `adj9_signer.py` (read-only), capture
`C:\Users\Apps\Downloads\cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz`,
`_sub_ios_timing.json` (context only).
Scripts (this folder): `_sub_unseal_core.py` (inverse + validation),
`_sub_unseal_ios.py` (extraction + decryption + verdicts).
Machine-readable outputs: `_sub_unseal_core_out.json`, `_sub_unseal_ios_out.json`.
No existing file was modified.

---

## 1. whiten_inverse — implementation

Exact inverse of `whiten_forward` (adj9_signer PART 5). Forward chunk law:

```
x = chunk ^ wa                          # wa_0 = header, wa_k = ciphertext[k-1]
repeat 14 rounds r = 0..13:  x ^= KB[16r:16r+16];  x = SBOX(x);  x = PI(x)
                             if r < 13: x = F(x)      # GF(2) linear mix
x ^= KB[224:240]                        # final sweep key
```

Inversion runs the chunk backwards: `^ FINAL_KEY` → for r = 13..0:
`F^-1 (r<13)` → `PI^-1` → `SBOX^-1` → `^ ROUND_KEYS[r]` → finally `^ wa`.
Concretely:

* **F^-1** — F is GF(2)-linear: the 32 row masks `F_ROWS` were inverted by
  Gaussian elimination into `F_ROWS_INV` and re-tabled through the signer's own
  `_byte_tables` (same 4×256 byte-table application, inverse rows).
* **PI^-1** — `_pi1` is `out[_PI[i]] = in[i]`, so the inverse is
  `in[i] = out[_PI[i]]` (PI verified a permutation).
* **SBOX^-1** — 256-entry inverse table (SBOX verified bijective).
* **CBC** — the chain value is the *ciphertext* chunk, so inversion needs no
  recursion: decrypt chunk k with `wa = header` (k=0) or `body[16(k-1):16k]`.

## 2. Validation (before touching iOS) — PASS

**(a) Round-trip.** 1000 random 144-byte records × random 16-byte headers:
`whiten_inverse(whiten_forward(rec, hdr), hdr) == rec` — **1000/1000 OK**.

**(b) Android gold vectors.** For each of the 9 embedded captures
(3 creditsea SDK-5.8.0 + 6 penti SDK-5.7.0):

| check | result |
|---|---|
| `sign_pure(second, S, map, d9, kind, head)` reproduces stored blob byte-exactly | 9/9 |
| `blob[:16] == make_header(second)` | 9/9 |
| `predict_digest(body) == blob[160:192]` | 9/9 |
| unsealed record == `build_record(S, head16_for(S, head), claims, d9)` | 9/9 |
| magic `01 00 08` @0..2; `SHA256("")` @79..110; `00*14` @114..127; `0e*14` @130..143; cert SHA-1 @25..44 == stored `d9_hex` | 9/9 all |

Head-phase search sanity: the search (section 4) run on the gold records alone
rediscovered the stored phases `[43]` / `[43, 72]` for 9/9 vectors.

## 3. iOS decryption — THE VERDICT: the body cipher IS shared

All 30 adj9-signed requests in the capture were extracted from `raw/*_c.txt`
(`signature="..."` → 192-byte blob; 30/30 match `_sub_ios_timing.json`'s file
set and `signature_b64`; Client-SDK `ios5.8.0`; paths on
consent.adjust.com/.io: sdk_click ×3, session ×1, event ×25, attribution ×1).
For every blob: header = blob[:16], body = blob[16:160], digest = blob[160:192].

**Result counts over the 30 unsealed records:**

| record law | iOS result |
|---|---|
| digest `predict_digest(body) == blob[160:192]` (MAC key K) | **30/30 OK** |
| magic `01 00 08` @0..2 | **30/30 OK** |
| `0x02` separator @19, `0x03` @24, `0x04` @45, `0x05` @78 | **30/30 OK** |
| `SHA256("")` @79..110 | **30/30 OK** |
| `0x06` @111, `0x07` @113 | **30/30 OK** |
| `00 00` @128..129, `0e*14` @130..143 | **30/30 OK** |
| S field BE32 @20..23 (see table below) | **30/30 OK** (30 distinct seeds, 123986850..4039111016) |
| byte @112 | iOS = `0x02` on 30/30 — Android record has `0x01` (descriptor-#7 variant flag) |
| field @114..129 (16 B) | iOS = `"iPhone13,2" + 6×00` on 30/30 — Android has 16 zero bytes |
| cert SHA-1 @25..44 | iOS = `0000000000000000000000000000000000000000` on 30/30 (constant, all-zero) |

**Verdict: the body whitening cipher, the digest MAC key K, and the record
container law are shared between Android and iOS.** The digest (custom
double-padded SHA-256 MAC with the secret K) verifies on 30/30 bodies, and
unsealing with the blob-carried header yields records whose magic, separator
ladder, SHA256("") constant, zero/`0e` tail, seed field and region-law d0 head
all reproduce. The only deviations are three iOS *payload* choices inside the
same container, not cipher differences:

1. **descriptor-#7 variant byte @112 is `0x02`** (Android `0x01`) — and the
   16-byte field after `07` carries the **device name** (`iPhone13,2`,
   zero-padded to 16) instead of Android's 16 zero bytes. Note the same string
   appears as `device_name=iPhone13%2C2` in the attribution POST body.
2. **cert SHA-1 (d9) is 20 zero bytes** — the iOS build does not carry an APK
   cert; it uses an all-zero placeholder, constant across all 30 records.
3. The record's BLOCK (@46..78, `sha256_iv2` with IV2) was not re-verified
   because that would require the iOS claims law (the claims string is not in
   the record; the presence-filtered key list in the signer is Android-keyed).

### Extracted iOS constants

* **cert SHA-1 (bytes 25..44):** `0000000000000000000000000000000000000000` —
  constant across all 30 records.
* **S (bytes 20..23, BE)** and **d0 head (bytes 3..18)** per record:

| file | S | cert SHA-1 (25..44) | d0 head (3..18) |
|---|---|---|---|
| 0142_c.txt | 3702265801 | 0000000000000000000000000000000000000000 | 3b2de77488ed52353dace1f58e6c0ff7 |
| 0143_c.txt | 3927906798 | 0000000000000000000000000000000000000000 | c839f68f85d28f85fcd8c26eb13397bf |
| 0144_c.txt | 2707084985 | 0000000000000000000000000000000000000000 | f0c3219acc469587785ba90244de5b77 |
| 0157_c.txt | 3844490772 | 0000000000000000000000000000000000000000 | 1d05926d9c5d64ac6a9ce5f4ebc49b3c |
| 0170_c.txt | 2116021225 | 0000000000000000000000000000000000000000 | 7c13b72e21e3f140678dacb03a7d2bc2 |
| 0454_c.txt | 1908119704 | 0000000000000000000000000000000000000000 | 06c3f4e35389b6b411dee3fe4494939b |
| 1068_c.txt | 2196634309 | 0000000000000000000000000000000000000000 | e447ed1307625cd1b6a0bff455850dd8 |
| 1144_c.txt | 1566286221 | 0000000000000000000000000000000000000000 | 48679ea7eb0c54fd2156f796823d12ee |
| 1303_c.txt | 1802265904 | 0000000000000000000000000000000000000000 | e75d3c4646d59e62e4f13fea4579afbb |
| 1311_c.txt | 3934469482 | 0000000000000000000000000000000000000000 | 51b4fbba1ac13f55de2e7420955bb88d |
| 1427_c.txt | 1866504305 | 0000000000000000000000000000000000000000 | 3eb562137cdc34fb2a347692685df15b |
| 1443_c.txt | 1680858891 | 0000000000000000000000000000000000000000 | 7d6ff248a07ac02c921e1d394f0b297c |
| 1451_c.txt | 3054962868 | 0000000000000000000000000000000000000000 | 439f7baee19bd28048b57084eab17429 |
| 1678_c.txt | 504210818 | 0000000000000000000000000000000000000000 | 34cd3748a488fc766fb66c33fff3ee14 |
| 1908_c.txt | 123986850 | 0000000000000000000000000000000000000000 | 872fb1a4ae3ca3b0bc288aa3953bdc75 |
| 1949_c.txt | 4039111016 | 0000000000000000000000000000000000000000 | 0bd1b7e97b9e93e75f90e3a82fdf66ae |
| 2155_c.txt | 687368540 | 0000000000000000000000000000000000000000 | 4bd2587dcb70d8934b9e5831cb3cdffa |
| 2545_c.txt | 3908185915 | 0000000000000000000000000000000000000000 | a445029f69734cf9271581cfea23e559 |
| 2564_c.txt | 228037877 | 0000000000000000000000000000000000000000 | efd3300ae46b43be97df48069c677263 |
| 2688_c.txt | 1461514703 | 0000000000000000000000000000000000000000 | c46f9d1a854e9e7f862bdf5ec70a9e9d |
| 2719_c.txt | 2918051255 | 0000000000000000000000000000000000000000 | a8bf9231f3a5967af7eecd60acf492f8 |
| 2758_c.txt | 3003948844 | 0000000000000000000000000000000000000000 | 2e656edbe52b11359ac5da7b518b2499 |
| 2795_c.txt | 1537529561 | 0000000000000000000000000000000000000000 | 62c87a9fd2cf6cc3c493dcc474948cca |
| 2831_c.txt | 443754508 | 0000000000000000000000000000000000000000 | 3c218c7f082db9583d0a8d5409064c71 |
| 2864_c.txt | 3134259674 | 0000000000000000000000000000000000000000 | fce76a56aac32d59edcc7b7dbbe876f0 |
| 2903_c.txt | 641933355 | 0000000000000000000000000000000000000000 | 8098d03966941e1fa8b2f8134ebed611 |
| 2925_c.txt | 3531093951 | 0000000000000000000000000000000000000000 | ec3a8e9ac4b69544df68bdc8f7e47d95 |
| 2959_c.txt | 3459211528 | 0000000000000000000000000000000000000000 | bd05bd334acdad895a775a41adbfa523 |
| 3260_c.txt | 3138080565 | 0000000000000000000000000000000000000000 | 376a4cdd87eee92f221c59ab929866d8 |
| 3429_c.txt | 2849517773 | 0000000000000000000000000000000000000000 | 501723339cc7055bbaafc98b767fd6c3 |

### First 3 unsealed iOS records (full hex)

```
0142_c.txt  S=3702265801  cert=0000...0000
  000: 01 00 08 3b 2d e7 74 88 ed 52 35 3d ac e1 f5 8e  ...;-.t..R5=....
  010: 6c 0f f7 02 dc ac 17 c9 03 00 00 00 00 00 00 00  l...............
  020: 00 00 00 00 00 00 00 00 00 00 00 00 00 04 41 ec  ..............A.
  030: fb 18 d6 af 59 6f 91 ee 56 bd f6 43 16 4e 8d 94  ....Yo..V..C.N..
  040: 2d fa cd 2d 0d ba cd 5c 88 01 c6 42 25 56 05 e3  -..-...\...B%V..
  050: b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27  ..B.........o.$'
  060: ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55 06  .A.d..L....xR.U.
  070: 02 07 69 50 68 6f 6e 65 31 33 2c 32 00 00 00 00  ..iPhone13,2....
  080: 00 00 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e  ................

0143_c.txt  S=3927906798  cert=0000...0000
  000: 01 00 08 c8 39 f6 8f 85 d2 8f 85 fc d8 c2 6e b1  ....9.........n.
  010: 33 97 bf 02 ea 1f 19 ee 03 00 00 00 00 00 00 00  3...............
  020: 00 00 00 00 00 00 00 00 00 00 00 00 00 04 97 92  ................
  030: 3a e4 f8 ff e2 43 05 3a 2b a3 8d 17 15 a3 81 9a  :....C.:+.......
  040: 7e 39 5f 46 59 ff f3 bb ee ac 6c 95 5c 0a 05 e3  ~9_FY.....l.\...
  050: b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27  ..B.........o.$'
  060: ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55 06  .A.d..L....xR.U.
  070: 02 07 69 50 68 6f 6e 65 31 33 2c 32 00 00 00 00  ..iPhone13,2....
  080: 00 00 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e  ................

0144_c.txt  S=2707084985  cert=0000...0000
  000: 01 00 08 f0 c3 21 9a cc 46 95 87 78 5b a9 02 44  .....!..F..x[...
  010: de 5b 77 02 a1 5a d6 b9 03 00 00 00 00 00 00 00  .[w..Z..........
  020: 00 00 00 00 00 00 00 00 00 00 00 00 00 04 a4 5c  ...............\.
  030: 7a 76 76 e5 ba e1 9c 32 03 fc 49 f5 ac 2f e3 8f  zvv....2..I../..
  040: 7b d7 59 00 8f 12 57 33 7d 51 a5 c2 1c 26 05 e3  {.Y...W3}Q...&..
  050: b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27  ..B.........o.$'
  060: ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55 06  .A.d..L....xR.U.
  070: 02 07 69 50 68 6f 6e 65 31 33 2c 32 00 00 00 00  ..iPhone13,2....
  080: 00 00 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e 0e  ................
```

Note the shared prefix visible in bytes 80..95 across records — that is
`SHA256("")` at record offset 79..110 (`b0c44298fc1c149afbf4c8996fb92427ae41e4
649b934ca495991b7852b855` continuing into the next row), exactly as in the
Android record law.

## 4. Region-law bonus — the d0 head reproduces from `region(S)`

The record's d0 head (bytes 3..18) is the first four d0 words: 8 selector
halfwords, read big-endian. For each iOS record, with
`source = _d0_source(_d4_words(S))` derived from the record's own S:

* selector positions 2..7 match the stable cycle `0x40|(i&7)` — **30/30**;
* selector positions 0..1 are reproduced by the head phase **`(0x40,)`**
  (equivalently `(0x40, 0x41)` — for a length-1 phase selector[1] is the cycle
  value `0x41`, so both spellings yield identical bytes; verified
  `head16_for(S, (0x40,)) == head16_for(S, (0x40,0x41))`);
* `head16_for(S, head)` == record bytes 3..19 — **30/30**;
* the phase differs from Android's request-signing phase `(0x2B,)` /
  `(0x2B, 0x48)` — i.e. iOS uses selector literal `0x40` where Android used
  `0x2B` (HEAD_FIRST). Since `0x40 = 0x40|(0&7)`, the iOS head is simply the
  cycle entered at index 0.

So `region(S)` with `head=(0x40,)` fully materializes the iOS d0 head: the
region law (shuffle + bit-transpose + selector expansion) is also shared; only
the free selector-phase choice differs per platform/campaign.

## 5. Header (blob[:16]) status — context

The 30 blobs carry 28 distinct headers (sids 142/143/144 share one header, as
`_sub_alg_RESULT.md` already noted). `make_header(second)` — the Android bionic
`Random3` law — matches **0/30** iOS headers, both at the timing JSON's candidate
seconds and across a ±10 s sweep around them. This is consistent with
`_sub_alg_RESULT.md`: the iOS header generator shares the 31-bit big-endian
XOR-pair shape but is not the bionic law. It does not affect body decryption —
the header rides inside the blob and doubles as the whitening CBC IV. (The
`authorization.header16_hex` in `_sub_ios_timing.json` is a constant 27-byte
adj_verification fragment, not the per-request header — see that report's
section 0.)

## 6. Bottom line

* `whiten_inverse` (in `_sub_unseal_core.py`) is validated: 1000/1000
  round-trips, 9/9 Android gold vectors byte-exact end-to-end.
* **The adj9 body cipher is shared between Android and iOS**: digest MAC 30/30,
  magic/separators/SHA256("")/tails 30/30, region d0 law 30/30 with head phase
  `(0x40,)`.
* iOS record constants: **cert SHA-1 = 20 zero bytes** (constant, all 30);
  per-record **S** and **d0 head** in the table above; descriptor-#7 variant
  byte `0x02` with the device name `iPhone13,2` in the 16-byte field at
  114..129 (Android: `0x01` + 16 zero bytes).
