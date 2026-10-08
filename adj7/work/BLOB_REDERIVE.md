# BLOB_REDERIVE.md - independent re-derivation of the adj7 signature BLOB

Date: 2026-10-07.  Everything below was re-derived with fresh, from-scratch
implementations (`work/rederive/mylaws.py`) - no adj7_pure code was imported
for any law except an explicit bit-for-bit cross-comparison (PRNG) and a
block-level equivalence test (AES).  No project files were modified.

## 0. Data

30 unique adj7 blobs extracted (dedup by signature hex) from:

* raw TLS-decrypted stream `D:\advance_emu\ssl_interception\wire_dumps\app.adjust.com_dev2srv.bin`
  (145 requests, 145 Authorization headers; 18 adj7)
* `cap\nirio_16Feb\raw\*.txt` (12), `cap\payrupik_new\raw\*.txt` (4),
  `cap\burger\raw\*.txt` (3), `cap\hunchdate\raw\*.txt` (3) - overlapping the
  JSON exports; plus the `cap\*_adjust.json` Fiddler exports (same blobs).
  4 apps x all kinds: session, sdk_click/click, third_party_sharing,
  attribution, event.  Blob length is **304 bytes on all 30**.

## 1. Verdicts at a glance

| # | law | verdict |
|---|-----|---------|
| 1 | TAG = HMAC-SHA256(DK37, blob[16:272]) == blob[272:304] | **30/30 OK** |
| 2 | HEADER = BionicRand(signing second) | **29/30 OK**; 1 outlier (row 0) |
| 3 | CIPHER = **STANDARD AES-256-CBC**, IV = header | **30/30 OK** (re-encrypt byte-identical) |
| 4 | RECORD layout | **30/30 OK** (240-byte JSON + 16 x 0x10) |
| 5 | blob length 304 | **30/30** |

## 2. Laws as independently re-derived

### 2.1 Header (BionicRand)

Re-implemented from the description: state r[0..30]; seed = unix second
(&0xFFFFFFFF, 0->1); r[0] = seed as signed; r[i] = 16807*r[i-1] mod 2^31-1
(MINSTD chain); f=3, b=0; step: r[f] += r[b] (mod 2^32), store back as
signed-31 (v-2^32 if v >= 2^31-1), f/b advance mod 31, output = word >> 1;
310 warm-up steps; then 8 draws, XORed in adjacent pairs (d0^d1, d2^d3,
d4^d5, d6^d7), each 32-bit word big-endian -> 16 bytes.

* Cross-check vs `adj7_pure.make_header`: **0/2863 mismatches**
  (seconds 0..20000 step 7 + the recovered seconds + boundary seeds).
* **Seed rule on real devices: the signing second is the wall-clock second
  with the timestamp's numeric UTC offset APPLIED.**  The Adjust timestamps
  (`2026-10-07T01:10:48.959Z+0530`) carry a **bogus `Z`**: the wall clock is
  local (+0530 / +0300), and the device signs with `wallclock - offset`.
  Brute-forcing the whole +/-120 s window around the *as-UTC* reading finds
  nothing; around the *offset-applied* reading every blob but one hits.

### 2.2 Cipher

Wrote standard AES-256 from scratch (key schedule + block encrypt/decrypt),
validated against **FIPS-197 C.3** (`f3eed1bdb5d2a03c064b5a7e3db181f8`) and
**NIST SP800-38A F.2.5 AES-256-CBC** (4 blocks, both directions).  Then:

* **STANDARD AES-256-CBC (key = SEED, IV = blob[:16]) decrypts all 30 blob
  bodies into the exact JSON record** (regex + byte-exact template rebuild).
* Re-encrypting the record with standard AES-256-CBC under the same IV
  reproduces blob[16:272] **byte-identically, 30/30**.
* The task-brief/`adj7_pure` docstring description ("measured ShiftRows law
  new[r][c]=old[(r+c)%4][c], no final SubBytes, 15 round keys") is
  **numerically equivalent to standard AES-256**, and misleading as written:
    - `adj7_pure._shift_rows` == standard FIPS ShiftRows (it is the same
      permutation written in row-major naming; verified on 200 random blocks).
    - `spn_chunk`'s sequence ARK0,SB,(SR,MC,ARK,SB)x13,SR,ARK14 is exactly the
      standard 14-round sequence ARK0,(SB,SR,MC,ARK)x13,SB,SR,ARK14 re-bracketed
      (verified equal to my standard block on 50 random blocks and on all 30
      real CBC chains).  There is no separate "measured law" in effect.

### 2.3 Record (256 B)

Confirmed exactly, 30/30 (byte-exact rebuild):

```
'{ "a":  ' + str(u64le(nonce12[0:8])).rjust(20)
 + ' ,"b": "<64 upper hex>"'
 + ',"c": "<40-char cert SHA-1 upper hex>"'
 + ',"d": "<8 upper hex = nonce12[8:12]>"'
 + ',"e": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" }\x00'
  -> 240 bytes, then 16 x 0x10 padding -> 256.
```

* nonce12 == struct.pack('<Q', int(a)) || bytes.fromhex(d) - **30/30**.
* e == sha256('') upper - **30/30**.
* c slot per app (device ground truth):
    - `in.hanafintech`   = `C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF` (12/12, matches brief)
    - `social.hunch.app` = `AA92A18790F85D4E9B5199C7792C55F2FB0F61E1` (3/3, matches brief)
    - `com.fdjservices.nirio` = `0E11813DD360D8AAC04B6DB33293CFBC4D3F1370` (12/12;
      equals the SHA-1 of `apks/signer_v2_cert0.der` / `signer_v3_cert0.der`)
    - `com.burgerizzr.app` = **`F963DB904A1B9925C6C6444120FD2FCE2FF1F62A`** (3/3)
      -- **the brief's expected `F963DB904A1B64D0E75F2B063412F7C5A13C8D1E` is
      STALE/WRONG** (shares only the first 5 bytes).  The device records are
      unanimous, and the project's own `work/EVENT_BURGER_AUDIT.md` already
      records the same value.  No burger/hunch campaign exists in
      `campaign_data.py`/`apps.json`, so nothing live currently uses the stale
      value - but if the burger cert value is re-introduced from the old notes,
      it would corrupt both the record `c` slot and the commitment hash `b`.

## 3. Per-row table

Deltas: `d_cUTC` = signing second minus created_at second read as UTC (bogus-Z
reading); `d_cOFF` / `d_sOFF` = same vs created_at / sent_at with the numeric
offset applied (the correct reading).  All rows: law=STD (standard AES-256-CBC),
tag OK, record OK, blob 304 B.  `None` = no second found (row 0, see 4.2).

| row | src | kind | app | created_at | tag | len | d_cUTC | d_cOFF | d_sOFF | law | record | reenc |
|----:|-----|------|-----|------------|:---:|----:|-------:|-------:|-------:|:---:|:------:|:-----:|
| 0 | nirio_16Feb | session | nirio | 13:44:04.198 | OK | 304 | None | None | None | STD | OK | OK |
| 1 | nirio_16Feb | third_party_sharing | nirio | 13:44:04.198 | OK | 304 | -10800 | 0 | 0 | STD | OK | OK |
| 2 | nirio_16Feb | third_party_sharing | nirio | 13:44:04.198 | OK | 304 | -10791 | 9 | 0 | STD | OK | OK |
| 3 | nirio_16Feb | third_party_sharing | nirio | 13:44:04.209 | OK | 304 | -10769 | 31 | 1 | STD | OK | OK |
| 4 | nirio_16Feb | third_party_sharing | nirio | 13:44:04.220 | OK | 304 | -10750 | 50 | 0 | STD | OK | OK |
| 5 | nirio_16Feb | sdk_click | nirio | 13:44:04.252 | OK | 304 | -10800 | 0 | 0 | STD | OK | OK |
| 6 | nirio_16Feb | sdk_click | nirio | 13:44:13.681 | OK | 304 | -10800 | 0 | 0 | STD | OK | OK |
| 7 | nirio_16Feb | third_party_sharing | nirio | 13:44:54.127 | OK | 304 | -10744 | 56 | 0 | STD | OK | OK |
| 8 | nirio_16Feb | third_party_sharing | nirio | 13:47:11.750 | OK | 304 | -10793 | 7 | 0 | STD | OK | OK |
| 9 | nirio_16Feb | attribution | nirio | 13:47:18.539 | OK | 304 | -10800 | 0 | 0 | STD | OK | OK |
| 10 | nirio_16Feb | sdk_click | nirio | 13:47:18.545 | OK | 304 | -10800 | 0 | 0 | STD | OK | OK |
| 11 | nirio_16Feb | third_party_sharing | nirio | 13:47:26.234 | OK | 304 | -10800 | 0 | 0 | STD | OK | OK |
| 12 | wire_dev2srv | session | hanaf | 15:39:11.098 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 13 | wire_dev2srv | click | hanaf | 15:39:11.209 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 14 | wire_dev2srv | attribution | hanaf | 15:39:14.196 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 15 | wire_dev2srv | event | hanaf | 15:39:16.018 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 16 | payrupik_new+wire | session | hanaf | 15:47:38.430 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 17 | payrupik_new+wire | sdk_click | hanaf | 15:47:38.531 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 18 | payrupik_new+wire | attribution | hanaf | 15:47:41.741 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 19 | payrupik_new+wire | event | hanaf | 15:47:43.343 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 20 | wire_dev2srv | session | hanaf | 16:58:42.027 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 21 | wire_dev2srv | click | hanaf | 16:58:42.187 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 22 | wire_dev2srv | attribution | hanaf | 16:58:45.088 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 23 | wire_dev2srv | event | hanaf | 16:58:46.935 | OK | 304 | -19799 | 1 | 1 | STD | OK | OK |
| 24 | burger+wire | session | burger | 23:38:27.817 | OK | 304 | -19799 | 1 | 1 | STD | OK | OK |
| 25 | burger+wire | sdk_click | burger | 23:38:27.925 | OK | 304 | -19799 | 1 | 1 | STD | OK | OK |
| 26 | burger+wire | attribution | burger | 23:38:31.001 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 27 | hunchdate+wire | session | hunch | 01:10:48.959 | OK | 304 | -19799 | 1 | 0 | STD | OK | OK |
| 28 | hunchdate+wire | sdk_click | hunch | 01:10:49.068 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |
| 29 | hunchdate+wire | attribution | hunch | 01:10:52.479 | OK | 304 | -19800 | 0 | 0 | STD | OK | OK |

## 4. Findings / discrepancies

### 4.1 MAJOR - the Adjust timestamp `Z` is bogus; the signing second uses the offset

Every blob's header inverts to `make_header(second)` where
`second = created_at/sent_at wall-clock second MINUS the numeric offset`
(-19800 s for +0530, -10800 s for +0300).  Read as UTC (trusting the `Z`), the
delta is exactly minus the offset for all 29 hit rows - i.e. the device never
signs at the as-UTC instant.  Concretely, the recovered signing second equals
the **sent_at second (offset-applied) in 22 rows, +1 s in 6 rows** (signing ran
1 s past the sent_at stamp), and for 5 queued nirio retries it equals the
offset-applied **created_at second +7/+9/+31/+50/+56** - those were queued
(`enqueue_size=3..4`) and signed at dequeue, still 0/1 s off their own sent_at.
For any mint implementation this means: **seed the header PRNG with the same
clock the device used - wall clock minus the local offset - or equivalently
with `parse(ts_wallclock_without_offset)`; trusting the `Z` puts the signature
5.5 h (or 3 h) off vs the device's behaviour.**  (What the SERVER accepts is a
separate question; the device law is as stated.)

### 4.2 MAJOR - row 0 (nirio sid-90 session, `90_c.txt`) has no seed

`blob[:16] = 3E3B6EC1041DFB7154F0C731513E2AA9` matches **no second anywhere in
+/-30 days** of the capture (full numpy sweep of 5,184,001 seeds over the bionic
law - XOR-pair and raw-4 layouts, draw offsets 0-40) and **no second within
+/-2 h** under ~50 structural PRNG variants (warm-ups 0/10/31/100/310/311/1000;
XOR adjacent/cross/raw/raw-no-shift; big/little endian; draw counts 4/8/12/16;
MINSTD; java.util.Random; seed-chain mod 2^31-1 / 2^31 / 2^32; f/b inits
(3,0)(0,0)(3,3)(0,3)(1,0)(2,1)(31,0); ms-based and 32-bit-truncated seeds).
The blob is otherwise a perfect adj7 blob (tag OK, standard-AES record
decrypts/re-encrypts byte-exact), so the constants are right and only this one
header defies the seed law.  The project's own README (`adj7/README.md:96`)
already concedes "header 11/12" on this capture.  The README's guess ("signed
in an earlier app process") is NOT supported: an earlier process would still be
inside the +/-30-day window.  Treat as an unexplained outlier - 29/29 resolvable
blobs still establish the header law beyond doubt.

### 4.3 MODERATE - the "measured AES law" description is wrong (implementation is standard)

`adj7_pure.py`'s docstring/comments (and the task brief) describe a non-standard
cipher: "measured ShiftRows law", "no final SubBytes", "15 round keys".  The
implementation is, in fact, **textbook AES-256** (`_shift_rows` is the standard
ShiftRows in row-major naming; `spn_chunk` re-brackets the standard round
sequence).  Verified numerically; zero behavioural difference.  Risk: someone
"fixing" the code to match the description (or re-implementing from it, as
attempted here first) will produce a *different*, wrong cipher.

### 4.4 MODERATE - stale burger cert SHA-1 in the brief

See 2.3.  Device truth: `F963DB904A1B9925C6C6444120FD2FCE2FF1F62A`.

### 4.5 Confirmed (no discrepancy)

* TAG law, DK37 - 30/30.
* Record layout incl. 240-byte JSON + 16x0x10 pad (the `adj7_pure` docstring's
  `"+ 0x10 * 16"` is correct; the task brief's "0x10*pad to 256" likewise).
* nonce12 = u64le(a) || d - 30/30.
* cert40 for hanafintech/hunch/nirio - match expected/project values.
* blob length 304 - 30/30.
* Two same-second requests (nirio 27_c tps + 28_c sdk_click, created
  13:44:04.198/252) share the identical 16-byte header, as the deterministic
  per-second reseed law predicts.

## 5. Reproduction

* `work/rederive/mylaws.py` - independent laws (BionicRand, AES-256 std+variants, tag, record).
* `work/rederive/extract_wire3.py`, `extract_raw.py`, `build_master.py` - blob extraction (30 unique).
* `work/rederive/verify_all.py` - per-blob verification; `final_table.json` - table data.
* `work/rederive/sweep_row0.py`, `sweep_row0b.py`, `alt_laws*.py` - row-0 investigation.
* AES validation: FIPS-197 C.3 + NIST SP800-38A F.2.5 (both directions) - PASS.
* PRNG cross-check vs `adj7_pure.make_header`: 2863 seeds, bit-for-bit equal.
