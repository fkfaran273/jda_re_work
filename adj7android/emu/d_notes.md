# d_notes.md — adj7 Android (libsigner.so 3.62.0) TAG law + RECORD/CLAIMS layout

Date: 2026-10-08. Everything below verified on emu mints AND real device
captures (payruki, hunch). Scripts: `d_tag.py`, `d_record.py`,
`d_tagtest.py`, `d_ydecode.py`, `d_record_mint.py`, `d_record_mint2.py`.

## 1. TAG LAW (blob[272:304]) — CRACKED

```
blob(304) = header(16) || body(256) || tag(32)
tag       = HMAC-SHA256(K, body)        # body in FINAL byte order, no header
K         = 2A4CC07960D647623CC386DCEFAFBF25
            B669914D32CC8585A1ED7F920EF591EB
```

Verification matrix (all field-exact):
- 7/7 emu mints: b_mints.json (garbage nonce), a_cache/pt1, p1..p4
  (seconds 1791358552 / 1791358652, nonces 0011..AABB / CCDDEEFF..,
  params session/event/os_version 12-13), d_rec_mint.json
  (attribution + 8 pool keys).
- **payruki capture 5/5 blobs (incl. sid 67)**, **hunch capture 3/3 blobs**
  — real devices, real signatures. K is a *build constant of the .so*,
  identical across apps/seconds/nonces/params.

Why earlier scans missed it: the HMAC is executed inside the LE-word staging
arena (every dword stored as BE value; the SHA core consumes dword-BE = final
byte order), so the *message* is the plain body — but the *key* never exists
as a contiguous window in the .so, libdata, stack or the post-mint heap
(checked: plain/xor-1byte-mask/swap4/rev/dword-rot windows; sha256 of every
<=192-B window (10.2M) and aligned region of the .so; sha256^2 windows — all
negative). K is produced by the obfuscated derivation VM whose scratch table
lives at heap 0x900f080..0x900f140 ((len,ptr) slots, writer rvas
0x110a28/0x110a40/0x11145c/0x111460/0x111154/0x111160; K dwords transit there
before reaching the staging arena).

**K extraction recipe for any new .so build** (b_ytrace.py hook): run one
mint with a write hook on the blob staging arena Y; K = the 8 dwords written
at Y+0..28 immediately BEFORE the 0x36363636 ipad block (write them BE).
Full HMAC arena sequence (mint1, Y=0x9004e20, writer rva 0x1102b4):
1. Y+0..28  <- K (BE dwords)
2. Y+32..60 <- 00*32 (zero-pad of key block to 64)
3. Y+0..28  <- K^0x36
4. Y+32..60 <- 36*32
5. Y+64..316 <- body ciphertext (message)
6. Y+0..28  <- inner = SHA256(K^36||36^32||body)
7. Y+0..28  <- K^0x5C
8. Y+32..60 <- 5C*32
9. Y+64..92 <- inner
10. Y+0..28 <- TAG (copied to Y+272..300; then rev-copy loop rva 0x10f834
   dword-reverses the whole blob into the output home and SetByteArrayRegion
   emits it).

## 2. RECORD LAYOUT (plaintext inside body, pre-SPN) — PINNED

Fixed 239-byte JSON template + NUL + 0x10*16 = 256 B exactly:

```
{ "a":<a rjust 22> ,"b": "<64 hex>","c": "<40 raw NUL bytes>","d": "<8 hex>","e": "<64 hex>" }\0 + 10*16h
```

verbatim examples (byte-exact, captured via staging-arena snapshots):

mint1 (params app_token/package_name/activity_kind=session/client_sdk):
```
{ "a":  11513738137359379900 ,"b": "86B8F1E565CAFB78E88E4E8ED1AD987BA8C3FA5D14E09A0FF2C1DA85319C7791","c": "\0*\x40","d": "00000000","e": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" }\0
```
mint2 (claims-bearing: +app_version/environment/event_token/os_name/os_version/seq=9, activity_kind=attribution):
```
{ "a":   7929136032687195261 ,"b": "BDCFFCBACB96096B39AB4586713B393E88E4773DF8D5B2F5E847B5C38F9D9C29","c": "\0*\x40","d": "00112233","e": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" }\0
```

Field laws:
- **a**: decimal u64 right-justified to width 22 after `{ "a":` (20-digit a ->
  2 spaces, 19-digit -> 3 spaces — hence the two-space look). Known values:
  11513738137359379900 = 0x9FC903D5622C6DBC, 7929136032687195261 =
  0x6E09F3361C12047D. Derivation from the nonce/entropy path is the
  obfuscated VM's (not a plain hash of the nonce or the 2048-B urandom
  buffer — tested). OPEN.
- **b**: 32 raw bytes hex-upper; VARIES with params/claims. NOT
  sha256/sha512/hmac(K,.) of the claims string or obvious combos (tested
  with two constraints). OPEN — two known (claims -> b) pairs in d_record.py.
- **c**: 40 raw NUL bytes (iOS uses ASCII '0'*40; Android stores NULs).
- **d**: hex-upper of nonce[0:4] ("00112233" for nonce 0011223344556677-
  889AABB, "00000000" unforced).
- **e**: sha256("") hex-upper in BOTH mints — the e-hash input was empty
  even while a claims string existed. (On real devices it may hash
  something non-empty; not verifiable until the body SPN is cracked.)
- **claims are NOT embedded in the record text** (mint2 record has no claims
  despite 89 B of claims present) — the claims feed b (derivation open).

## 3. CLAIMS STRING LAW — PINNED

Values (no separators) of every present key of the 98-key pool, concatenated
in POOL LIST ORDER, with the pin `1300000` + (seq value, or `0` when seq
absent) injected at seq's position. The pool list sits xor-0x16-masked in
.data at 0x11e9c0 (sorted list, then block2 `activity_kind,client_sdk`
appended last).

```
mint1: smxi7gqwu39c + in.hanafintech + 1300000 + 0 + session + android5.6.0
mint2: smxi7gqwu39c3.0.4productionabcdefandroid12in.hanafintech13000009attributionandroid5.6.0
```

## 4. Open items (for the body-cipher follow-up)

- SPN body cipher: 12-round AES-like, no-final-SubBytes suspicion; the
  per-mint 12x16-B round-key block is at heap 0x900e3e8 (dword&0xFF per
  dword, keyblock192.bin); a_spn.py variants all miss. Body chunks decrypt
  starting `{ "a":  ` with IV = header (swap-domain care).
- b-field derivation (2 pairs known), a-field derivation (2 values known),
  K's derivation chain inside the 0x900f080 table VM.

## 5. Files

- `d_tag.py` — tag law impl + checker (15/15: 7 emu + 5 payruki + 3 hunch).
- `d_record.py` — record template impl + claims/b/a reference data.
- `d_tagtest.py` — the (negative) contiguous-key scan; documents why K is
  not a memory window.
- `d_ydecode.py` + `d_ydecoded.txt` — full decoded staging-arena write log
  (HMAC sequence, record passes, claims, a-decimal conversion).
- `d_record_mint.py` / `d_record_mint2.py` + `d_rec_mint.json` /
  `d_rec_mint2.json` — the two instrumented mints (claims log, record
  snapshots, blob reproduced byte-exact across passes).
