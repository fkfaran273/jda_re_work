# CRYPTO_AUDIT.md — byte-level audit of the adj7 signature crypto path

Date: 2026-10-06. Scope: `adj7/work/myrun/adj7_pure.py` (signer copy under test)
vs first principles + `adj7/work/spn_law2.py` (independent closed-form reference).
Offline only: zero requests to app.adjust.com. Read-only everywhere except new
files under `adj7/work/myrun/verify_so/crypto/` (`audit_run.py`,
`supp_round_claims.py`, `audit_output.txt`, `audit_results.json`, this report).
No original was edited; nothing was overwritten.

Vectors: genuine payrupik sids 42/43/44 from
`adj7/cap/payrupik_new/payrupik_new__adjust.json` (304-B blobs, sid44
`created_at=2026-10-06T15:47:41.741Z+0530` → second 1791281861,
nonce `deb8d66011fc70a885006809`, cert
`C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF`); hanaf attribution vector from
`adj7/work/hanaf_verify.json` (nonce `0cdfe7304edbe4b598457008`, A
`13106841944429420300`, D `98457008`); emulator mint `adj7/work/v3_blob.hex`.
Runner: `crypto/audit_run.py` — 69 checks, **69 PASS / 0 FAIL**
(`crypto/audit_results.json`); supplement `crypto/supp_round_claims.py`.

Line refs below are `adj7/work/myrun/adj7_pure.py` unless marked `spn_law2.py`
(`adj7/work/spn_law2.py`).

## 1. Record template — PASS

- Exact template (`adj7_pure.py:229-239` `build_record`; `spn_law2.py:320`):
  `{ "a":  ` + A(20) + ` ,"b": "` + H(64) + `","c": "` + cert40(40) +
  `","d": "` + D8(8) + `","e": "` + E64(64) + `" }` + `\x00`, then `0x10`-fill
  to 256. Byte decomposition of the head literal: `7B 20 22 61 22 3A 20 20`
  (`{`, space, `"a"`, `:`, **two** spaces before the 20-char A slot); field
  separators ` ,"b": "`, `","c": "`, `","d": "`, `","e": "`; field order
  a,b,c,d,e. Checks 1a (hand-concat == `build_record`, jlen 240/pad 16 on the
  hanaf vector), 1b (6 literals in order) PASS.
- A-field width/pad: `str(u64le(nonce12[0:8])).rjust(20)` — pad char is
  U+0020 SPACE (Python `str.rjust` default; 1e proves `"1".rjust(3)=="  1"`).
  20-char A slot confirmed on zero-nonce vector (`19×0x20 + "0"`, 1d) and on
  genuine sid44 (`A=b'12137478147332815070'`, 20 chars, no pad needed, 4m).
- H/d8/e hex case: UPPER in all three slots (`H.hex().upper()`,
  `nonce[8:12].hex().upper()`, `SHA0_HEX` upper). Genuine sid44 record slots
  match `[0-9A-F]` regex and `== .upper()` (4o); e == `SHA0_HEX`
  `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` (4p).
- `\x00` terminator: at `j` end — genuine bytes `...B855" }\x00\x10\x10...`,
  `find(b'" }\x00')`=236 on the hanaf rebuild, same shape on sid44 (1i, 4q).
- Pad math: `record = j + b"\x10" * (256 - len(j))`, j **includes** the
  `\x00` (hanaf vector: j=240, pad=16; sid44: j=240, pad=16 — same length is
  coincidence of 20-char A in both). Pad bytes all `0x10`, total 256 (1j, 1k,
  4q). `spn_law2.py:328` (`js + b"\x00" + b"\x10"*(256-len(js)-1)`) is
  algebraically identical.
- Hand rebuild == genuine: independent inline concat == `build_record` ==
  fresh-decrypted sid44 record, byte-exact (4r, 4s). PASS.

## 2. Header (bionic rand) — PASS

- Construction (`adj7_pure.py:94-136`; `spn_law2.py:178-219`): Schrage
  `16807/2^31-1` fill of 31 words, `f=3,b=0`, additive
  `v=(r[f]+r[b])&0xFFFFFFFF`, signed store (`v if v<M else v-2^32`),
  output `v>>1`; **310-draw warm-up**, **8 draws**, pair-XOR
  `w[i]=d[2i]^d[2i+1]`, **big-endian** `to_bytes(4,"big")`.
- Fuzz my-vs-ref: 24 seeds — 0,1,2,3,310,311, 2^31-1, 2^31, 2^31+1, 2^32-1,
  2^32-2, 2^32, 2^32+1, -1, -2, -2^31, -2^31-1, 123456789, 1771238644,
  1789382946, 2147483647, 4294967295, 9999999999, -9999999999 — all 16-B
  identical (2a, 2i). Third fresh reimplementation (Schrage + additive,
  written inline in the runner) matches on all 24 (2b).
- Warm-up 310 load-bearing: 309/311 warm-ups both differ at seed 1771238644
  (2c). Draws==8 structural: 8 draws → 4 XOR words → 16 B (2d).
- Pair-XOR load-bearing: raw first-4-draws != XORed header (2g); manual
  `d[2i]^d[2i+1]` recomputation == `make_header` (2e).
- Big-endian: LE packing differs (`be=66e7ca68…` vs `le=68cae766…`,
  seed 1771238644) — BE confirmed (2f).
- Edge seeds: `seed&0xFFFFFFFF or 1` (0→1), `s<2^31 else s-2^32` signed fold
  — no crash, 16-B output on every edge/negative/oversize seed (2i).
  Schrage negative-`prev` branch (`_schrage`, `adj7_pure.py:98-105`) is
  exercised by the negative seeds in the fuzz set.
- Draws are 31-bit (`v>>1`, max 2147469841/200 draws, 2h).
- Genuine: `make_header(1791281861) == BLOB44[:16]` (`29FC17E9…`), my and ref
  both (2j). PASS.

## 3. Commitment hash (custom-IV SHA-256) — PASS

- Message: `prefix(40) || nonce12(12) || SHA0_HEX ASCII(64) || claims`
  (`adj7_pure.py:220-226`; `spn_law2.py:291-316`). `IV0 =
  16ba6d02 11a298c2 82187e46 4c148c22 3a5cbc15 06519f14 97b9e370 08ec3bec`
  (`adj7_pure.py:59-60`) == `spn_law2.py:270-271` bytes (3a), != standard
  SHA-256 IV (3b).
- Padding edge cases: fresh independent compression implementation in the
  runner validates against `hashlib.sha256` (standard IV) on 130+ lengths
  incl. 55/56/63/64/119/120/127/128/200/1000 (3c) — padding
  `msg+b"\x80"+b"\x00"*((55-len)%64)+>Q(bitlen)` and the compression
  function are correct. `my.sha256_iv0` == fresh-custom-IV impl on
  0,1,55,56,63,64,119,120,119,120-equivalents,1000 (3d).
- Boundary claims: msg len = 116+N; N chosen for msg%64 ∈ {55,56,63,0,1,59}
  (N=3,4,11,12,13,7): my == ref == fresh on all 6, incl. the two-block
  (N=12, len 128) and 0x80-second-block (N=3..11) transitions (3e).
- Prefix selection: `cert40` vs `00*40` give different H on identical
  claims+nonce (`1e7fc4b8…` vs `d64f5a0c…`, 3f) — branch is load-bearing.
  Genuine selection is cert40: sid44 claims(211 B, block2
  attribution/android5.6.0) → H `599E004527744E84…` == record `b` slot
  (supplement); same H==record-b on sids 42 (nonce `574ef5bfed63fd91e4b94d81`)
  and 43 (nonce `5e5f73decbad4b6f51c145a2`).
- `SHA0_HEX` == `sha256(b"").hexdigest().upper()` (3g); claims encoded
  `latin1` — byte `0xE9` (`café`) survives into claims (3h).
- Pad-formula note: `(55-len)%64` (`adj7_pure.py:212`) ≡ `(55-len%64)%64`
  (`spn_law2.py:295`) for all L in 0..299 (3i) — same function, no
  divergence. PASS.

## 4. AES-256-CBC — PASS

- S-box: `my.AES_SBOX` (`adj7_pure.py:267-268`, generated via GF-inverse +
  affine `y^rot1^rot2^rot3^rot4^0x63`) == FIPS-197 literal ==
  `ref.AES_SBOX` (`spn_law2.py:47-55`), `my[0:4]=637c777b` (4a).
- Key schedule (`adj7_pure.py:271-283`; `spn_law2.py:119-135`): textbook
  AES-256 — RotWord+SubWord+Rcon at `i%8==0`, SubWord at `i%8==4`, plain XOR
  otherwise; 15 keys K0..K14 (4b); K0/K1 == SEED halves (4c); my RK ==
  ref KEYS 15/15 (4d); rcon `01,02,04,08,10,20,40…` standard xtime chain
  (4e).
- ShiftRows law (`adj7_pure.py:289-295`): `out[4r+c] = in[4((r+c)%4)+c]`,
  verified cell-by-cell on `bytes(range(16))` →
  `00050a0f04090e03080d02070c01060b` (4f); my == ref (4f2). Nuance recorded:
  the textbook column-major formula `out[r+4c]=in[r+4((c+r)%4)]` is the
  **same flat-byte function** (dummy-variable swap proof + empirical
  equality) — i.e. the "transposed convention" note in `spn_law2.py:22-23`
  describes coordinates, not a different permutation. Direction is
  load-bearing the other way: InvShiftRows differs, and forward-SR
  `cbc_encrypt(rec44, hdr) == body44` (4u).
- MixColumns matrix (`adj7_pure.py:298`): `((2,3,1,1),(1,2,3,1),(1,1,2,3),
  (3,1,1,2))` standard (4g); `gmul(0x57,0x13)==0xfe` FIPS spot-check, my
  and ref (4g2).
- Round count/order, no-final-SubBytes (`spn_chunk`, `adj7_pure.py:313-322`):
  AddKey, SubBytes, [SR→MC→AddKey→SubBytes]×13, SR, AddKey — 14 rounds,
  **no final SubBytes, no final MixColumns**. Functional proof on genuine
  sid44 body: 13-round variant FAILS, 14-round MATCHES, final-SubBytes
  variant FAILS (4t), final-MixColumns variant FAILS (supplement).
- CBC IV=header chaining (`cbc_encrypt`, `adj7_pure.py:325-332`): block0
  uses header (4i), block k uses C_{k-1} (4j).
- Round-trip with a **fresh inverse written in the runner** (InvShiftRows,
  InvMixColumns `(14,11,13,9)…`, reverse key order; `ks_inverse` NOT
  imported): 20/20 random 256-B round-trips (4k); genuine sid44 body
  decrypts to a record that parses under the §1 grammar (4l) with
  nonce `deb8d66011fc70a885006809` == `law_recheck.py` value (4n),
  hand-rebuild == genuine (4r), `my.build_record` == genuine byte-exact
  (4s); emulator `v3_blob.hex` body also decrypts to a parsing record
  (4v). PASS.

## 5. Tag (HMAC-SHA256) — PASS

- `DK37 = 2a4cc079 60d64762 3cc386dc efafbf25 b669914d 32cc8585 a1ed7f92
  0ef591eb` (`adj7_pure.py:56-58`) == 8/8 SO_VERIFY word immediates
  (`0xcc43c-0xcc5bb`: `0x2a4cc079 … 0x0ef591eb`) (5a); my == ref (5b).
- `verify_tag` (`adj7_pure.py:386-387`) computes
  `HMAC-SHA256(DK37, blob[16:272]) == blob[272:304]` — TRUE on genuine
  sids 42, 43, 44 (5c); source contains the exact slice `blob[16:272]`
  (5d). Off-by-one slices (`0:256`, `16:271`, `15:272`, `16:272+0x00`)
  all FAIL (5e) — slice exactness is load-bearing. Layout 16+256+32 =
  304 B on all three blobs (5f). PASS.

## 6. Authorization header — PASS

- Genuine sid44 matches
  `^Signature signature="([0-9A-F]+)",adj_signing_id="…",algorithm="…",
  headers_id="…",native_version="…"$` — param names/order
  `signature,adj_signing_id,algorithm,headers_id,native_version`, comma
  separators with **no spaces**, one space after leading `Signature` (6a,
  6e); scheme capital-S `Signature`, key lowercase `signature` (6f).
- Sig hex UPPERCASE, 608 chars = 304 B (6b); tail
  `1300000,adj7,8,3.62.0` (6c). `sign_request` (`adj7_pure.py:346-383`)
  emits the identical shape (`Signature signature="%s",adj_signing_id="%s",
  algorithm="%s",headers_id="%s",native_version="%s"` with
  `blob.hex().upper()`) — fresh mint matches the regex (6d). PASS.

## Supplementary full-chain (supp_round_claims.py)

- sid44: `build_claims(attribution, wire+block2)` (211 B) → `commitment_digest`
  → `599E0045…` == decrypted record `b`; `build_record` == decrypted record;
  `cbc_encrypt` == genuine body; `verify_tag` TRUE; `make_header(sec)` ==
  `blob[:16]`. Sids 42/43: H==record-b TRUE with record-derived nonces.
- Round variants on genuine body: 13-round False / 14-round True /
  final-MixColumns False.

## Final verdict

**CONFIRMED** — no divergence in `adj7/work/myrun/adj7_pure.py` on any of the
six items. Every byte-level detail re-derives cleanly: space-padded
20-wide A, upper-hex H/d8/e, `\x00`+`0x10*(256-len)` record, 310/8/pair-XOR/BE
bionic header (edge seeds incl.), custom-IV SHA-256 with standard padding
(boundary-proven), textbook AES-256 S-box/rcon/SR/MC, 14 rounds with neither
final SubBytes nor final MixColumns, CBC IV=header chaining, DK37 HMAC over
exactly `blob[16:272]`, exact auth-header grammar. Genuine sid-44 decrypts
with a from-scratch inverse to a parsing record and rebuilds byte-exact;
**no byte-level correction is required — do not touch the copy.**

On the owner's 400/ask_in suspicion: the mint path is exonerated by the
above (genuine-byte replays 400 the same way per the task statement, and the
crypto bytes themselves verify end-to-end). A 400 `ask_in:3600000` on even
genuine bytes is server-side throttling/attribution-gating, not a mint
defect — no signer change can fix it; further diagnosis belongs to
request-timing/attribution-state analysis, offline-invisible from here.
