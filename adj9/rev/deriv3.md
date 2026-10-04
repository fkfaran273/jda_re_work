# deriv3 — Is the 56-byte "region" a KEYED function of the request under a secret embedded in libsigner.so?

**Test date:** 2026-09-22 (offline; no device, no internet)
**Artifacts:** `deriv3.py` (runs clean end-to-end), `deriv3.log` (full evidence, 156 lines), `deriv3_summary.json`, this file.
**Hypothesis under test:** `region_word_i = F(secret_in_binary, X_i, nonce_i)` where `nonce` is transmitted in-blob, making the region server-verifiable.
**Standing alternative:** region entropy = one 32-bit `/dev/urandom` seed driving a self-keyed fold (no embedded secret).

---

## 1. Secret harvest (candidates + sources)

From `extracted/arm64/lib/arm64-v8a/libsigner.so`:

| Source | Method | Yield |
|---|---|---|
| (a) `mov`/`movk` 64-bit constants, `sub_9afa4` (0x9afa4..0x9e000) | parsed `fn_9afa4_full.log` | **474** assembled 64-bit constants (509 mov + 1422 movk lines) |
| (a2) independent capstone rescan of the same range | `Cs(ARM64)` over raw file bytes (vaddr→offset via program headers) | **478** consts; **3** new vs the log pass → merged pool **477** |
| (b) high-entropy runs in `.rodata` (336 B), `.data.rel.ro` (2400 B), `.data` (13834 B) | sliding 16/32/64-B windows, entropy-gated, ASCII-skipped, deduped | **500** distinct 16-B windows (max entropy 4.00 bits/B), **61** 32-B runs, **330** 64-B runs |
| (c) known strings | `adj_verification='KlcAG2cbAAsKSl1KVi0FGiJbDHMI'`, `app_token='jut9tib0eeps'` | **neither string is in libsigner.so** (plain or single-byte-XOR). `jut9tib0eeps` IS in `libpenti-native-keys.so` @ 0x10ca. Both (+ MD5/SHA-256 derivatives) still tested as keys. |
| (b2) primitive-signature scan | well-known constant tables, both byte orders | see §2 |

Derived key material actually injected into the battery (after byte-level dedup):
**K16 = 1758** 128-bit keys (const le/be padded/concat, adjacent-const pairs, w16 windows, ELF windows/runs lo/hi, string derivatives, H1/H2 raw),
**KVAR = 1986** variable-length keys (HMAC + concat),
**K4 = 292** 32-bit seeds (crc init / fnv basis / murmur seed). Total distinct key materials: **4036**.

### (b2) Which primitives are even plausible in libsigner.so?

| Signature | Result |
|---|---|
| SHA-1 init h0..h3 (`0123456789abcdeffedcba9876543210`) | **PRESENT** @ 0x3620; h4 `f0e1d2c3` @ 0x3640; K0 `5a827999` @ 0x3644, K1 `6ed9eba1`, K2 `8f1bbcdc` |
| AES (sbox, Te0, inv-sbox) | ABSENT |
| MD5 (T-table `78a46ad7`) | ABSENT |
| SHA-256 (H0, K0) / SHA-512 / SHA-3 | ABSENT |
| SipHash (`somepseu`/`dorandom`) | ABSENT |
| murmur3 / xxhash / FNV / CRC32 / CRC32C | ABSENT |
| ChaCha (`expand 32-byte k`) / TEA-XTEA delta | ABSENT |

libsigner.so natively implements **SHA-1 only** (consistent with `CORRECTIONS_AND_NATIVE_SHA1.md`). Every other tested family would have to exist in Java/Kotlin or server-side, not in this binary.

## 2. Test battery and coverage

**Rows (16):** S0, S1, S2 (desc_det emit stream; S0/S2 byte-identical claims, all sec=1789240512) + pair rows P0,P1,P2,P3,P4,P5,P6 from `pair_h3.json` (P7 == S0) + 6 app rows (`app_signings*.json`). Header material per row: `make_header(sec)` (verified law; = `5595c3c431567e631a7bf9b958dabea7` for S0/S1/S2) **and** the observed H where available.

**Targets per row:** tile `d0[2:6]` (BE+LE) and `d0[1:5]` alt alignment (BE+LE); words W0=d0[0], P=d0[1] (when the tile repeats), d2, d4[0..7] — each in BE and LE packing.

**Messages X per row (~22–26):** `claims[:16]`, `claims[-16:]`, `claims[16:32]`, full claims, header, header‖claims, claims‖header, md5/sha1/sha256(claims), claims‖sec(LE/BE/ascii), sec‖claims, claims‖d2, d2‖claims, claims‖W0, W0‖claims, d2‖header, header‖d2, claims‖P, P‖claims, claims‖H, H‖claims, nonce-block(d2,W0[,P]).

**Families (computations → comparisons against all targets):**

| # | Family | Computations |
|---|---|---|
| 1 | AES-128-ECB(K16, X)[:16] + word windows | 225,024 |
| 2 | HMAC-MD5 / HMAC-SHA1 / HMAC-SHA256(KVAR, X) | 2,621,520 |
| 3 | MD5/SHA256(secret‖X) and (X‖secret) | 3,495,360 |
| 4 | SipHash-2-4 and SipHash-1-3(K16, X) | 379,728 |
| 5 | tile == K16 XOR md5/sha256(X) | 1,547,040 |
| 6 | crc32 mixes (init 0/0xffffffff × final-xor ±) + secret-seeded/init variants | 14,832 |
| 7 | unkeyed md5/sha1/sha256 4-byte window truncations of mixes | 3,740 |
| 8 | fnv1a-32 (basis=sec, 2166136261^sec, +sec, sec‖msg, msg‖sec) + murmur3-32 (seed=sec, 0) | 56,096 |
| | **Total (row, test) comparisons** | **87,166,216** |

**Primitive validation:** AES-128 passes FIPS-197 + SP800-38A vectors and is cross-checked bit-for-bit against OpenSSL (`cryptography` pkg). SipHash is spec-faithful and was cross-validated by three independently written transcriptions agreeing bit-for-bit (official reference vectors unavailable offline — a remembered vector value proved unreproducible under ~360 natural spec variants and was discarded; see deriv3.py comment). crc32/fnv1a/murmur3 sanity-checked. **Fixed during setup:** the previous session's script had (i) a truncated AES S-box literal (64 of 256 bytes) — replaced by generated-and-verified S-box; (ii) a `word_targets()` syntax error (script had never run); (iii) a P2/P4 assert that would have crashed (their claims differ).

## 3. Result: ZERO HITS — precisely stated

**HITS: 0** across 87,166,216 comparisons.

What a hit would have been: any 32-bit window of any digest output equal (BE or LE) to any target word, or any 16-byte digest head equal to any tile packing, for any of the 4,036 key materials from every plausible embedded-constant source. Under pure chance, ~87.2M 32-bit comparisons yield an expected **0.02** false hits — so zero is exactly what uncorrelated data looks like; no marginal signal was suppressed by the threshold.

**This does NOT disprove the keyed hypothesis in general — it empty-scans this candidate space.** Coverage is bounded by: (i) keys that are literal 64-bit `movz/movk` constants in sub_9afa4, literal high-entropy .rodata/.data runs, or the two known strings — a runtime-derived key (KDF over adj_verification with runtime inputs, key agreement output, or a key in libpenti-native-keys.so / Java layer) is invisible; (ii) standard constructions only — a custom ARX/Feistel fold, ChaCha keystream, AES-192/256, SM4, Speck, or non-standard SipHash parameterization would be missed; (iii) the SipHash caveat above. Notably, libsigner.so contains constant signatures for **none** of the tested primitives except SHA-1, which strengthens "no embedded-standard-secret" considerably: an AES/HMAC/SipHash-based scheme would be implemented somewhere, and it is not in this binary.

## 4. Nonce-structure probe (Section 4 of deriv3.log)

**S0 vs S2** (same claims, same second, different d0/d2/d4 — the pair that forces any keyed model to carry a transmitted nonce):

- W0: `13271271` vs `f1a55b5b` (xor `e282492a`); P: `db50f44c` vs `9949bda6`; d2: `fb1a8296` vs `4bce691e` — **no** ±k counter, no Park–Miller (16807/48271 mod 2^31−1), no LCG-31/32, no xorshift32 (8 tap triples), no 2^k xor.
- tile_S0 XOR tile_S2 = `b72ad5d2 c9958ed4 9692f46a e82dab6d` (hamming 68/128) — not a repeated W0/W0-xor/d2/d2-xor/P word in either packing; per-word xor intersects the candidate set in **0/4** words.
- d4: 0/8 words equal between S0 and S2; no pairwise PRNG relation.
- **P2 vs P4** (same second 1789240075, same observed H — but different claims, so tile/d4 diffs are confounded; nonce-word relations still valid): W0 xor `8f142e93`, d2 xor `1f8a5a3b`, P xor `c21461d5` — same nulls. The one candidate-set intersection (`P_xor@3`) is the trivial identity **P == tile[3]** for those rows (see below), not structure.

**Alignment artifact worth recording:** in every desc/pair row examined, `d0[1] == d0[5]`, i.e. the "preamble" word equals the last word of the repeating 4-word unit. The 8x repeat is equally consistent with the block starting at d0[1] or d0[2]; which 16 bytes are "the tile" is a byte-layout question the data alone cannot resolve — hence both `d0[2:6]` and `d0[1:5]` were tested throughout.

**Conclusion of probe:** the nonce words (W0, P, d2, d4) of two calls with identical claims+second share **no detectable algebraic relation** — they behave as independent per-call entropy draws.

## 5. Verdict

**The keyed-region hypothesis gains zero support from this probe, and the nonce evidence actively favors true per-call entropy.**

1. **No positive evidence:** 87.17M targeted comparisons over 4,036 key materials harvested from every literal-constant source in libsigner.so × 9 keyed families × ~25 request messages × BE/LE → zero hits (expected 0.02 false hits under random, so the emptiness is not a threshold artifact).
2. **Binary is the wrong shape for the hypothesis:** libsigner.so embeds constant tables for SHA-1 only — no AES, no MD5, no SipHash, no murmur/CRC/FNV constants. A server-verifiable standard MAC in the region would need one of those somewhere in the native signer.
3. **Nonce structure absent:** for the S0/S2 pair (byte-identical claims + header second) the differing words show no counter, no LCG/PRNG kinship, no XOR masking by any transmitted word; a server recomputing `F(secret, claims, nonce)` would need a nonce that is functionally transmitted — and none of W0/P/d2/d4 relates to the request or to each other in any tested way.

**Remaining escape routes for a keyed model (unfalsifiable offline):** secret not materialized as a literal (runtime-derived), construction non-standard (custom ARX fold keyed by e.g. the header bytes themselves), or verification server-side without any secret in this binary at all (pure entropy + server-side trust of the other descriptors). Within everything offline testing can reach, the standing model — **region = true per-call entropy (urandom-seeded self-keyed fold), not a keyed verifiable function** — remains the best explanation.
