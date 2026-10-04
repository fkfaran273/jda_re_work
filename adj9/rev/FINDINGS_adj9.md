# FINDINGS — the adj9 signature: everything established to date

Consolidated 2026-09-30 so the two working agents stop rediscovering.
Every claim below is measured. Where something is a negative result it says so.

---

## 0. Goal

Signing takes 12–20 s per request. The work is *not* intrinsically expensive —
raw C emulation of the whole VM is **0.24 s**. The cost is ~1.6M crossings
from the VM into Python. The goal is a signature in well under a second,
byte-identical to what the device produces.

## 1. The envelope

192 bytes = a 16-byte Random3 header + a 176-byte body.
The header is a pure function of the signing second (`make_header(second)`),
which is why the signing second can be recovered from any real blob.
The body is the 144-byte record, whitened (144 B) + a 32-byte digest.

## 2. The record (144 B) — everything except block32 is known

| range | field | how we get it |
|---|---|---|
| [0:3) | magic `010008` | constant |
| [3:19) | head = d0[0..3] | from the region law |
| [19] | flag `02` | constant |
| [20:24) | S — the per-fill seed | from the region law |
| [24] | flag `03` | constant |
| [25:45) | APK cert SHA-1 (descriptor #9) | constant per app |
| [45] | flag `04` | constant |
| **[46:78)** | **block32** | **UNKNOWN — the open problem** |
| [78] | flag `05` | constant |
| [79:111) | SHA256("") | constant |
| [111:114) | tag `060107` | constant |
| [114:128) | zeros14 | constant |
| [128:130) | tail2 = `0000` | constant, always zero |
| [130:144) | ones14 (`0x0e`×14) | constant |

## 3. The whitening — SOLVED, both directions

A complete static cipher. 14 rounds, per round:
`chunk[i] ^= 0x55 ^ KB[16r+i]` → `T[chunk[i]] ^ 0x55` → permute by
`PI[i] = (-3i) mod 16` → a 32-bit GF(2) linear map `F`. Then a final sweep.

Constants, all in the binary:
- `T` — 256-byte S-box
- `KB` — 240 bytes = **15 × 16 groups** = AES-256's 14 round keys + final sweep.
  Independently confirmed present in the binary; group 0 = `43fc368804c8ed1b17e5c8f603002f46`.
- `PI`, `F` / `F_MINV`, `T_INV`

**Verified:** `whiten_forward(record, header) == body` byte-exactly, and
decrypting all 9 chained chunks returns the record byte-exactly. The cipher is
CBC-chained across 9 chunks of 16 B with the 16-byte header as IV.

It is **AES-shaped but not stock AES** — the permutation is a stride-3 walk,
not ShiftRows, and the `^0x55` offset sits outside the S-box. Do not waste
time trying to match it to a published AES mode; it is a custom cipher.

**The keystore key is NOT involved in this layer.** The trace shows
`keystore2.AndroidKeyStoreSecretKey alg=HmacSHA256`, which never leaves the
secure element — so any construction keyed on it is unreachable.

Inverse: `adj9/rev/whiten_decoder.py`. Forward: `whiten_forward(record, header)`
in `manual_run/adj9_signature.py`.

## 4. The region law — SOLVED

d0/d2/d4 are a pure function of the per-fill seed, which is
`V = tv_sec ^ tv_usec` at the fill instant (see `rev/fill_model.md`).
Descriptors: d8 is a 16-byte constant, d9 the cert SHA-1, d7 the unpadded
desc10 length, d10 the claims, d5/d1/d3 zero fillers.

**head_phase is PER APP and fails silently.** It selects the non-cycling
prefix of the whitener's selector schedule and rewrites only the first few
words of d0. Wrong value → the server still answers HTTP 200 with a real adid.
Measured: penti `(0x2b, 0x48)`, creditsea `(0x2b,)`, declic `(0x2b,)` —
the last two verified against genuine device blobs, not assumed. It now lives
in `manual_run/adj9_signature.py` as `HEAD_PHASE_BY_APP_TOKEN`, keyed by
app_token, so it is derived rather than typed. Brute-force it by decoding a
real blob: take F_seed from record[20:24), compute d4 = `_d4_words(F_seed)`,
then test every 1- and 2-selector head until `_head_words(_d0_words(d4, h))`
matches record[3:19).

## 5. The claims law — SOLVED for both SDK generations

`desc10_keys(kind, ...)` gives the fixed key order; values are concatenated in
that order, NUL-padded to 4 bytes, with the unpadded length in d7.
5.7.0 and 5.8.0 have different key lists; `desc10_58.py` implements 5.8.0.
Signed claim count: 27 (session) / 32 (click) in 5.7; the 5.8 lists are
extended. Pinned values `adj_verification`, `adj_signing_id`, `headers_id`,
`native_version` are native-injected and never appear as dex literals.

## 6. The VM — structure, and where the cost is

- `libsigner.so` is **byte-identical across every app** (same sha256), so
  nothing app-specific lives in the code.
- 332,772 bytes of ARM64 across 3 spans = **83,193 instructions**:
  `0x99000–0xBCA30`, `0x100094–0x12AA48` (contains the entry point), `0x146000–0x149000`.
- Entry point `pc = 0x100114`. Spans are position-dependent; map them at those
  addresses, no relocation.
- A signature is ~9.87M executed instructions.
- **16% of all executed instructions are `bl` to an intercepted primitive** —
  architecturally load-bearing, not incidental.
- 1,616,116 such calls per run at ~3.4 µs each = ~5.5 s. Raw C emulation of
  the non-hook instructions is 0.24 s. **The boundary is the entire cost.**

### The intercepted targets (COMPLETE list — omitting any silently corrupts the blob)
`PUSH`, `POP`, `PUSH2` (0x146470), `POP2` (0x146478), `PUSHS` (0x147120),
`POPS` (0x147220), `EMIT`, `LENQ`, `OUTLEN`, `MKITER`, `ITERNEXT`, `ISEMPTY`,
`RAND`, plus three CAP cells at `0x14784c` / `0x147a18` / `0x147a20`.
All of these live in span 3, and the VM reaches span 3 **only** through them,
so patching each entry's first instruction to `ret x30` makes Unicorn return
by itself (x30 == bl+4 == the Python model's fall-through).

### Memory model — NOT load-bearing
3.24M `FinEx.ld/st` accesses instrumented: **every one naturally aligned**,
zero MTE/heap tags, touching only ~200 addresses in 6 small regions
(`0x0`–`0x18` scratch, `0x50FF..`, `0x51..`, `0x52..` CTX, `0x53..` writer,
`0x56..` nodes, `0x57..` descriptor data), all seeded by `Ex.__init__`.
The `&~7`/`&~3` masking quirk in `_memplan` never fires. Real Unicorn memory
reproduces the fake dict exactly.

### Two Unicorn traps that cost real time
- `UC_ARM64_REG_X0 + i` is only valid for `i <= 28`; x29/x30 have ids 1 and 2.
  Using the arithmetic form on them writes garbage into x29.
- The POP hook must test queue emptiness **before** popping. Testing after
  turns a legal 1-element pop into a spurious underflow that sets the writer
  error cell and produces a false early `exit-clean`.

## 7. block32 — the open problem

32 bytes, the only non-constant field. It **changes when ANY of the 11
descriptors changes, including the zero fillers** — which rules out any
function of whole record fields and points to word-level mixing.

**Ruled out (do not repeat):**
- SHA-256 / MD5 / HMAC over 12 record fields, all 144 ordered pairs, all 1728
  ordered triples
- 2,197 messages + 169 HMAC-SHA256 pairs (earlier reversing)
- AES ECB / CBC (2 IVs) / CTR (2 nonces) with 31 keys (every KB group, adjacent
  pairs, the full 240-byte KB, T head, F_MINV head) × 14 inputs including the
  record prefix `rec[0:46]`
- Decrypting block32 with the real inverse cipher returns the same bytes — it is
  **not** an encrypted field; nothing is hidden underneath.

Caveat on those negatives: they all assume block32 is a function of WHOLE
fields. If it is a multi-round construction over interleaved words, no field
permutation could ever hit. That is the main reason to keep modelling rather
than assume closure.

Most likely primitive: **`F`**, the 32×32 GF(2) circulant matrix with an exact
inverse that the whitening already uses.

## 8. Correctness gate (mandatory)

`sign_request(params, kind, second=..., seed=...)` draws `os.urandom(4)` as the
per-fill seed **unless `seed=` is passed**. Two runs on identical inputs differ.
Pin the seed (0xDEADBEEF works) for every comparison or you will conclude
working code is broken — this cost real time twice.

Verified references: `manual_run/_gold.json`, `unicorn_work/golden.json`.
Three independent gates have passed: full instruction trace (9,869,394 PCs),
full intercepted-op stream (~1.57M ops), and the 192-byte blob.

**A wrong signature is far worse than a slow one.**

## 9. Prior reversing to read before re-deriving

- `rev/writer_findings.md` (419 lines) — the region-struct writer chain, the
  two JNI exports, descriptor #8 classified as a static XOR-keyed constant
- `rev/whiten_decoder.md` (171 lines) — the inverse cipher, validation, scope
- `rev/fill_model.md` (192 lines) — the descriptor-fill model: region words are
  a pure function of gettimeofday at the fill instant, `V = tv_sec ^ tv_usec`
- `rev/whiten_decoder.py`, `rev/fill_model.py` — implementations
- Genuine device signings with full claim maps AND blobs:
  `adj9/rev/creditsea/adj9_cap_{declic,fresh,live_tarsan,scopefix}.log`

## 10. What is settled and not worth revisiting

- The signature is byte-exact and correct; three independent gates agree.
- `adj_verification` and `adj_signing_id` are identical across all three apps.
- The whitening is fully solved in both directions; static keys confirmed.
- The region law, the claims law (5.7 and 5.8), and the per-app head are solved.
- The keystore key is unreadable and, for the whitening, not even needed.
- Offline non-organic attribution **works end to end** on penti, creditsea
  (`2439ti22`) and declic (`24faz5r5`).
