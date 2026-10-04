# adj9 — session-close board (2026-09-10)

**Canonical status lives in `../STATUS.md`.** This file is the consolidated
one-screen summary; where the two disagree, `../STATUS.md` +
`WALL_A_SLICE_3.md` win (this file was rewritten 2026-09-10 after an audit
found it stale).

Target: `com.penti.app` 3.12.1 · Adjust Signature SDK **5.0.0**
(app `libsigner.so` md5 `dbe36c643d174f1cca240dcec1f4c585` == official aar
`jni/arm64-v8a/libsigner.so`; reference aars 3.3.5 / 3.6.7 / 5.0.0 / 5.5.0 held
locally, 4 arches extracted → `extracted/_ref/sigs/`).

---

## SOLVED — offline, byte-exact

| # | item | evidence |
|---|---|---|
| 1 | Envelope shape: 192 B → Base64(NO_WRAP) → 256 chars; `16 B header + 176 B body` | Fiddler capture + 38-blob set |
| 2 | `adj_verification` = `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` | XOR(`{"os_name":"android"}`, `Quoh8uafohgh7CahM2h`, i%19) + Base64 |
| 3 | **16-B header law** — `srand(time(NULL))` + bionic `rand()`/`random()` (TYPE_3, 31-word, deg 31/sep 3, 310 discards) → 8 draws → 4 XOR pairs → BE int32 | **94/94**. `header_gen.py::make_header(sec)` |
| 4 | Header is **invertible** → `recover_second()` returns the exact `srand` second | 34/34; equals `ts//1000` (30) / `ts//1000-1` (4) |
| 5 | MSB law: bytes 0/4/8/12 always < 0x80 (31-bit draws) | all blobs, both devices |
| 6 | Header field order in the header line | `signature, adj_signing_id, algorithm, headers_id, native_version, adj_verification` |
| 7 | `key2` spec | AndroidKeyStore **HMAC / SHA-2 256 / 256-bit / 32-B MAC / PURPOSE=SIGN / ORIGIN=0 (TEE) / sec_level=1**, non-exportable (`persistent.sqlite`, uid 10392) |
| 8 | Java crypto flow of SDK 5.0.0 (`com.adjust.sdk.sig.t1`) | `javap` of the real aar: `b(Context)` gen key2; `a(Context,byte[])` = Mac HmacSHA256 + `getKey("key2")`; `a(Context)` = wipe |
| 9 | Envelope assembly is **native**; canonical string ≈1355 B, 50 entries | trace: `mac.update(len=1355)` → `mac.doFinal` == nSign `arg3` |
| 10 | **The seal primitive is identified** — self-keyed 16-bit XOR-feedback "snowball" chain, no embedded key, no standard cipher | `WALL_A_SLICE_3.md` §2/§6/§7; `fold_roundtrip.py` |
| 11 | **The blob builder is un-flattened** (103 tokens → 103 blocks, 0 unresolved) and it is the environment-verdict pipeline | `machine10594_unflatten.py`, `machine10594_map2.json`, `WALL_A_SLICE_3.md` §8/§9 |
| 12 | All **26 emulator/instrumentation markers** decoded + confirmed live in memory | `WALL_A_SLICE_3.md` §9/§11, `device/rwdata2.bin` |
| 13 | String table = plain per-entry single-byte XOR, decrypted in place | `file XOR live` = constant byte per entry; `tbl_decode.py` |
| 14 | **The fold's entropy is ONE 32-bit seed from `/dev/urandom`** — `openat`@`0x13e764` → `read(fd,buf,8)`@`0x13e6b0` → `ldr w1,[sp]` → `ctx_init` `0x1437ec` → Park–Miller `0x13dfd0` + `shuffle16` `0x143c88` | `WALL_A_SLICE_4.md` §1; single caller `0x1437b8`; single caller of that `0xdb160` |
| 15 | **ctx layout exact** — the ctx IS the 26-pointer marker array at `ctx+0x00..0xCF` (ascending `va 0x151d18…0x151e50`) | `0x11d14` disassembly, 26 `stp` pairs (`WALL_A_SLICE_4.md` §4) |
| 16 | Complete live string table: claims + 26 env markers + ~300 env inputs | `device/rwdata2.bin` (`WALL_A_SLICE_4.md` §5) |
| 17 | Big fn prologue is `0xe3144` (frame `0x1900`), not `0xe3c0` | no `ret` in `0xe3144..0xe4a74`; `sub sp,sp,#1,lsl#12`+`#0x900` |

## DISPROVEN — earlier claims that were wrong (corrections)

| # | withdrawn claim | why it was wrong |
|---|---|---|
| C1 | "body is AES-GCM under key `5cde8cbc…`" | **False positive.** That key is `com.penti.app`'s own EncryptedSharedPreferences master key (AES-ECB decrypts app pref names 5/5; absent from `libsigner.so` under all 256 XOR keys; `cipher_init` fires 56× outside vs 6× inside; libsigner has no GCM/`SecureRandom`/`IvParameterSpec` string). |
| C2 | "`[inside nSign]` tags prove those ops are nSign's" | The module flag is a **global static boolean** (`Hook.java:439`), not thread-local → concurrent app crypto gets tagged. |
| C3 | "the SHA1/SHA-256/MD5 cascade is nSign hashing the trust store" | Google TLS chain verification (`upload.video.google.com` → GTS WR2 → GTS Root R1); identical cascade outside windows. |
| C4 | "**wall B (TEE `key2`) is decisive** — forging is impossible" | The server cannot recompute `HMAC(key2,·)` either. Validation is **unseal + compare-to-history**, never verify ⇒ a constant/borrowed `H` passes. TEE adds no wire-format strength. |
| C5 | "nSign ignores `arg3` (zero_h oracle)" | A zeroed arg3 still yields a structurally valid 192-B blob, so that test proved nothing. Parsimonious model: first call per process recomputes+checks the MAC; later calls embed arg3. |
| C6 | "`libsigner.so` has **no** hash implementation" | **Wrong — corrected.** Native SHA-1 **does** exist: H vectors in `.rodata` at va `0x3620`/`0x3640` (LE dwords `67452301…`/`c3d2e1f0…`), init `0x12e5f4`, compress `0x12de60`, update `0x12e620`, final `0x12e7d0`; sole init caller `0xe57c` (fn `0xe3c4`) = one-shot SHA-1 over a `{len,ptr}` record. It has **no cipher**, though — that part stands. |
| C7 | capstone `adrp` formula `(pc & ~0xFFF) + (imm<<12)` | `operands[1].imm` is **already** the resolved page; the old formula silently gave 0 hits. |
| C8 | "layer-2 = the fold applied to the string table" | The 4 "double-obfuscated" entries are **DP-decoder mis-segmentations** (`0x151cb0` IS `1500000`, `0x151d50` IS `ARChon`, `0x151d60` IS `AMIDuOS`). No second string layer. The fold primitive lives on the **record/blob path** only (`WALL_A_SLICE_3.md` §11.2). |

## HARD STRUCTURAL FACTS

* **nSign does zero JCA in steady state.** 6 of 11 windows contain exactly 2
  events (`nsign_in`, `nsign`) — ~800–950 ms of pure native work, no JCA. The
  heavy JCA is **once per process**: `SHA-1(app 745-B signing cert)` →
  `KeyStore("AndroidKeyStore").load(null)` → `getKey("key2")` →
  `Mac("HmacSHA256").init/update(1355)/doFinal` == `arg3`.
* **`libsigner.so` is cipher-free.** `.rodata` = 336 B; no AES/ChaCha/SM4/TEA/
  Blowfish/SHA-256/MD5 constants (4 builds); no ARMv8 crypto instructions; no
  `AES/*`/`NoPadding`/`SecureRandom`/`IvParameterSpec`/`GCMParameterSpec`/
  `KeyGenerator` string under **all 256 XOR keys**. Its whole JCA surface:
  `Cipher`+`RSA/ECB/PKCS1Padding`+`AES`+`SecretKeySpec`, `Mac`+`HmacSHA256`,
  `MessageDigest`+`SHA1`/`SHA-256`, `KeyStore`, `KeyFactory`, `Ed25519`, `Base64`.
  ⇒ the 176-B seal is **hand-written native code**, not a platform cipher.
* **The seal = `sub_1441e4(ctx,len)` (call len=42)** → `sub_143b20` slot search
  (returns index into the key-state region, or 72 sentinel) → `sub_144074`
  XOR-fold loop; ctx init `0x1437ec` = **Park–Miller LCG (16807, Schrage
  127773/2836, mod 2³¹−1)** + **Fisher–Yates shuffle16**; driver
  **`0x144214(ctx,words*,count)`** (the ciphertext word IS the mask param).
* **`0x10594` machine** (fn prologue `0xe740`) = the blob builder: 26 CAS
  marker decrypts → `0x11d14` ctx assembly (26-ptr va-array + memset 0x96) →
  `0x80eb4` 14-stage env-check pipeline → `0x11a0c` float gate → `0x12b74`
  FOLD_LOOP → `0x1317c` ret. Same `+0xf0|1` processed flag as the `0xe3c0` seal.
* **Decoder architecture is `verify-by-resimulation`, not classical decrypt.**
  The fold writes into the key-state region and does **not** mix the slot's old
  value in ⇒ the pre-fold content is unrecoverable from output alone. A decoder
  rebuilds ctx from candidate claims + the transmitted nonce, runs the fold
  program, and compares (`fold_roundtrip.py` §10).
* **Reference builds give nothing away.** 2 exported symbols per arch/version
  (`..._nSign`, `..._nOnResume`); x86_64 equally O-LLVM-flattened.
  `nSign` = `0xdb1cc`/3188 B (arm64) = `0xc060c`/2588 B (x86_64).

## OPEN — one input, not one wall

The seal is **solved as an algorithm**; what is still missing is the **runtime
ctx bytes / exact ctx field order on the seal path**. Everything else is
mechanical. Two routes (either closes it):

1. **Device dump during a live nSign** (~860 ms window): scan `/proc/pid/mem`
   for the ascending 26-pointer va-array `base+0x151d18 …` built at `0x11d14`
   (layout proven in `WALL_A_SLICE_4.md` §4). Capture must be keyed to
   `nsign_in` growth in the oracle log (signings are minutes apart; a launch
   does not reliably produce one) and must re-resolve the PID at trigger time.
   `device/ctxcap/watch2.sh` does both and is armed.
2. **Skip the dump — brute-force the 32-bit seed** (`WALL_A_SLICE_4.md` §1):
   the body's only randomness is one `read(/dev/urandom, 8)` → low 32 bits →
   Park–Miller (mod 2³¹−1). Search space ≤2³¹. Needs the fold program + record
   layout pinned from the `0x10594` block order; the ctx's first 0xD0 bytes are
   already known exactly.

Housekeeping that no longer blocks anything: `Hook.java` → `ThreadLocal<Boolean>`
+ log `Cipher.init(int,Key,AlgorithmParameterSpec)`/IVs (kills the C2 noise).

## Files added (this phase)
`adj9/device/{parse_full,window,pairs,body_keyhunt}.py`, `events.json` (5564 ev),
`triples.json`, `rwdata2.bin`; `adj9/device/ctxcap/{cap,cap2,cap3,cap4,watch,
watch2}.sh` + captured stacks; `adj9/rev/{prim_scan,dis_x86,key_sweep,
ollvm_states,machine10594_unflatten,seal_unflatten,seal_walk,layer2,
fold_roundtrip,tbl_decode,find_va_refs,callers_of,branches_into,syscall_nums,
plt_map,bigframes,fnbounds,grep_insns,scan_reg}.py`, `WALL_A_SLICE_4.md`.

---

## EXTERNAL VALIDATION — `pentindroid_logs.saz` (2026-09-10)

New doc: **`SAZ_LIVE_TRAFFIC.md`**. Fiddler capture of 4 real Adjust requests
from a **second device** (OnePlus DN2101, Android 11, `api_level=30`), all
**HTTP 200 OK** (server-accepted).

- `Authorization` structure confirmed verbatim; **`adj_verification` is
  byte-identical to the offline-computed `KlcAG2cbAAsKSl1KVi0FGiJbDHMI`**.
- **Header law 4/4 on live traffic**, each at `created_at + 1 s`. **S1/S2 share
  a byte-identical 16-byte header** across two different endpoints ⇒ header =
  pure `time(NULL)`, payload-independent. Holds at api_level 30 too.
- Bodies (176 B): fully high-entropy, **0 constant positions** across the four.
- `Client-SDK` 5.7.0 (Adjust SDK) ≠ `native_version` 5.0.0 (signer lib).

**Corrections recorded:**
1. "libsigner re-mapped per signing" is **wrong** → mapped **once per process**
   and persists (base `0x7b8164b000` stable across reads minutes apart, after
   signing). No need to race a signing.
2. Base is computable from maps alone: `base = start of the r-xp mapping whose
   file offset is 0x54000` (libsigner's APK offset in the split APK).
3. The stack-ctx scan found nothing because the ctx/marker data lives in
   **`.data`**, not the stack — the "stack-resident ctx" premise was the error.
   Diffing two sessions' `.data` shows only ASLR-relocated pointers (1067 B,
   all 8-byte slots at va 0x14ce60) ⇒ `.data` is semantically static.

`rev/scan_ctx.py` retained as the (negative) stack-scan tool.

---

## CLOSURE — adj9 fully modeled + live-accepted (2026-09-13)

- **`fin_result.md`**: from-inputs recompute **48/48 byte-exact** (header
  4/4 + body 44/44, hex-identical to blob 5595c3c4…) with `rev/fin_vm2.py`
  over the real 11 descriptors (`rev/fin_descs.json`, 147 dw). Two emulator
  bugs fixed: va_order (#6↔empty) + MKITER/ITERNEXT LIFO. Merge ground
  truth = 22,272 EMITs (not 205).
- **Slice 78**: envelope complete — blob = OUTPUT[0..48) BE; header =
  Random3(second); workhorse = pure copier; server model final.
- **Slice 81**: **first offline-crafted signature ACCEPTED (200)** —
  `make_fresh.py`/`sign_fresh.py`: fresh claims + replayed H/#0 + emulator
  body + Random3 header; server rejects stale binding/garbage, requires
  `Client-SDK` header; H freshness and #0 slots NOT validated.
- **Slice 82**: differential taint probe (`taint44.py`) — **0 of 44 body
  dwords server-verifiable** (all value-tainted); random #0/H never reach
  exit-clean (unknowns are device-real-only, not free); #2 is free.
  **#0's real shape: dword0 + one 16-B block tiled ×8¾** — true entropy
  ≤5 dwords. Pending: `device/get0.py` capture across signings (USB drop).
- **Generator `rev/adj9_sign.py`**: params in → Authorization header out;
  control mode re-verified 48/48; dynamic SAZ mode reproduces the real
  S1 header; swaps fixed. `rev/decode_signature.py`, `saz_session_log.py`.
- **Slice 85**: #0 captured live (`device/get0.py`, 7 signings): the
  "nonce words" are heap POINTERS (7 u64 heap + 4 MTE-tagged slots) +
  40 B run-stable data + count 0xb; buffer stable within a signing,
  moves across runs. #0 CLOSED — zeros/replay both server-proven.
