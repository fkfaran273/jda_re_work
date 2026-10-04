# Hunting the "encryptor" in `libsigner.so` (2026-09-09, evening)

Question: Adjust's server apparently *decrypts* the 192-byte blob that `nSign`
returns. So there must be an encryptor in `libsigner.so`. Find it.

**Result: there is no encryptor. There is no crypto primitive in the library at
all.** Evidence below. The 192-byte blob is *not* produced by any recognisable
cipher, in native code or via JCA.

---

## 1. No native crypto implementation

`scan_consts.py` — scanned all **327,541** instructions of `.text` for SHA-1 /
SHA-256 / MD5 K- and H-constants materialised as `mov`/`movk` immediates
(O-LLVM hides constants this way, which is why a `.rodata` table scan finds
nothing):

| family | distinct constants found | expected if implemented |
|---|---|---|
| SHA-1 K | 1 / 4 | 4 |
| SHA-1 H | 1 / 5 | 5 |
| SHA-256 K | 6 / 64 | 64 |
| SHA-256 H | 2 / 8 | 8 |
| MD5 K | 9 / 64 | 64 |

6/64 and 9/64 is exactly the random-collision floor for 16-bit immediates in a
327k-instruction binary (~128 target half-words out of 65536 ≈ 0.2 % per
immediate). **No hash implementation.** No 256-byte bijection anywhere in the
file → **no AES S-box**. `DT_NEEDED` is still libc/libm/libdl/liblog only.

## 2. What `nSign` actually does — from the real device trace

`cap/adj9_capture6.log` already contains a complete, tagged `[inside nSign]`
trace. In order:

```
SHA1(745 B)                                  -> 20 B      (app/cert material)
KeyStore.getInstance("AndroidKeyStore"); load(null)
getKey("key2")  -> AndroidKeyStoreSecretKey alg=HmacSHA256 encoded=null
Mac.getInstance("HmacSHA256") provider=AndroidOpenSSL
Mac.init(key2)
Mac.update(canonical)   len = 1337 / 1355    -> 32 B      <-- H
... then a walk over the system trust store:
KeyStore type=BKS provider=BC 1.77
MD5 / SHA-1 / SHA-256 over buffers of 33,36,48,53,61,81,91,120,294 B
```

That is **all** of it. There is **no `Cipher` call, no RSA, no AES, no
`SecretKeySpec`, no `Base64.decode` inside nSign**. The `getString`-level
strings for those exist in `.data` but their decrypt sites are *off* the nSign
path (`crypto_users.py` / `inline_decrypt.py`): even `AndroidKeyStore`'s own
decrypt sites are off-path — only `key2` (0xd82c8, 0xda2dc) and `doFinal`
(0xa0d74, 0xb9564) are on it.

The AES traffic in the same log is **not** nSign: it is the app's own
EncryptedSharedPreferences — one constant raw AES-256 key
`54e22f818d6d49e56f582a3dc7af79c3c913f25bb2c1bcb4d12484ce3ae15126`
(`SecretKeySpec alg=AES format=RAW encoded=32B`), alias
`_androidx_security_master_key_`, 93/113-byte base64 blobs, running outside
the nSign window.

So the "encryption" the user hypothesised is not performed by any crypto API
at all.

## 3. The 192-byte blob is not those digests, and not decodable

`envelope_test.py` — 88 distinct short digests (16/20/32 B) captured in the
logs, searched against the three genuine 192-byte blobs:

* direct containment: **0 hits**
* any ≥6-byte fragment: **0 hits**

`blob_crypto_test.py` — the three blobs have 135-139 distinct bytes of 192
(= exactly the random expectation, 135.2) and defeated:

* XOR with `.rodata` 32-byte pair / each 16-byte half
* AES-256-ECB, AES-256-CBC (iv=0 and iv=blob[:16]), AES-256-CTR, AES-128-ECB
  with each half

No PKCS#7 padding, no printable structure (all 61-84 printable of 192, i.e.
the 71-ish you get by chance).

## 4. New things found (lead inventory, all currently negative)

| finding | where | status |
|---|---|---|
| two 16-byte constants `0123456789abcdeffedcba9876543210` and `f0e1d2c39979825aa1ebd96edcbc1b8f` + magic `0xca62c1d6` | `.rodata` +0xc0/+0xe0, loaded at `0x12e5f4` (on nSign path) into a struct at +0x50/+0x60/+0x70 | key candidates — **tested against blob, failed** |
| 64-hex blob `c22b0c02505175fdc8651d3a623c0499fcec04941db33f1f83aae7701faa16` | `.data` `0x1536d2` | **zero code xrefs** — likely unused / indirect |
| JNI `SetByteArrayRegion` wrapper | `0x9e778` (args `x5`=buf, `w4`=len, `x3`=start, `x2`=array, `x1`=env) | generic; **zero `bl` callers** (reached by tail-branch in the flattened dispatcher) |
| `.rodata` also holds `"SHA-256"`, `/system/lib64/libart.so`, `ro.arch`, `exynos9810` | `.rodata` +0x100.. | anti-tamper, not envelope |

## 5. Conclusion / where this leaves us

The 192 bytes are assembled by native code with **no cipher primitive** — a
packing / shuffling / byte-mixing routine inside the flattened dispatcher, or
genuinely random-padded material. Nothing about it is decryptable by a standard
algorithm, and there is no key to extract.

Decisive next experiment (cheap, uses the working LSPosed oracle):

1. **Sign the same payload twice** and diff the two 192-byte blobs. If they
   differ byte-for-byte for identical input, the blob contains randomness or a
   nonce and the server cannot be decrypting a deterministic record; if they
   are identical, the transform is deterministic and a known-plaintext attack
   becomes possible (we control the canonical string, so we can flip 1 byte of
   one field and watch which of the 192 bytes move — that alone recovers the
   diffusion structure).
2. Only if (1) shows determinism is it worth slicing the dispatcher further;
   the 1-byte-flip diff gives you the layout for free without reading any more
   obfuscated assembly.

## 6. Tooling added

| file | purpose |
|---|---|
| `rev/scan_consts.py` | constant-materialisation scan (mov/movk) for SHA-1/256/MD5 + S-box search |
| `rev/dataref2.py` | robust ADRP-window code-xref finder |
| `rev/strusers.py` | maps obfuscated strings to the code that loads them |
| `rev/inline_decrypt.py` | harvests every in-place string decrypt |
| `rev/crypto_users.py` | crypto strings -> decrypting function, with nSign-path flag |
| `rev/envelope_test.py` | digest containment test against the blobs |
| `rev/blob_crypto_test.py` | XOR / AES-ECB-CBC-CTR tests with the `.rodata` constants |
| `rev/hunt2.py`, `hunt3.py`, `dumpfn.py`, `slice_output.py` | caller / back-slice attempts (all dead ends, kept for record) |

---

# 7. RESULT OF THE ORACLE EXPERIMENT (2026-09-09 17:0x) — nSign is NON-DETERMINISTIC

Implemented the re-sign oracle in the Xposed module (`adj9/module/src/com/adj9oracle/Hook.java`,
`oracleSuite()`), built, installed, ran. Raw capture: `cap/oracle_run3.log`.
Analysis: `rev/oracle_diff.py`.

## What was done

The oracle fires once per process, 2.5 s after the first genuine signing, and calls
`NativeLibHelper.a(ctx, map, H, apiLevel)` itself with a deep copy of the live args:

| call | input |
|---|---|
| `oracle_same_0/1/2` | **byte-identical** args (arg3 H = `8042f41c794b24c5…608a2f`, level 31, same 50-entry map) |
| `oracle_hflip` | arg3[0] bit0 flipped (`8142f41c…`) |
| `oracle_mapflip` | one map value changed: `store_name_from_system=com.android.vending` → +"x" |

Note: `a` is an **instance** method — you must pass `param.thisObject` as the receiver,
`m.invoke(null, …)` throws `NullPointerException: null receiver`.

## Result

```
oracle_start    2aa4e57951b4f7eb16713d4e06ffa3d9…
oracle_same_0   37b688d72a89f2c72702e4b026f5684f…
oracle_same_1   18b1ae9924a7d3287bd14d8c350e1c33…
oracle_same_2   40b5a55623e311b16e892f500dc6cff6…
oracle_hflip    1e64b937201f0d8013904d875ceb171b…
oracle_mapflip  33735da323a43985341a951304baf3171…
```

* every blob is exactly 192 B
* **0 byte positions are constant across the 6 blobs**
* every pair differs in **190–192 of 192 bytes** (random expectation 191.25)
* 0 shared 16-byte aligned blocks; 252/256 distinct byte values overall

Three calls with *byte-identical* inputs produced three outputs that differ from each
other as much as random data. There is no deterministic
`nSign : (map, H, level) -> 192 B`.

## Consequences

1. My proposed "flip one byte and watch which of the 192 move" attack is **dead** —
   the noise floor is the whole blob. There is no observable diffusion to measure.
2. The envelope is randomised per call: random IV / salt / nonce, or randomised
   internal content. Both remain compatible with "the server decrypts it" (a proper
   cipher with a random IV looks exactly like this), and neither can be distinguished
   from here without either (a) reading the native packing code, or (b) getting the
   plaintext another way.
3. Suggestive but not conclusive: in `cap/adj9_capture6.log` the two nSign windows
   contain **different internal digest sequences** (99 vs 75 events, different
   MD5/SHA-1/SHA-256 ordering). Those windows may be interleaved between concurrent
   threads, so this is not proof — but it is a candidate source of the randomness
   (hashing trust-store certs in a non-deterministic iteration order).
4. Bottom line unchanged: you cannot mint this offline. Even with a perfect
   implementation of the scheme you would still need `key2`, and `key2` is
   GENERATED-in-TEE (proven). The on-device oracle remains the only signing route.
