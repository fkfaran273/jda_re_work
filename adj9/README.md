# adj9 signature algorithm — Python port (com.penti.app)

Short version: **yes for the canonicalisation + HMAC, no for the final native step.**
A pure-Python implementation cannot produce a signature the Adjust server accepts on
any modern device. Here is exactly what is and isn't reproducible, and why.

## What the pipeline actually is

Read off `javap` on `com.adjust.sdk.sig.u2` from the real 5.0.0 AAR — not inferred:

```java
LinkedHashMap out = new LinkedHashMap<>(activityParams);  // copy: keeps SOURCE order
out.put(globalParams...);                                 // appended
out.put("adj_verification", o3.a(new a0()));              // appended
byte[] hmac = keystore.sign(out.toString().getBytes(UTF_8));   // t1.a(ctx, bytes)
byte[] blob = NativeLibHelper.a(ctx, out, hmac, SDK_INT);      // -> nSign()
header = String.format("Signature %s,%s,%s,%s,%s,%s", ...);    // 6 fields
```

```
source HashMap (bucket order)  ->  LinkedHashMap copy  ->  + globals  ->  + adj_verification
        |                                                        |
        |          Python CAN model this (verified vs JVM)       |
        v                                                        v
   (order of prefix)                                    out.toString()  <-- canonical string
                                                                |
                                                                v getBytes(UTF-8)
                                        HmacSHA256(key = AndroidKeyStore "key2")
                                        CAN do IF you have the raw key
                                                                |
                                                                v 32 bytes
                                            nSign() -> binder -> keystore2/keymint
                                            -> 176 bytes, DIFFERENT EVERY CALL
                                            CANNOT do this
                                                                |
                                                                v
                                                    Base64 -> header
```

```http
Signature signature="<b64>",adj_signing_id="<id>",algorithm="adj9",headers_id="<id>",native_version="5.0.0",adj_verification="<v>"
```

Field order is `signature, adj_signing_id, algorithm, headers_id, native_version,
adj_verification` — **`algorithm` before `headers_id`**. Verified against the 5.0.0
reference AAR and against this app's own `u2.a` in `classes3.dex`. (An earlier
revision of this README had the two swapped; that was wrong.)

The 3.x header differs only by **omitting `adj_verification`**. `build_authorization_header()`
here emits the 5.x form.

`adj_verification` is the one piece of the header you *can* produce and invert
offline — see below.

Two hard walls:

1. **The key.** `key2` is an AndroidKeyStore HmacSHA256 key. On API >= 23 it is
   non-exportable — `getEncoded()` returns `null`, and `adb root` + Magisk cannot pull
   it. The only software path is the API 18–22 fallback in `com.adjust.sdk.sig.c`,
   which generates 16 random bytes, RSA-wraps them into SharedPreferences
   `adjust_keys` → `encrypted_key`, and holds the raw key in the Java heap every
   call (hookable, or unwrap the software-keymaster blob offline).
2. **`nSign()`.** `libsigner.so` does no crypto in-process — no AES tables, no ARMv8
   crypto instructions, no `javax.crypto.Cipher`. It JNI-reflects `javax/crypto/Mac`
   and `java/util/HashMap`, and tracing shows hundreds of `BINDER_WRITE_READ` ioctls
   to `/dev/binder` plus AF_UNIX connects to keystore2/keymint during the call. Its
   176-byte output varies per call for identical input (per-call randomness inside the
   keystore). There is nothing to reimplement — the math happens in another process.

So the working strategy is a **device oracle**: run the real `Signer.sign()` via frida
RPC and use its output. This module gives you the part you need to *verify* that oracle
and to reason about the canonical string — not an offline signing box.

## adj_verification — the one part that *is* offline

Unlike `signature`, `adj_verification` never touches the keystore:

```
serialize a0  ->  UTF-8  ->  XOR with 19-byte key s2.a, i % 19  ->  Base64(NO_WRAP)
```

`s2.a == b"Quoh8uafohgh7CahM2h"` (from `s2.<clinit>`; identical in the AAR and in
this app's `classes3.dex` at `0x36a7f8`). Fully invertible:

```python
from canonical import decode_adj_verification
print(decode_adj_verification("...from a captured Authorization header..."))
```

It's the SDK's device/environment integrity report, and it is inside the HMAC input,
so it also has to be right for a signature to verify.

## What's in here

| file | what it does |
|---|---|
| `canonical.py` | `java.lang.String.hashCode`, `HashMap` iteration order, canonical string, HMAC, header assembly, `decode_adj_verification()`, pluggable backends, `SIGNED_FIELDS` allow-list |
| `verify/HM.java` | ground-truth `HashMap.toString()` printer (real JVM) |
| `verify/verify_canonical.py` | 40 randomised cases, Python vs JVM (HashMap bucket order) |
| `verify/verify_v5.py` | 30 cases for the v5 path: `LinkedHashMap` copy + globals + `adj_verification` |
| `verify/stress_collisions.py` | forced-collision stress to find where the port breaks |

## Verification status (not "should work" — actually tested)

```bash
set P=C:\Users\Apps\.workbuddy-ai\binaries\python\versions\3.13.12\python.exe
%P% verify/verify_canonical.py      # 40 passed, 0 failed
%P% verify/stress_collisions.py     # realistic map OK; guard fires where Java diverges
```

Needs `javac`/`java` — this box has them at
`C:\Program Files\Android\Android Studio\jbr\bin\`.

Two real bugs the JVM comparison caught, both of which would have produced a
confidently wrong canonical string:

- **Java 8 appends to the tail of a bin**; Java 7 inserted at the head. Head insertion
  silently reverses order inside every colliding bucket (24/40 cases failed).
- **Treeification fires at 8 nodes, not 9**, and `treeifyBin()` *resizes* when the
  table is under 64 slots. A treeified bin iterates root-first and inserts are linked
  after their parent. The port now models the resize and raises
  `TreeifyUnsupported` instead of guessing.
  On the real 52-field Adjust map the largest bin is **4**, so this is unreachable in
  practice — but it will tell you loudly if that ever stops being true.

## Usage

```python
from canonical import canonical_string_v5, hmac_sha256, build_authorization_header, LocalKeyBackend

params = {                       # activity params, in the SDK's real insertion order
    "app_token": "abc123def456",
    "activity_kind": "session",
    "client_sdk": "android5.6.1",
    "created_at": "2026-09-08T11:34:33.324Z+0530",
    ...
}

s = canonical_string_v5(
    params,
    global_params={"endpoint": "session"},   # appended, in this order
    adj_verification="...",                  # appended last
    source_capacity=64,                      # capacity of the SDK's source HashMap
)
print(s)                                  # exactly what Java HMACs
```

# only meaningful if you hold the raw key (API 18-22 fallback path)
backend = LocalKeyBackend(raw_key=bytes.fromhex("..."))
print(backend.sign(params, adj_signing_id="1400000", headers_id="9"))
```

`initial_capacity` matters: it changes bucket indices and therefore the entire
ordering. The SDK builds these maps with `new HashMap<>()` and grows them; real
packages land at **64**. Verify against a device trace before trusting it.

## Device oracle (the part that actually mints accepted signatures)

Hook points, from `javap` on the real 5.0.0 classes (these are the *kept* names, so
they survive the app's own R8):

| target | gives you |
|---|---|
| `com.adjust.sdk.sig.Signer.sign(Context, Map, Map, Map)` | the public entry — call it to mint |
| `com.adjust.sdk.sig.NativeLibHelper.a(Context, LinkedHashMap, byte[], int)` | the map passed to native + the Java HMAC + the returned 176 bytes |
| `com.adjust.sdk.sig.t1.a(Context, byte[])` | the bytes being HMAC'd — diff these against `canonical_bytes` |
| `com.adjust.sdk.sig.NativeLibHelper` `nSign` | private native, `nSign(Context, Object, byte[], int)` |

```python
from canonical import DeviceOracleBackend

def call_signer(params):            # your frida RPC
    return rpc.exports.sync.sign(params)

sig = DeviceOracleBackend(call_signer).sign(params, "1400000", "9")
```

Expect a fight: `libsigner.so` ships a large emulator/instrumentation detector
(`TracerPid:`, `ro.kernel.qemu.*`, `/dev/qemu_pipe`, Bluestacks/Nox/MEMU/Goldfish
markers, `isInsideSecureHardware`), and the app kills frida-server repeatedly —
re-check `ps -A | grep frida` and restart it with
`su -c 'setsid /data/local/tmp/frida-server … &'` between runs.

To validate the canonical string against the device, hook
`com.adjust.sdk.sig.c.a(Context,[B)` and compare the bytes it HMACs with
`canonical_bytes(params, 64)`. If they match, your ordering and capacity are right.

---

## Correction: the "hook `com.adjust.sdk.sig.c.a(Context,[B)`" line above is wrong

`com.adjust.sdk.sig.c` is an obfuscated list/subList helper — it only has
`<init>(d;II)`, `a()I`, `get(I)`, `subList(II)`. It has **no** `a(Context,[B)`.
The verified signatures (from a dex scan of `classes3.dex`, see `dexscan.py`) are:

```
com.adjust.sdk.sig.d3.a(String) -> byte[]                      # input = CANONICAL STRING
com.adjust.sdk.sig.t1.a(Context, byte[]) -> byte[]             # bytes actually signed
com.adjust.sdk.sig.u2.a(LinkedHashMap, byte[]) -> String       # map + final Authorization HEADER
com.adjust.sdk.sig.o3.a(a0) -> String                          # adj_verification
com.adjust.sdk.sig.NativeLibHelper.a(Context, LinkedHashMap, byte[], int) -> byte[]
```

Hook `d3.a` for the canonical string and `t1.a` for the bytes that get HMAC'd.

## Xposed/LSPosed capture module (frida-free oracle)

frida is fragile here: only attach-by-PID works, `spawn`/`enumerate_processes`
need `system_server` (which degrades a few minutes after boot on this device), and
the app kills frida-server. An Xposed module has none of those problems — it is
loaded *into* the app by LSPosed, needs no ptrace and no activity manager, so the
user can simply tap the app icon.

`module/` builds `module/build/adj9-oracle.apk`:

```bash
bash module/build.sh
adb install -r module/build/adj9-oracle.apk
# enable in LSPosed ("Vector"), scope is auto-set to com.penti.app via xposedscope
adb reboot
# then open Penti, and read:
adb shell "su -c 'cat /data/data/com.penti.app/files/adj9_capture.log'"
# or: adb logcat -d -s ADJ9ORA
```

It records, for every request the app signs: the canonical string, the exact
`LinkedHashMap` insertion order, the Authorization header, `adj_verification`,
and the nSign output length — each as `###ADJ9_BEGIN type=… utf8len=…` / `text:` /
`hex:` / `###ADJ9_END` so the bytes can be diffed exactly.

Build gotchas (already handled in `build.sh`):
* `d8.jar` has no main manifest → `java -cp d8.jar com.android.tools.r8.D8`.
* JBR `javac` emits class-file v69 → must pass `--release 17`.
* d8 needs an explicit `*.class` glob, not a directory.
* The Xposed API stubs are compiled separately and kept out of the dex.
