# Java side of the Adjust Signature SDK (`com.adjust.sdk.sig`) — Signer field map & sign() flow

Date: 2026-09-23. Static only (no device). Source: `adj9/dex/classes3.dex` (the sig package,
`adjust_keys` strings and `com.adjust.sdk.AdjustSigner` all live here), plus `classes6.dex`
for the app's own `NativeKeys`. Method: androguard 4.1.4 (`AnalyzeDex` + DAD) decompiled
**all 125 classes** of `com.adjust.sdk.sig` to `adj9/rev/java_src/`; critical call sites
cross-checked at raw-bytecode level with the in-house `adj9/dexscan.py` parser
(`adj9/rev/decompile_sig.py`, `adj9/rev/decompile_callers.py`).

Companion pieces: `adjust-sig-findings.md` (algorithm + live validation),
`adj9/rev/writer_findings.md` / `WALL_A_SLICE_145.md` (native region writer).

---

## 1. `com.adjust.sdk.sig.Signer` — declared fields, ctors, methods

File: `adj9/rev/java_src/com_adjust_sdk_sig_Signer.java` (dex @ 0x365820 region).

| Field | Type | Modifiers | Set where | Value origin |
|---|---|---|---|---|
| `Companion` | `com.adjust.sdk.sig.t2` | public static final | `Signer.<clinit>` | `new t2()` — **t2 is an EMPTY class** (no fields, no methods; pure Kotlin companion placeholder) |
| `EXCEPTION_MSG_SDK4` | `java.lang.String` | public static final | encoded static value of class_def | compile-time constant `"This version of Adjust Signature is not compatible with Adjust SDK v4. Please upgrade to SDK v5."` |
| `c` | `boolean` | public **static** | `sign(...)` catch handler | **lockdown flag**. Default false. Set `true` only when the native lib reports `sign: Library received error, it has locked down` (native throws `IllegalStateException` with that message through `nSign`/`nOnResume`). Once true, every later `sign()`/`onResume()` throws `IllegalStateException` immediately (checked first under the monitor). |
| `a` | `com.adjust.sdk.sig.NativeLibHelper` | public final | `<init>()V` | `new NativeLibHelper()` — its `<clinit>` runs `System.loadLibrary("signer")` (failure only logs, doesn't throw) |
| `b` | `com.adjust.sdk.sig.t1` | public final | `<init>()V` | `new t1()` — stateless keystore/prefs helper (see §3) |

Methods: `<clinit>()V` (static), `<init>()V` (public), `onResume()V` (public, synchronized),
`sign(Context, Map, Map, Map)V` (public, synchronized — the real one), `sign(Context, Map,
String, String)V` (public, synchronized — **v4-compat stub that always throws** `UnsupportedOperationException(EXCEPTION_MSG_SDK4)`).

**THE HEADLINE: this class has NO `int` field and NO `byte[]` field.** Its only mutable
state is the static boolean `c`. Everything the native side consumes must come from the
objects *passed into* `nSign`, not from `Signer` instance fields (see §4 for the consequence).

`onResume()` = `if (!c) this.a.a()` → `NativeLibHelper.nOnResume()` (private native).
Caller: `com.adjust.sdk.AdjustSigner.onResume(ILogger)` (reflection).

### Instantiation / identity

`com.adjust.sdk.AdjustSigner` (`adj9/rev/java_src/c3_com_adjust_sdk_AdjustSigner.java`,
classes3.dex) holds `private static volatile Object signerInstance` and fills it via
`Reflection.createDefaultInstance("com.adjust.sdk.sig.Signer")` — i.e. one Signer per
process, created lazily, everything reflective (that's why a direct-xref scan for
`Signer.<init>` finds nothing outside the package):

```java
// AdjustSigner.sign(activityParams, globalParams, ctx, logger):
getSignerInstance();
Map out = new HashMap();
Reflection.invokeInstanceMethod(signerInstance, "sign",
    new Class[]{Context, Map, Map, Map},
    new Object[]{ctx, activityParams, globalParams, out});   // out == headers map, filled in-place
return out;
```

## 2. `com.adjust.sdk.sig.NativeLibHelper` — the JNI bridge

File: `adj9/rev/java_src/com_adjust_sdk_sig_NativeLibHelper.java`. **No fields.**

| Method | Descriptor | Body |
|---|---|---|
| `<clinit>` | `()V` | `System.loadLibrary("signer")`; on Throwable logs `"Signer Library could not be loaded: "` (lib stays absent → nSign would throw UnsatisfiedLink later) |
| `<init>` | `()V` | trivial super() |
| `nOnResume` | `()V` | `private final native` — JNI export `Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume` |
| `nSign` | `(Landroid/content/Context; Ljava/lang/Object; [B I)[B` | `private final native` — JNI export `..._nSign`. Note arg2 is declared **`java.lang.Object`** |
| `a` | `()V` | wrapper → `nOnResume()` |
| `a` | `(Landroid/content/Context; Ljava/util/LinkedHashMap; [B I)[B` | pure passthrough → `nSign(ctx, linkedHashMap, hmacBytes, sdkInt)` (bytecode-verified: `invoke-direct v0,v1,v2,v3,v4, nSign(Context, Object, [B I)` with v2 = the LinkedHashMap) |

So the native `nSign` receives exactly: `Context`, **the signing `LinkedHashMap` as
`Object`**, the 32-byte HMAC, and `Build.VERSION.SDK_INT` (a parameter, not a field read).

## 3. `com.adjust.sdk.sig.t1` — Keystore + `adjust_keys` prefs (sole owner)

File: `adj9/rev/java_src/com_adjust_sdk_sig_t1.java`. Implements marker interface `d1`.
**No fields.** String-table xrefs prove t1 is the ONLY class in the app referencing
`adjust_keys`, `encrypted_key`, `AndroidKeyStore`, `HmacSHA256` (and the only
`SharedPreferences` user in the whole sig package).

| Method | Decompiled body | Role |
|---|---|---|
| `b(Context)` | `KeyStore.getInstance("AndroidKeyStore").load(null); if (!ks.containsAlias("key2")) { KeyGenerator.getInstance("HmacSHA256","AndroidKeyStore").init(new KeyGenParameterSpec.Builder("key2", 4 /*PURPOSE_SIGN*/).build()); gen.generateKey(); }` | ensure HMAC key exists (non-exportable TEE key; NOT a pref) |
| `a(Context, byte[])` | `Mac.getInstance("HmacSHA256").init(ks.getKey("key2", null)); mac.update(input); return mac.doFinal();` | **the sign-time HMAC** — HMAC-SHA256 of the canonical string, 32-byte result |
| `a(Context)` | `ks.deleteEntry("key2"); ctx.getSharedPreferences("adjust_keys", 0).edit().remove("encrypted_key").apply();` | wipe: delete keystore key + clear prefs entry |

### `adjust_keys` SharedPreferences — read/write trace (complete)

- **Written by Java: nowhere.** No Java code in the entire app writes `encrypted_key`.
- **Read by Java: nowhere.** No `getString("encrypted_key")` exists in the dex.
- Java only **removes** the entry (`t1.a(Context)`, the retry wipe path).
- The write/read of `encrypted_key` (RSA-wrapped copy of the software HMAC key,
  `RSA/ECB/PKCS1Padding`) is done by the **native lib itself** — `adjust_keys`,
  `encrypted_key`, `RSA/ECB/PKCS1Padding` are in `libsigner.so`'s XOR string table
  (`WALL_A_SLICE_145.md` §2). That fallback only matters on API 18–22.
- Device evidence: `adj9/device/java_dump/shared_prefs/` has **no `adjust_keys.xml`** —
  on this API≥23 device the file was never created (TEE path used).

## 4. THE int field read by JNI GetIntField — candidates

Native context (from `writer_findings.md` §F2, slot 0x320 = **GetIntField**, instance not
static; two `GetFieldID` calls with two different XOR-obfuscated name blobs 0x153690 /
0x1536a0, sig blob 0x1540d4; interleaved with an object-graph walk `sub_9afa4` over the
same object; results stored to region dwords ctx[0x60]/ctx[0x64]):

```
clazz = GetObjectClass(env, obj)            # 0xbe6a8
fid   = GetFieldID(env, clazz, dec(0x153690|0x1536a0), dec(0x1540d4))   # 0xbe49c
ctx[0x60] = GetIntField(env, obj, fid)      # 0xbe604 call #1
ctx[0x64] = GetIntField(env, obj, fid)      # 0xbe604 call #2
```

Java-side verdict:

1. **It cannot be a field of `com.adjust.sdk.sig.Signer` — no such field exists** (§1).
   The task's working label "Signer instance" is a misnomer for this build: the jobject
   available inside static JNI export `nSign` are (a) the `Context` argument and (b) the
   `Object` argument = **the signing `java.util.LinkedHashMap`** (§2).
2. **Best candidate: the `LinkedHashMap` passed as arg2.** The native code already walks
   that same object as a graph (`sub_9afa4(signer_obj, 0)` = the map's node table walk)
   and pulls its String values via the decoded `getBytes` bridge. A stock Maven lib built
   against system classes can only rely on **JDK field names**, and `LinkedHashMap` has
   exactly two stable `I` fields visible to `GetFieldID`:
   - **`size`** (`"size"`, sig `"I"`, inherited `java.util.HashMap`) → 50 for the standard
     47-source-field request (47 + `activity_kind` + `client_sdk` + `adj_verification`).
   - **`modCount`** (`"modCount"`, sig `"I"`, `java.util.AbstractMap`) → 50 at nSign time
     for the same request (47 inserts during `new LinkedHashMap(d)` + 3 more puts in u2).
   The two distinct GetFieldID blobs map naturally to these two names. Both are
   deterministic per payload, which **matches the device struct-diff finding "No counter
   behavior at B+0x64"** (`WALL_A_SLICE_145.md` §3) — there is no per-sign increment.
3. **"Int counter that changes per sign() call": does not exist on the Java side.** The
   only mutable Signer field is a boolean (`c`, lockdown). No static int, no AtomicLong,
   no counter anywhere in the 125 sig classes (field census in
   `adj9/rev/java_src/_decompile_log.txt`: the package's int fields are all
   iterator/config plumbing — `f.b`, `e1.*`, `j1.c`, `l1.c`, `o1.b` (char[] length),
   `r2.a` (enum ordinal) — none persistent). Whatever varies per call in the region
   (timestamps, HMAC, 192-byte blob) is produced native-side or is in the byte[]/map data,
   not a Java int field.
4. Second-order candidate (less likely): the `Context` arg — but its runtime class is
   app-specific (`android.app.ContextImpl`/`Application` wrapper with app-defined fields),
   which a stock library cannot reference by name. Rejected.
5. The 4th `nSign` argument (`Build.VERSION.SDK_INT`) is the only other int crossing the
   boundary — a parameter, not a `GetIntField`.

**Bottom line:** `GetIntField` best candidates = `java.util.HashMap.size` and
`java.util.AbstractMap.modCount` of the signing `LinkedHashMap` (name blobs 0x153690/0x1536a0
pending the state-graph crack; both sig `"I"`). No `Signer`-declared int field exists.

## 5. sign() call flow in Java (ordered pseudo-code)

Bytecode cross-checked (`u2.a()V` @ 0x36ab2c; invoke/const-string sequence verified with
the minimal dex parser; DAD output in `java_src/com_adjust_sdk_sig_u2.java`):

```java
// 0. startup (once, reflective)
AdjustSigner.signerInstance = Reflection.createDefaultInstance("com.adjust.sdk.sig.Signer");
//   Signer.<init>: a = new NativeLibHelper()  -> loadLibrary("signer")
//                  b = new t1()

// 1. per request — Adjust SDK -> AdjustSigner.sign(activityParams, globalParams, ctx, logger)
// 2. Signer.sign(ctx, d=activityParams, e=globalParams, f=headersMap)   [synchronized]
synchronized (this) {
    if (c) throw new IllegalStateException("sign: Library received error, it has locked down");
    // Kotlin null-checks (IllegalArgumentException "Required value was null.") on all 4 args
    // k3.a(f) = checkNotNull intrinsic
    new u2(ctx, /*b*/ t1, /*c*/ nativeLibHelper, d, e, f).a();   // real work
    // catch: NPE->"sign: Required parameter is null"; ISE->"sign: Incorrect library state";
    //        other -> log "sign: Unhandled exception: "+msg;  if msg=="sign: Library received
    //        error, it has locked down" -> c = true (permanent lockdown)
}

// 3. u2.a()  (fields: a=ctx, b=t1, c=NativeLibHelper, d/e/f=maps, g=x1 logger)
g.a("Signature execution begin: ");
LinkedHashMap map = new LinkedHashMap(d);              // copy of activity params (source order)
for (k : {"activity_kind", "client_sdk"}) {
    v = e.get(k); if (v == null) { log; return; }       // abort, request goes out unsigned
    map.put(k, v);
}
if (!"b".equals(e.get("a"))) {                          // obfuscated kill-switch: e["a"]=="b" => NO signing
    map.put("adj_verification", o3.a(new a0()));        // = Base64( XOR19("Data(osName=android)") ) — constant
    Object hmac; int attempt = 2;
    while (attempt > 0) {
        try {
            b.a(ctx);                                    // t1.b: ensure AndroidKeyStore HmacSHA256 "key2"
            hmac = b.a(ctx, d3.a(map.toString()));       // t1.a: HMAC-SHA256(UTF-8(LinkedHashMap.toString())) -> 32B
        } catch (UnrecoverableKeyException | InvalidKeyException ex) {
            log("sign: Received a retriable exception: " + ex);
            log("sign: Attempting retry #" + attempt);
            attempt--;
            b.a(ctx);                                    // t1.a(ctx): deleteEntry("key2") + prefs adjust_keys remove encrypted_key
                                                         // -> next loop iteration regenerates a FRESH key2 and re-HMACs
        } catch (s1 ex) {
            throw new b2("sign: API is less than JellyBean-4-18");
        }
        if (attempt == 0) throw new b2("sign: Reached maximum retries");
        g.a("Calling native begin: ");
        byte[] sig = c.a(ctx, /*LinkedHashMap*/ map, /*byte[]*/ hmac, Build.VERSION.SDK_INT);   // -> nSign
        g.a("Calling native end: ");
        if (sig == null) { log("sign: Returned a null signature. Exiting..."); return; }        // unsigned
        try {
            f.put("authorization", u2.a(map, sig));      // header builder
        } catch (ex) { log("sign: Signature generation failed. Exiting..."); throw ex; }
    }
    hmac = null;
}
f.putAll(d);                                            // headers also carry all activity params
for (k : {"network_payload", "endpoint"})               // + these two globals when present
    if (e.get(k) != null) f.put(k, e.get(k));
g.a("Signature execution end: ");

// 4. u2.a(LinkedHashMap, byte[] sig) — Authorization header (Base64.NO_WRAP of 192B blob)
//    Signature signature="..",adj_signing_id="..",algorithm="adj9",headers_id="..",
//              native_version="5.0.0",adj_verification=".."
//    any null component -> log "Required value was null." -> return null -> request unsigned
```

## 6. byte[] material and HMAC/Keystore usage at sign time

- **Into `nSign`: exactly one byte[] — the 32-byte HMAC** from `t1.a(ctx,
  d3.a(map.toString()))`, where `d3.a(s)` = `s.getBytes(j.a)` with `j.a = UTF-8`
  (`java_src/com_adjust_sdk_sig_d3.java`, `..._j.java`). HMAC input =
  `LinkedHashMap.toString()` of the 50-entry signing map (canonical string; see
  `adjust-sig-findings.md` for the byte-for-byte validated model).
- **HMAC/Keystore at sign time: exactly one path** — `t1.a/t1.b` above
  (`javax.crypto.Mac` HmacSHA256 + AndroidKeyStore alias `key2`, PURPOSE_SIGN).
  No other `KeyStore`/`Mac`/`Cipher` reference exists in the 125 sig classes.
- **Java byte[] constants in the package** (neither feeds nSign):
  - `s2.a` = 19-byte adj_verification XOR key `51 75 6F 68 ...` = `"Quoh8uafohgh7CahM2h"`.
  - `w2.b` = 93-byte JSON-escape lookup table (kotlinx.serialization plumbing; `w2.a` =
    the 93 escape strings). Part of the serializer that renders `a0` for adj_verification.
- **byte[] material fetched BY the native side** (`#0/#4` in the writer model): the
  decoded bridge name is **`getBytes`** (`writer_findings.md` §F3) — the lib pulls String
  values out of the passed `LinkedHashMap` (params: `secret_id`, `client_sdk`, …) and
  calls `String.getBytes()` over JNI. Additional native-side material (per its string
  table): prefs `adjust_keys`/`encrypted_key` + `RSA/ECB/PKCS1Padding` (API 18–22
  fallback only) and APK-cert fetchers for the SHA-1 (#9). No Java byte[] blob is
  stored on Signer.

## 7. Side note — app's own `libpenti-native-keys.so`

`com.penti.core.data.security.NativeKeys` (classes6.dex;
`adj9/rev/java_src/c6_com_penti_core_data_security_NativeKeys*.java`):

- `<clinit>`: singleton `instance` + `Companion`; `try { System.loadLibrary("penti-native-keys") } catch { }` → `isLibraryLoaded` flag (load failure swallowed).
- ~25 lazy `String` getters delegating to private `native String native*()` methods
  (`nativeAdjustKey`, `nativeClarityKey`, `nativeGoogleSignInServerClientId`,
  `guestClientId/Secret`, `masterPass{Url,SystemId,SystemKey,SystemIdTest,SystemKeyTest}`,
  `personaClickStoreKey`, …) — plain app-secret getters, matching the 25
  `Java_com_penti_core_data_security_NativeKeys_native*` exports in the .so
  (`writer_findings.md` §F5). **No interaction with the Adjust signing pipeline.**

## 8. Deliverable file index

- `adj9/rev/java_src/` — DAD decompilation of all 125 `com.adjust.sdk.sig` classes +
  `c3_com_adjust_sdk_AdjustSigner.java` + `c6_*NativeKeys*.java` (field/method summary in
  every header comment; `_decompile_log.txt` = package-wide field/method census; logs of
  both runs).
- `adj9/rev/decompile_sig.py`, `adj9/rev/decompile_callers.py` — reproducible androguard
  scripts (run from any cwd; `python adj9/rev/decompile_sig.py Signer NativeLibHelper t1 u2`
  re-dumps single classes).
- Key sources: `com_adjust_sdk_sig_Signer.java`, `com_adjust_sdk_sig_NativeLibHelper.java`,
  `com_adjust_sdk_sig_t1.java`, `com_adjust_sdk_sig_u2.java`, `c3_com_adjust_sdk_AdjustSigner.java`.

Caveats: DAD output is verbose/imprecise on types in `u2.a()` (`String v2_12 = this.b` for
what is really the `t1`/byte[] pair) — the ordered invoke/const-string sequence above was
verified independently at bytecode level; the native `signer_obj` name binding
(GetFieldID blobs) remains XOR-cracked-only-partially by the native-side effort, so §4's
`size`/`modCount` identification is inference from (a) the Java argument types, (b) the
"no counter behavior" device diff, and (c) the object-graph walk — not from the decoded
name string.
