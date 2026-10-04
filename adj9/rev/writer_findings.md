---
title: writer_findings
---

# SLICE 141 — the region-struct writer chain, found statically (worker + 0x97200 + builder)

Date: 2026-09-22. Pure static pass over `libsigner.so` (no device). Tools: `rev/dump_at.py`,
new `rev/scan_refs.py` (whole-binary linear sweep: bl targets / adrp-formed globals /
immediate-offset accesses incl. stp/ldp), new `rev/symtrack.py` (symbolic pointer+stack-slot
tracking for O-LLVM spill idioms). Artifacts: `rev/wf_worker.log`, `rev/wf_fn97200.log`,
`rev/wf_fn95fc4.log`, `rev/wf_mega.log` (0x8d6f4..0x95fc4), `rev/wf_be168full.log`,
`rev/wf_engine.log`.

## 0. The decisive global fact: the two JNI exports

`elf.py` dynsyms — libsigner.so exports exactly two functions:

```
0xda4b0  Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume
0xdb1cc  Java_com_adjust_sdk_sig_NativeLibHelper_nSign
```

`nSign` (0xdb1cc) calls `sub_95fc4` directly at **0xdb24c** (args: w0=cmd=w5, x1=x0,
x2/x3/x4 = request payload ptrs spilled at [x29-0x50..-0x58], x2-out = [x29-0x60]).
`nOnResume` contains the `sub_97200` call at **0xda63c**. Everything analyzed below hangs
off these two.

**KEY IDENTIFICATION — the "vtable" calls are the JNI function table.** x1 of sub_95fc4 is
nSign's arg0 = `JNIEnv*` (`ldr x8,[x20]` = env->functions):

| site | slot | JNI function (index) | matches |
|---|---|---|---|
| 0x9617c (in 0x95fc4) | 0x6d8 = 219 | `GetJavaVM(env, &vm)` | out-param = `&global 0x155aa8`, success test `w0==0` = JNI_OK |
| 0x96320 (worker) | 0x20 = 4 (JavaVM) | `AttachCurrentThread(vm, &env, &args)` | `[sp+0x10] = 0x10006` = JNI_VERSION_1_6 |
| 0x96c88 (worker) | 0x28 = 5 (JavaVM) | `DetachCurrentThread(vm)` | no args |
| 0xbe49c | 0x2f0 = 94 | `GetFieldID(env, clazz, name, sig)` | name/sig = XOR-deobfuscated strings |
| 0xbe5f8 | 0x320 = 100 | `GetStaticIntField(env, clazz, jfieldID)` | returns the dword stored into the region struct |
| 0xbe6a8 | 0xf8 = 31 | `GetObjectClass(env, obj)` | |
| 0xbe818 | 0xb8 = 23 | `DeleteLocalRef(env, obj)` | |

So global **0x155aa8 = the cached `JavaVM*`** (fetched once per nSign via GetJavaVM), the
worker thread **attaches to the JVM** (version 1.6) before doing anything, and the whole
"engine" is a JNI bridge.

## 1. TASK 1 — the worker 0x962ac..0x971e4, de-flattened

`bl 0x13de90` at 0x962ec = elapsed-time helper: `clock_gettime` (thunk 0x148a80) →
`d0 = (sec + nsec/1e9) - arg_d0`, also writes `14` to `*arg0` on one flattened path.
Worker saves t0 in d8.

Virtual prologue: `GetJavaVM` was already done in 0x95fc4; worker does
`AttachCurrentThread(vm[0x155aa8], &env=[sp+0x28], {JNI_VERSION_1_6})` at **0x96320**
(`blr x8`), then runs a tag-dispatch state machine (initial tag chosen by
`csel x21, x9, x8, eq` on the attach result: x8=0x3df5d7d84891b0b0 / x9=0xf79c67ad07407811).

Real operation order reconstructed (tags → handler VAs):

1. CAS-acquire flag (`0x1483e0(0,1,&flag)` = `casab` byte test-and-set) on
   0x155a84 / 0x155a88 / 0x155a8c — guards for three scratch buffers.
2. **Engine calls** `0x99ac8(env, dst, len)` (wrapper over sub_97414 with state u32
   `[0x155aa4]`, skipped when non-zero), five sites:
   - 0x96b7c dst=0x153788 len=0x40; 0x96c10 dst=0x153790 len=0x40;
   - 0x96d54 dst=0x153790 len=0xc; 0x9700c dst=0x153788 len=0xc; 0x97184 dst=0x153794 len=0xc.
   (0x153788/0x153790/0x153794 are overlapping windows of one ~72-byte scratch block.)
3. **De-obfuscation states**: `d0=[0x153788] ^ 0x0404040404040404` stored back
   (0x96fd8-0x96fe0, flag 0x155a96=1); bytes [0x153790..2] ^= 0x1e (0x96e98/0x97118,
   flag 0x155a97=1); bytes [0x153794..7] ^= 0xb5 (0x96f5c, flag 0x155a98=1).
4. Gates/counters: `[0x155aa4]` engine-state checked before engine calls (0x96b88 etc.),
   set to 0x2b at 0x96c70; `[0x155aa0]` compared >0x20/0x1e (0x96da8/0x970c8);
   `stlr 2 -> [0x155a9c]` at 0x96cd0; tiny accessor at 0x971e8 returns `[0x155a9c]==2`.
5. `DetachCurrentThread` at **0x96c88**; epilogue 0x971a8 (stack-cookie check, `mov x0, xzr`).

**The worker never writes anything resembling the region layout** — its only non-stack
stores are to the scratch block 0x153788-0x15379f and the flag/state globals
0x155a96-0x155aa4. It is the per-signing JNI-attached config fetcher/deobfuscator.

## 2. TASK 2 — the flagged store sites, bases resolved

Worker sites (0x96c70/0x96ecc/0x96f88-fa8/0x96fb4/0x96fe0/0x96fe8/0x97148-160): all bases
are `adrp 0x155000`/`adr`-formed **globals** (0x155aa4, scratch 0x153790/0x153794,
flags 0x155a96-a98). No region offsets.

Next function **0x97200** (NOT 0x97204 — it starts at 0x97200 `sub sp,#0x70`) is the
**config-snapshot submit**. De-flattened (initial tag 0x2fb96acdb22d7fe0):

```
0x97220  add x8, x1, #0x20        ; arg1+0x20 saved for later use
F(0x9738c): if ([0x155a90]!=0) { memset-ish 0x1441e4(arg1+0x20, 0x30); [arg1+0xf0] |= 1 }
A(0x97300): w20 = [0x155aa4]      ; engine state
B(0x97324): *arg0 = w20           ; 0x97338 str w20,[x9], x9=[sp+8]=arg0 (caller out u32*)
C(0x973cc): x0=[0x155ab8]; ret=calloc(ret,1); *arg1+0x130 = ret   ; 0x973ec
            memcpy(ret, [0x155ac0], [0x155ab8]); [arg1+0x128] = [0x155ab8]  ; 0x97378
D(0x97340): *arg0 = 2             ; 0x97358
```

So the **0xf0/0x128/0x130 triple = fields of the manager object (arg1)**: 0xf0 = status
flags, 0x128 = size of a global config blob, 0x130 = private calloc'd copy of it
(globals 0x155ab8 = size / 0x155ac0 = data; written by the engine family, never by direct
adrp stores). **None of 0xf0/0x128/0x130 matches the region layout** — different base
object, different purpose. Caller: exactly one — `0xda63c` in nOnResume
(`x0 = &local u32; x1 = x19 = manager object`). A second tiny export-side accessor at
0x971e8 = "engine finished?" predicate.

## 3. TASK 3 — the actual region-struct writer chain (the answer)

The region struct (runtime base B; fields 0x8=claims-len, 0x60/0x64, 0x74, 0x94,
0x134, 0x144) is filled by the **VM's builder**, not the worker:

```
VM interpreter fn (entry ~0xfb00; tag dispatcher at 0xffc74; body includes the
  descriptor-walk blocks at 0x100094.. — 0x100094 has NO callers/branches to it and no
  data pointers to it: the dispatch jumps INTO its blocks, e.g. the copy loop
  0x100150-0x100194 and the LENQ tail 0x100228+)
  0xfb50:  memset(sp+0x38, 0, 0x878)          ; zero a 2168-byte context frame
  0xfb64:  bl 0x8d6f4(x0, x1, ctx=sp+0x38, x3) ; THE REGION BUILDER
```

**sub_8d6f4** (flattened, ~35 KB, 0x8d6f4..0x95fc4, 72 calls) — symbolic tracking
(`symtrack.py`) shows it writes the ctx field table: qwords at +0x00..+0x68
(0x90988 `str x9,[x8,#0x28]`, 0x93a00 `str x9,[x8,#8]` = **claims byte-length at ctx+8**,
0x92134 +0x68, 0x92be4 +0x58, ...). It:

1. Forms `&ctx+0x64` (0x8d77c) and `&ctx+0x60` (0x8d790), spills them through
   O-LLVM randomized stack slots.
2. Collects environment: **13× `0xe2948(name?, val)`** — that family calls
   `__system_property_get` (0xe2b7c), `syscall` ×many, `read`+`close` (file probes,
   e.g. 0xe3c44), each gated by CAS byte flags at 0x1556xx-0x1559xx
   (16× `0x1483e0`).
3. **De-obfuscates static config blobs** in .data with per-blob byte XOR keys:
   0x1525d0 ^= 0x6c (16B, 0x93880-0x938a0), 0x1540d4[0..1] ^= 0x22 (0xbe77c),
   plus `movi vN.8b` key vectors 0x60/0x32/0xea/0x66/0xd0/0xa9/0xb5/0xb1 loaded at
   0x8d730-0x8d76c. These blobs are the JNI **class/field name+signature strings**.
4. **sub_be168(out_status, env, x2, x3, &ctx+0x60 / &ctx+0x64)** — called twice
   (0x912d0 with &ctx+0x60, 0x93814 with &ctx+0x64):

```
0xbe48c  ldr  x8, [x22]            ; env->functions
0xbe498  ldr  x8, [x8, #0x2f0]     ; GetFieldID(env, clazz, name, sig)   <- deobfuscated strings
0xbe49c  blr  x8
0xbe4a4  bl   0x9afa4(env, 0)      ; the recursive builder walks in between
0xbe5f4  ldr  x8, [x8, #0x320]     ; GetStaticIntField(env, clazz, jfieldID)
0xbe5f8  blr  x8
0xbe5fc  ldr  x8, [sp, #0x20]      ; = &ctx+0x60 (or &ctx+0x64)
0xbe604  str  w0, [x8]             ; *** REGION DWORD STORED ***
0xbe60c  bl   0x9afa4(env, 0)
```

   **Descriptor #2's dword (B+0x64, and its partner B+0x60) = `GetStaticIntField` of a
   Java class field** whose name/signature strings are XOR-obfuscated in this library and
   deobfuscated at runtime. 0xbe168 also drives GetObjectClass/DeleteLocalRef around them
   and writes status codes (0x1c/0x12/3) to *out_status.

5. **Data-source classification of the fill**: the engine ladder under 0x97414
   (0xa96c0 → 0xaa24c → 0xaba3c → 0xac1fc → 0xacc7c → 0xae3cc → 0xaef9c → 0xaf73c →
   0xb0060 → 0xb118c → 0xb1df0 → 0xc8314) calls **only** calloc/malloc/memcpy/free —
   **zero entropy imports** in the entire signing region 0x95fc4-0xc8314+0x8d6f4-0x95fc4.
   `rand/srand/time/gettimeofday` are used only at 0x12a2fc/0x12cbc0/0x13e5fc (unrelated:
   the 0x12-0x13 utility/net region). The only hash material is a SHA-1/MD5 constant block
   at 0x3610-0x364f (67452301 efcdab89 98badcfe 10325476 c3d2e1f0 5a827999 6ed9eba1
   8f1bbcdc) referenced at 0x8d434 (sibling function that also reads [x0,#0x60/#0x64]) and
   0x12e604 — consistent with #9 = cert SHA-1 being computed/deobfuscated, not random.
   The 64-byte repeated fills (`stp q0,q0,[x8,#-0x50]; stp q0,q0,[x8,#-0x30]` at 0x92ea4)
   and keyed-XOR block stores match the runtime tile structure of #0/#4.

## 4. TASK 4 — VERDICT

Writers of the region-struct fields:

- **B+0x08 (claims len)**: sub_8d6f4 @ 0x93a00 (`str x9, [x8, #8]`).
- **B+0x60, B+0x64 (descriptor #2 + partner)**: sub_be168 @ **0xbe604**
  (`str w0, [x4]`), value = **JNI GetStaticIntField** (slot 0x320) after
  GetFieldID (slot 0x2f0) with deobfuscated name/sig; chain invoked from sub_8d6f4
  at 0x912d0 / 0x93814; the whole thing driven by nSign → 0x95fc4 → VM → 0x8d6f4.
- **B+0x74 (#4), B+0x94 (#0), B+0x134 (#8), B+0x144 (#9)**: filled inside sub_8d6f4's
  flattened handlers via the same primitives — deobfuscated static config blobs
  (#8/#9), keyed-XOR block construction over the ctx fields (0x60-0x68 + claims len +
  SHA-1 material) for the #0 tile/#4 — exact handler VAs not individually pinned
  (O-LLVM randomized spill slots; see Remaining unknowns).

Classification:
- **(a) static table copy — YES, but obfuscated**: #8 (bfffffff fffffd1f 00070000
  00000000) and #9 (fad0f10d 60f93c17 937b2f1e b6c09691 ae7d74bd) live as XOR-keyed
  blobs in .data (0x152xxx/0x1540d4 family) and are deobfuscated in place; the strings
  the builder needs are the same kind of blob. These are offline-computable once the
  per-blob XOR keys are lifted (keys observed: 0x6c, 0x22, 0x1e, 0xb5, 0x0404..04,
  vectors 0x60/0x32/0xea/0x66/0xd0/0xa9/0xb5/0xb1).
- **(c) keyed/arithmetic function of request data — YES**: #2 is literally a Java
  static int field (request/session-scoped, fetched via JNI); #0/#4 are keyed-XOR
  constructions over ctx material (claims length, field values, SHA-1 state).
- **(b) PRNG — NO**: no rand/srand in the pipeline; engine ladder is deterministic.
- **(d) kernel entropy — NO**: no getrandom/dev-urandom in the signing path; the
  syscalls in the 0xe2xxx-0xe4xxx family are property/file environment probes feeding
  anti-tamper fields, not the signature words.

Slice-131's "uncomputable heap memory" conclusion is thereby REFINED: the inputs are not
raw ASLR heap bytes — they are **Java-side values + deobfuscated embedded config**,
fetched through a JNI bridge that statically is fully visible. The blob is offline-
computable in principle once (i) the Java class/field names are lifted from the XOR
blobs, (ii) the state-graph order of sub_8d6f4/0xbe168 is linearized, and (iii) the
Java side of the fields is reproduced. That is the jackpot path.

## 5. Remaining unknowns

1. Exact handler VAs inside sub_8d6f4 for the 36-dword (#0) and 8-dword (#4) fills —
   requires a tag-state-graph walker (the obfuscator re-randomizes the
   `sub xN, x29, #M; ldur [xN,#-0x100]` slot split per access).
2. Content of the XOR blobs (Java class/field names, sigs, the #8/#9 raw material) —
   lift by XORing with the observed keys, then read as strings.
3. The Java side of the GetStaticIntField fields (com.adjust.sdk.sig package) and the
   byte arrays the engine reads with len 0x40/0xc — the last input plane.
4. Which vtable slots the LENQ pair 0x147630/0x147734 wraps (VM read-back, not writer).

## 6. Artifacts

- `rev/scan_refs.py`, `rev/symtrack.py` — new scanners (whole-binary sweep w/ stp/ldp,
  symbolic pointer/spill tracking)
- `rev/wf_worker.log`, `rev/wf_fn97200.log`, `rev/wf_fn95fc4.log`, `rev/wf_mega.log`,
  `rev/wf_be168full.log`, `rev/wf_engine.log`, `rev/wf_engine_head.log`

## Follow-up: Java-side extraction

Date: 2026-09-22 (same static pass, continued). New tools: `rev/blob_brute.py`
(single-byte-XOR brute force + JNI-slot scan), `rev/blob_table.py` (self-describing
table parser), `rev/decode_blobs*.py` (handler-driven decoders). Key artifacts:
`rev/blob_table.log` (770 decoded entries), `rev/blob_brute.log`.

### F0. The obfuscated-string table format (mechanism)

The .data string area (VA 0x151000-0x15540A, file_off = VA - 0x7E20) is a
**self-describing XOR table**: each entry is `[data ^ key][key][00 00 00]` — the
key byte follows the payload, then 3 zero bytes. Example at 0x152560:
`...3275781c 00000000` with key 0x1c -> `ro.build.display.id\0`.
The same table also holds *binary* entries (keys/IVs) that do not decode to ASCII.
Every entry is also decrypted in place at runtime by a dedicated O-LLVM state
(`movi vN.8b, #key; ldr d/q; eor; str` + `strb #1, [flag 0x1552xx/0x1553xx]`),
CAS-guarded by `0x1483e0` on a per-entry flag byte — 5600 guarded references total.
Multi-pass XOR chains exist (e.g. 0x1525d0 shows code-key 0x6c but the static
plaintext needs 0xf2; 0x1536a0 shows code-key 0xea): the effective key is the XOR
of all passes, so a handler's immediate key alone is not always the final key.

### F1. Decoded string inventory relevant to the signer

The full 770-entry decode is in `rev/blob_table.log`. Entries that name the Java
plane (verified plaintext):

```
0x151a3f  key=bd  client_sdk
0x151a6c  key=d0  com.adjust.sdk.sig.Signer::sign\0AdjustSigner
0x151abf  key=ce  secret_id
0x151b1c  key=bb  adj9
0x151c99  key=7b  ro.build.version.release
0x151cbe  key=9e  ro.build.version.sdk
0x151cd8  key=7e  os_version
0x151ce7  key=83  api_level
0x151cf5  key=66  app_version
0x151d07  key=24  android_id
0x151d16  key=27  fire_adid
0x153540  key=36  java.security.NoSuchAlgorithmException
0x1535d4  key=7d  decode
0x153602  key=52  javax/crypto/Cipher        (+ getInstance, init)
0x15366c  key=d2  init
0x1536ca  key=29  (Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;   (Map.put)
0x15371c  key=4b  remove
0x153756  key=70  toString                   (+ ()Ljava/lang/String;)
0x153788  key=c7  getBytes                    <- inside the engine scratch window!
0x1537a0  key=ff  android/security/keystore/KeyGenParameterSpec$Builder
0x1537df..15393a  setAttestationChallenge ([B)L...Builder;, setIsStrongBoxBacked (Z)L...;,
                  ()Ljava/security/KeyPair;
0x153a5b  key=1d  getPrivate                  (+ ()Ljava/security/PrivateKey;)
0x153a90  key=0f  java/security/KeyFactory    (+ getKeySpec-ish sigs)
0x153b5d  key=d4  android/security/keystore/KeyInfo (+ getSecurityLevel ()I)
0x153bcf  key=eb  getCertificateChain         (+ (Ljava/lang/String;)[Ljava/security/cert/Certificate;)
0x153c2f  key=f4  java/security/KeyStore      (+ getInstance sig, load)
0x153d40  key=a6  (Ljava/lang/String;[C)Ljava/security/Key;
0x153daf  key=1c  javax/crypto/Mac            (+ (Ljava/lang/String;)Ljavax/crypto/Mac;)
0x1545b0  key=cd  ...HmacSHA256               (+ getEncoded, getAlgorithm-ish)
0x153e5f  key=69  java/security/MessageDigest
0x153f17  key=95  getPackageName              (+ getPackageManager)
0x153f7f  key=f4  getSharedPreferences        (+ (Ljava/lang/String;I)Landroid/content/SharedPreferences;)
0x154050  key=1a  android/view/Display        (+ getMetrics, DisplayMetrics, widthPixels, heightPixels)
0x1540cf  key=dc  signatures
0x1540de  key=4f  signingInfo                 (+ Landroid/content/pm/SigningInfo;)
0x15436e  key=f0  getApkContentsSigners       (+ ()[Landroid/content/pm/Signature;)
0x1543bd  key=18  getSigningCertificateHistory
0x1543e0  key=69  hasMultipleSigners
0x15443f  key=fe  java/lang/Thread            (+ currentThread, getStackTrace - anti-hook stack check)
0x154517  key=a3  versionName
0x15452d  key=26  getContentResolver          (+ android/provider/Settings$Secure -> android_id)
0x154664  key=11  RSA/ECB/PKCS1Padding
0x154668  key=59  adjust_keys                 <- SharedPreferences file name
0x154686  key=40  AES
0x15468f  key=d4  environment                 / 0x15469f key=33 sandbox
0x154753  key=95  TracerPid:                  (anti-debug, /proc/self/status)
0x15470c  key=fc  /dev/__properties__/property_info
0x1547a5  key=65  injector
0x1547cf  key=70  HostSession
0x154f46  key=8f  /dev/urandom                <- entropy IS referenced somewhere in the lib
```

Plus ~700 anti-emulator/anti-tamper probes (ro.kernel.qemu.*, /dev/socket/qemud,
/system/bin/qemu-props, BlueStacks/Nox/LdVM/VirtualBox/Genymotion/MEMU...)
and device-property names. A 64-hex-char constant sits at 0x1534f0 (plaintext,
unobfuscated): `b1c22b0c02505175fdc8651d3a623c0499fcec04941db33f1f83aae7701faa16`
(a SHA-256 as hex — likely a pinned digest for one of the verification paths).

### F2. JNI call sites in the region-builder path (verified args)

The "vtable" of the object threaded through sub_8d6f4 -> sub_be168 is the
JNIEnv function table (verified via GetJavaVM/AttachCurrentThread semantics).
The #2-int chain inside sub_be168:

```
0xbe6a8  slot 0xf8 (GetObjectClass)          clazz = GetObjectClass(env, signer_obj)
0xbe49c  slot 0x2f0 (GetFieldID, idx 94)     fid   = GetFieldID(env, clazz, name, sig)
                                             name <- arg3 blob (0x153690 call#1 / 0x1536a0 call#2)
                                             sig  <- x3 = 0x1540d4 (7B+20B blob, ^0x22 pass seen)
0xbe4ac/0xbe60c/0xbe6b8  bl 0x9afa4          recursive builder walk interleaved between calls
0xbe5f8  slot 0x320 (GetIntField, idx 100)   w0 = GetIntField(env, signer_obj, fid)
0xbe604  str w0, [x4]                        *(&ctx+0x60) / *(&ctx+0x64) = w0   <- REGION DWORDS
0xbe818  slot 0xb8 (DeleteLocalRef, idx 23)  DeleteLocalRef(env, clazz)
```

The name/sig blobs (0x153690, 0x1536a0, 0x1540d4) are runtime-multi-pass-XOR
blobs (in-place passes observed: 0x58 @0x9086c for 0x153690, 0xea @0x90d64 for
0x1536a0, 0x22 @0xbe76c for 0x1540d4[0..1]); their final runtime plaintext needs
the full pass chain (state-graph walk). Note the static-table entry `([B)[B`
decodes from 0x1536a0's at-rest bytes under key 0x70, and `secret_id` /
`client_sdk` are in the same table — the field name is almost certainly one of
these tags, but the exact binding is not yet proven.

### F3. The 0x40/0xc engine "buffers" — what they really are

The three addresses are NOT runtime data buffers — they are **string-table
entries used as engine arguments**:

- 0x153788 (len arg 0x40): at-rest = `"getBytes"` XOR-obfuscated (key 0xc7),
  followed by 56 more bytes of string-table material. The engine call
  `0x99ac8(env, 0x153788, 0x40)` therefore passes a 64-byte *obfuscated name
  blob* to sub_97414, which multi-pass-decrypts it in place and uses it as a
  Java method name — the decoded name is `getBytes` (String -> byte[] bridge).
- 0x153790 (len 0xc) / 0x153794 (len 0xc): 12-byte windows over the same blob
  area (0x153790..0x15379b, 0x153794..0x15379f; at-rest tail decodes under key
  0xff to `android/security/keystore/...`). The worker's final XOR states
  (^0x1e on 3 bytes at 0x153790, ^0xb5 on 4 bytes at 0x153794, ^0x0404..04 on
  the 8 bytes at 0x153788, all flagged by 0x155a96-a98) are the last passes of
  these chains; the double at [0x153788] is the first 8 bytes of the blob
  (`getBytes`), not a timestamp.
- State 0xe104706a4d2223f8 (0x9cee0) additionally applies a 16-byte ^0xc8 pass
  at 0x1537a0 and the engine runs FindClass (0x9abd4) on the 56-byte blob at
  0x153750, then uses NewByteArray / Get*ArrayElements family
  (0x104f8, 0x8d43c-0x8d45c, 0x93880 sites) and DeleteLocalRef (0x9a930).

So the "0x40/0xc payloads" are **Java-bridge argument strings** (method names /
signatures / class names), not key tables, and not the region data itself.

### F4. Relation to the region fill (pseudo-code, verified structure)

```
# ---- per nSign(cmd, payload...) ------------------------------------------
env   = arg0; vm = NULL
GetJavaVM(env, &vm)                                   # 0x9617c, must return JNI_OK
# VM interpreter fn (0xfb00) runs the region builder on a 0x878-byte ctx:
memset(ctx=sp+0x38, 0, 0x878)
sub_8d6f4(x0, env_or_bridge, ctx, x3)                 # 0xfb64
    ctx[0x08] = claims_byte_length                    # 0x93a00
    ctx[0x00..0x68] = environment probe results       # 13x 0xe2948 (__system_property_get,
    #                                                  syscall+read+close), CAS-guarded
    # descriptor #2 + partner int (per signing, Java-side values):
    clazz = GetObjectClass(env, signer_obj)           # 0xbe6a8
    fid   = GetFieldID(env, clazz, dec(0x153690|0x1536a0), dec(0x1540d4))   # 0xbe49c
    builder_9afa4(signer_obj, 0)                      # interleaved heap/object walk
    ctx[0x60] = GetIntField(env, signer_obj, fid)     # 0xbe604 (call #1)
    builder_9afa4(signer_obj, 0)
    ctx[0x64] = GetIntField(env, signer_obj, fid)     # 0xbe604 (call #2)
    DeleteLocalRef(env, clazz)                        # 0xbe818
    # constants #8 (ctx+0x134) / #9 (ctx+0x144): XOR-keyed table entries + SHA-1
    # (SHA-1 consts at 0x3610; cert bytes from signatures/signingInfo/
    #  getSigningCertificateHistory JNI calls) - not random, not request-hashed.
    # tiles #0 (ctx+0x94, 36 dw) / #4 (ctx+0x74, 8 dw): keyed-XOR block writes
    # (81 eor sites; repeated 16B vectors, stp q0,q0 fills) over ctx fields and
    # Java-fetched byte[] material.
# worker (0x962ac, attached thread): decrypts bridge-string blobs
#   ("getBytes" ^0x0404..04, 12-byte windows ^0x1e/^0xb5, flags 0x155a96-a98)
# VM descriptor walk (0x100094 blocks): for each of 11 descriptors
#   {u32 nbytes; ptr->ctx} : for w in words: EMIT(rev32(w))      # bl 0x146ed8
#   then LENQ read-back (0x147630/0x147734) into the stream plane -> blob
```

So: **the fill is a keyed-XOR/derived construction whose per-signing inputs are
Java-side values** (an int field read via GetIntField for #2, byte[] material
via the Signer/"getBytes" bridge for #0/#4) **plus static deobfuscated
constants** (#8/#9). The exact copy edges engine-buffer -> ctx 0x74/0x94 are
inside sub_8d6f4's flattened states and need the state-graph walker; the
mechanism classes above are each individually evidenced.

### F5. libpenti-native-keys.so

Exports 25 `Java_com_penti_core_data_security_NativeKeys_native*` functions —
plain app-secret getters (Network/Guest client id+secret, SignalSight bearer,
PersonaClick, AdjustKey, Clarity, QuinAi, Segmentify, SurveySparrow,
MasterPass x5, Xurrent x2, GoogleSignIn, SocialLogin, TikTok). Strings
(plaintext, no XOR): `jut9tib0eeps` (app_token @0x10ca), `63a93d0800ec5442
49d71f934974ad4420540e52` (SHA-1 hex, @0x10d7, next to the token),
`68c057c1...465cd5d` (SHA-256 hex), HMAC secrets, Masterpass URLs, a Teams
webhook. **No signer/region material**: `fad0f10d60f93c17...` (#9) appears in
NO shipped library — consistent with #9 being computed at runtime as SHA-1 of
the APK signing certificate (fetched via the signatures/signingInfo JNI calls
above, digested by the native SHA-1 at 0x3610).

### F6. Corrections to the previous verdict

- Slot 0x320 = **GetIntField** (idx 100), not GetStaticIntField (idx 150).
- The engine's 0x40/0xc "buffers" are obfuscated bridge strings, not payloads.
- `/dev/urandom` IS referenced in the lib (0x154f46 blob) — entropy exists in
  the keystore/session paths; the region-fill path still shows no entropy
  imports, but the blanket "no entropy in the library" claim is withdrawn.
- GetFieldID name/sig blobs for the #2 int are runtime-multi-pass-XOR; exact
  plaintext pending the state-graph walk (candidates: `secret_id`,
  `client_sdk`, sig `([B)[B`).
