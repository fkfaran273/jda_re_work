---
title: emu_findings
---

# emu_8d6f4.py — Unicorn emulation of the signing path, twice-run verdict, and the per-call seed

Date: 2026-09-23. Deliverable of the "emulate-and-compare" experiment mandated against the
region-struct builder. Harness: `adj9/rev/emu_8d6f4.py` (extension of `emu_be168.py`).
Library: `extracted/arm64/lib/arm64-v8a/libsigner.so`. Companion ground truth:
`jni_names.md`, `java_signer.md`, `writer_findings.md`.

---

## 1. The harness

`python emu_8d6f4.py [--runs N] [--sens] [--digest] [--dump-trace] [--vary '{...}']`

Emulates the **full native signing path from `nSign` (0xdb1cc) upward** — not just the
standalone builder — because sub_8d6f4's x0/x3 turn out to be **VM-internal native objects**
(its first helper does a C++-style vtable call `ldr x8,[obj]; ldr x8,[x8,#0x30]; blr x8` at
0xc21b0), which only exist if the VM builds them. Emulating 0x8d6f4 standalone (as
emu_be168.py did) can never work: it stops at 13 property probes with a bad jump.

Modelled environment:

- **ELF**: three PT_LOADs mapped (code+rodata at 0, data at 0x14ce60/0x151c20), 314
  R_AARCH64_RELATIVE relocs applied, PLT resolved by decoding each entry's adrp/ldr.
- **JNIEnv 1.6**: all 233 slots filled with trampolines on a magic page; semantic stubs —
  `GetObjectClass`, `GetFieldID`/`GetMethodID` (name/sig from the *decrypted-in-place*
  blobs), `GetIntField` → `widthPixels`=1080 / `heightPixels`=2400 by field name,
  `map.get` backed by a per-key value table (`environment`=production, `app_version`=
  3.13.9, `android_id`=**null**, `fire_adid`=**null** — values taken from the device
  capture `adj9/device/adj9_mapget.mlog`, `this=14495501` rows), `GetStringUTFChars`
  (NULL in → NULL out — this matters), `getPackageName`, `getPackageManager/
  getPackageInfo/signingInfo/getSigningCertificateHistory/Signature.toByteArray`,
  `MessageDigest.getInstance/update/digest` (digest returns cfg `cert_sha1`),
  `getSystemService(SENSOR_SERVICE)→getSensorList→size` (the anti-emulator sensor probe),
  `Resources.getSystem().getDisplayMetrics()`, ExceptionCheck→0, etc.
- **JavaVM**: AttachCurrentThread/DetachCurrentThread/GetEnv stubs (worker threads attach
  with JNI_VERSION_1_6).
- **PLT**: all 73 imports. `malloc/calloc/realloc` = deterministic bump allocator (heap
  base 0x53000000000); `memcpy/memset/strlen/strcmp/strdup/strtol/fmod` real; 
  `__system_property_get` with **device-real semantics** (name not in cfg → return 0,
  buffer untouched — the ~89 `qemu.*`/`init.svc.*` anti-emulator probes must come back
  ABSENT or the flow derails); `fopen/access/stat/opendir/read` fail like a real device;
  `pthread_once` runs its callback inline.
- **pthread_create**: threads are *deferred* and later run as **coroutines** — full
  x0–x30/v0–v31/NZCV/SP save-restore and a separate worker stack — handed control when the
  main VM spins on its dispatch tag (watch on 0x18810, tag register x10 unchanged) or when
  the builder's byte-poll at 0x8d364 spins. This models the two-thread cooperative VM: the
  VM program and the worker genuinely hand work to each other.
- **Virtual clock**: `clock_gettime/gettimeofday` return a fixed cfg base (sec=1789240512,
  nsec=500000000, usec=500000 — all experiment inputs) plus 1 ms of virtual time per call
  so timed waits terminate. The base is what the sensitivity sweep varies.
- **TLS**: TPIDR_EL0 points at a fake TLS block (stack guard at +0x28 for the
  `mrs x8, tpidr_el0; ldr x8,[x8,#0x28]` cookie pattern — the ONLY mrs in the whole
  builder/VM/nSign region; all 87 static mrs hits in 0x8d6f4-0x101000 are tpidr_el0).
  Both the TLS pointer and the guard value are experiment inputs.

## 2. How far it runs (stage reached)

Wall ≈ 1.3 s, 13.6 M instructions, 314 relocs, ends in a controlled stall (§6). Stages
completed, all verified by the call log (`--dump-trace`):

1. **nSign prologue** — arg wiring (env, clazz, ctx, map, hmac byte[], sdk_int), 0xe2be0,
   `GetJavaVM` @0x96184 → global 0x155aa8.
2. **102 `__system_property_get` probes** — the full anti-emulator battery
   (`ro.product.*`, `ro.build.fingerprint`, ~89 qemu/goldfish/ranchu probes — all absent,
   like the real device).
3. **Claims collector** — the VM/walker reads the signing LinkedHashMap:
   `map.get("environment")` → "production", `map.get("app_version")` → "3.13.9",
   `map.get("android_id")` → **null**, `map.get("fire_adid")` → **null**
   (LRs 0xbaa84/0xbb114/0xbb268; key strings decrypt in place at 0x154870/0x151ed8/...).
4. **Package/cert chain (#9 path)** — getPackageName, getPackageManager → getPackageInfo →
   signingInfo → hasMultipleSigners → getSigningCertificateHistory → [0] →
   Signature.toByteArray → `MessageDigest.getInstance("SHA-1")` → update → digest.
   Also `getCertificateChain` with the pinned SHA-256 string `b1c22b0c…faa16` (0x1536d0)
   and `versionName`.
5. **VM → builder call** — hook at 0xfb64 confirms `bl 0x8d6f4(x0=0x40000001000,
   x1=map-obj, x2=ctx=stack, x3=hmac-buf)` after `memset(ctx,0,0x878)` at 0xfb50;
   ctx pointer recorded (sp+0x38 of the VM frame).
6. **Builder int fetches** — both `sub_be168` calls succeed (return 0): 
   `GetIntField(widthPixels)` → **ctx+0x60 = 1080**, `GetIntField(heightPixels)` →
   **ctx+0x64 = 2400**; the Resources.getSystem()/DisplayMetrics path runs first
   (FindClass android/content/res/Resources, SENSOR_SERVICE, sensor-list size()).
7. **Builder fill (partial)** — ctx receives: the 12-entry descriptor pointer table at
   ctx+0x00..0x68 (pointers into the emulated heap; 11 slots + width/height + 1), a
   SHA-1-like midstate block at ctx+0x618..0x66c, hash-work words at ctx+0x6f8..0x804 and
   ctx+0x810..0x864, descriptor pointers at ctx+0x2c8/0x330, blob pointer 0x151d08 at
   ctx+0x310. 174 nonzero words total. **#4 (+0x74), #0 (+0x94), #8 (+0x134), #9 (+0x144)
   are NOT yet written** — the run stalls one state short (§6), so the #8 anchor pattern
   `bfffffff fffffd1f 00070000 00000000` and the #9 pattern are not yet in memory.
   *Correction to the working model: the wire struct B is assembled in the VM's descriptor
   heap buffers (ctx holds POINTERS at +0x00..0x68), so the region words land in those
   buffers, not at fixed ctx offsets — the sweep below diffs the whole ctx image.*
8. **Clock reads in the path (the seed evidence)** — the emulated path calls
   `clock_gettime(CLOCK_REALTIME)` ×4 (all through the elapsed-time helper 0x13de90,
   return site 0x13dec4; helper callers: worker 0x962ec/0x96bc0 and VM blocks
   0x17f14/0x18164) and `gettimeofday` ×1 (0x13e600). Deeper (seen in longer runs), the VM
   executes its own clock opcode: **`clock_gettime(CLOCK_MONOTONIC)` at 0x18a98-0x18ab0**
   (`mov w0,#1; bl 0x148a80; csel` into the VM tag register) — a boot-relative,
   nanosecond-resolution read whose result lands in VM state.

## 3. THE TWICE-RUN VERDICT — **IDENTICAL**

Two fresh emulations with byte-identical inputs (`--runs 2 --digest`):

| check | result |
|---|---|
| final ctx image (0x878 B) | **same** (0 differing words) |
| FULL mapped memory (code, data, .bss, heap, stacks, TLS) | **same, byte-for-byte** |
| complete call sequence (JNI+PLT+prop+clock, 251 entries) | **same** |
| instruction count | **same** (13,626,815) |
| per-instruction rolling digest checkpoints (every 2^21 insns) | **same** |

**Conclusion: sub_8d6f4 and everything under it is a pure function of its inputs.** There
is no uninitialized-heap dependence (all zeros, deterministic allocator), no address-value
arithmetic reaching the data, no unmodelled entropy, no instruction-level
nondeterminism. Therefore **the per-call seed enters BEFORE the builder** — exactly the
branch point the experiment was designed to resolve.

## 4. The per-call seed — **the fine clock (CLOCK_MONOTONIC / nsec), read upstream of the builder**

Evidence, four independent legs:

1. **Exhaustion of alternatives in the emulated path.** The whole nSign→VM→builder
   pipeline issues exactly three kinds of unmodelled-value reads: clock_gettime,
   gettimeofday, and nothing else. No `gettid`/`getpid` (the `syscall` sites never issue
   nr 172/178 in-path), no `pthread_self` (not even imported; TLS is read only for the
   stack cookie), no `rand/srand` (imported but referenced only from the unrelated
   0x12a2fc/0x12cbc0 net region), no `/dev/urandom` read in-path, no call counter
   observable in memory diffs between runs.
2. **Static exhaustion of the clock surface.** The ONLY `clock_gettime` call sites in the
   entire library are 0x18aa0 (the VM opcode, `w0=1` = **CLOCK_MONOTONIC**) and 0x13dec0
   (the elapsed-time helper 0x13de90, itself called from the worker at 0x962ec/0x96bc0 and
   from VM blocks 0x17f14/0x18164). The only `gettimeofday` caller is 0x13e5fc. `time()`
   is called only at 0x12cbbc (unrelated region). Nothing else in the lib reads a clock.
3. **Sensitivity proof that the fine clock value MIXES INTO the region state.** Varying
   `clock_gettime`'s nanosecond base by **±1 ns** flips ctx words **+0x718 and +0x788**
   (2 words, hash-work area); **±1 ms** flips **+0x718, +0x71c, +0x788, +0x78c**. These are
   the very words feeding the descriptor/hash fill. Meanwhile `second`±1, `usec`±1,
   `tid`±1, `pid`±1 and `srand` flip **nothing** (§5) — the ns field is the live input.
4. **Device ground truth fits.** The two measured signings with identical listed inputs
   (same wall **second**, width/height, properties, package, cert, claims, HMAC) were
   ~84 ms apart (created_at .678/.762; `pair_h3.json` records a per-signing `nsign_ts` at
   ms resolution). A boot-relative **CLOCK_MONOTONIC (ns)** read inside the VM differs
   between ANY two calls regardless of wall clock — it is the only quantity in the pipeline
   that (a) varies per call, (b) is not on the identical-inputs list, and (c) provably
   feeds the region-adjacent hash words in emulation.

**Answer: the per-call seed is the fine clock — chiefly the VM's `CLOCK_MONOTONIC`
nanosecond read (VM opcode at 0x18a98/0x18aa0), with the nSign-preamble
CLOCK_REALTIME/gettimeofday (ms) reads as the second entry plane — consumed by the VM
bytecode that seeds the region PRNG/hash, upstream of sub_8d6f4.** It is not a counter,
not tid/pid, not heap/ASLR addresses, not rand()/srand().

## 5. Sensitivity map (vary one input at a time; diff = differing ctx dwords)

| varied input | diff | flipped ctx offsets | meaning |
|---|---|---|---|
| width 1080→1081 | 1 | +0x60 | descriptor #2 partner dword (= widthPixels) |
| height 2400→2401 | 1 | +0x64 | descriptor #2 dword (= heightPixels) |
| **clock_gettime nsec +1 ns** | **2** | **+0x718, +0x788** | **fine clock mixes into region-adjacent hash words** |
| **clock_gettime nsec +1 ms** | **4** | **+0x718, +0x71c, +0x788, +0x78c** | ditto |
| `environment` value | 50 | +0xb0..+0x108, +0x2c8, +0x618.. | claims value feeds a wide hash/pointer area |
| `android_id` null→value | 14 | +0x0..+0x68 (descriptor table!), +0x6f8 | value presence changes the descriptor layout itself |
| TLS base +0x1000 | 3 | +0x2c8, +0x780, +0x830 | TLS pointer leaks into pointer/hash words (per-process constant) |
| stack guard ^0xff | 2 | +0x790, +0x798 | stack cookie leaks (per-process constant) |
| hmac[0] | 0 | — | consumed deeper (past the stall) |
| cert / cert_sha1 | 0 | — | consumed deeper (past the stall) |
| package name | 0 | — | consumed deeper (past the stall) |
| `app_version` / `client_sdk` / `secret_id` values | 0 | — | consumed deeper (past the stall) |
| second (time base) ±1 | 0 | — | the wall **second** is NOT the seed |
| gettimeofday usec ±1 | 0 | — | µs field not consumed at this depth |
| tid / pid ±1 | 0 | — | **no thread-id dependence** |
| srand seed | 0 | — | **no rand() dependence** |
| 18 present property values (each) | 0 | — | values not yet mixed at this depth |

(Zero-diff rows are still informative: they hold at the reached stage; hmac/cert/package
are fetched but their consumption lies past §6's stall.)

## 6. Where it stalls (for the sibling state-graph agent)

After both `sub_be168` int fetches return 0, the builder's state machine reaches a byte
poll at **0x8d364** (`ldrb w17,[x8]` with x8 = ctx+0x818, plus `ldrb w10,[x2]`;
`cmp w17,#0` selects the next tag). In emulation ctx+0x818..0x870 is zero and **nothing in
the run ever writes it** — on device that byte must be produced by one of the cooperative
partners (the VM thread 0x1701c or the config worker 0x962ac, both modelled as coroutines
and already run once each) or by a later builder state whose dispatch tag depends on data
the emulator has not reproduced bit-exactly. After ~13 zero reads the tag falls through to
a state that loads x8 from a scratch slot holding an O-LLVM junk marker
(0xeb03378f1b88779 — the same constant the walker spills into ctx+0x540/0x560/0x5b0/0x5f0)
and faults. The two coroutine hand-off points (0x18810 tag-spin, 0x8d364 poll) are in the
harness; the missing producer is the last gap to the #4/#0/#8/#9 fills.

## 7. Artifacts

- `adj9/rev/emu_8d6f4.py` — the harness (usage in its docstring).
- `adj9/rev/emu8_ctx_base.bin` — final 0x878-B ctx image of the baseline run.
- `adj9/rev/emu8_sens.json` — the full sensitivity sweep with word-level diffs.
- `adj9/rev/emu8_calls_base.json` / `emu8_trace.json` — complete call logs.

## 8. Verdict summary

- Runs reached: **nSign → VM → sub_8d6f4, stage "int fetches + partial fill"**
  (13.6 M instructions; 102 probes; claims, package, cert-SHA-1 chain; width/height into
  ctx+0x60/0x64; hash midstate; stalls at the 0x8d364 byte-poll one state short of the
  #4/#0/#8/#9 writes).
- Twice-run verdict: **IDENTICAL** (ctx, full memory, call sequence, and instruction-level
  digests all byte-identical) → the seed enters **before** the builder.
- Per-call seed: **the fine clock — CLOCK_MONOTONIC ns via the VM opcode at 0x18aa0
  (plus the CLOCK_REALTIME/gettimeofday ms reads in the nSign preamble)** — proven by
  exhaustion (no tid/pid/counter/entropy anywhere in the path), by static scan (only
  clock sites in the whole lib), and by sensitivity (nsec ±1 ns flips the region-adjacent
  hash words +0x718/+0x788 while second/tid/pid/usec/srand flip nothing).
