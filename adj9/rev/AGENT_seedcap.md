# adj9 SDK 5.0.0: same-signing capture of `S`, raw descriptor #10, and the 192-byte blob

Date: 2026-09-24  
Scope: authorized, read-only analysis of the extracted app/native library. This document proposes a capture agent; it does not install or run anything on the device.

## 1. Executive conclusion

The single most reliable on-device method is a **Frida spawn-mode agent with synchronous native hooks**, armed before the app is resumed:

1. Open a per-thread signing record at exported JNI `nSign`, RVA `0xdb1cc`.
2. In that record, capture the exact 32-bit seed `S` in `get8random(out[8])` **onLeave** at `base + 0x13e0e4`. `S` is the little-endian low word of the eight-byte output.
3. Cross-check `S` at `ctx_init(ctx, S)` on entry at `base + 0x1437ec`, and check `ctx[0]` on return.
4. At VM descriptor iteration instruction `base + 0x100154`, use `x23 == 6` to select descriptor #10. Read its node at `x27`, decode its length word, then read exactly that many bytes from `x27+8`.
5. Return from the real Java `NativeLibHelper.a(...)` and Base64/hex-encode the exact Java `byte[]` blob. Associate that blob with the current thread's `sign_id`.

The native hooks must be correlated by a **monotonic `sign_id` plus Linux TID**, not by a global “last seed.” Java `NativeLibHelper.a` is the correct boundary at which to capture the output blob: a JNI return register is a `jbyteArray` handle, not a direct pointer to 192 readable bytes.

This is preferable to polling `/proc/<pid>/mem`, native Xposed/PLT hooking, or reconstructing #10 from Java. Once a row contains the same-row `S`, raw #10, `second`, and 192-byte blob, the existing FinEx has all currently missing per-signing inputs and can be checked for 48/48 byte equality.

## 2. Target binary identity

The three relevant files are byte-identical:

| Path | Size | MD5 | SHA-256 |
|---|---:|---|---|
| `C:\Users\Apps\Downloads\com.penti.app\extracted\arm64\lib\arm64-v8a\libsigner.so` | 1,366,632 | `dbe36c643d174f1cca240dcec1f4c585` | `55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc` |
| `C:\Users\Apps\Downloads\com.penti.app\extracted\_ref\sigs\sig500_arm64_v8a.so` | 1,366,632 | `dbe36c643d174f1cca240dcec1f4c585` | `55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc` |
| `C:\Users\Apps\Downloads\com.penti.app\extracted\_ref\sig500.aar.so` | 1,366,632 | `dbe36c643d174f1cca240dcec1f4c585` | `55353b7539894b40c6a8997f0734486cd71bddf1b0f4a0810a22ae8e15ffd2bc` |

`file` identifies the target as a stripped, dynamically linked AArch64 ELF shared object. Its Build ID is `7219539551f5c1ba78dcaf6219ffd02f1c2a4856`. The matching MD5 is the SDK 5.0.0 target requested.

Other reference SDK families found in the workspace are sig335, sig367, sig500, and sig550. Their presence does not change the target hash: all above signer files are the same sig500 binary.

## 3. RVA verification on the actual target `.so`

Capstone 5.0.7 was run directly over the target bytes at these ELF virtual addresses. The requested addresses are real code, not notes-only offsets.

### 3.1 Seed wrapper and hub call

At the hub call site:

```asm
0xdb150: ldr      x0, [sp, #0x10]
0xdb160: bl       #0x143794
```

The wrapper at `0x143794` performs the draw and immediately initializes the context:

```asm
0x143794: sub      sp, sp, #0x30
0x143798: stp      x29, x30, [sp, #0x10]
0x14379c: stp      x20, x19, [sp, #0x20]
0x1437a0: add      x29, sp, #0x10
0x1437a4: mrs      x20, tpidr_el0
0x1437a8: mov      x19, x0
0x1437b0: mov      x0, sp
0x1437b8: bl       #0x13e0e4
0x1437bc: ldr      w1, [sp]
0x1437c0: mov      x0, x19
0x1437c4: bl       #0x1437ec
```

Thus `get8random` writes eight bytes to the wrapper's stack buffer, the wrapper loads only the first 32-bit word, and `ctx_init` receives that word as `w1`.

The deeper draw path opens `/dev/urandom` and reads exactly eight bytes:

```asm
0x13e6a0: ldr      x26, [sp, #0x10]
0x13e6a4: mov      x1, x23
0x13e6a8: mov      w2, #8
0x13e6ac: mov      w0, x26
0x13e6b0: bl       #0x148c60
```

The corresponding open setup includes the Android `AT_FDCWD` value and `O_CLOEXEC`:

```asm
0x13e748: adr      x8, #0x155e30
0x13e74c: mov      w0, #0x38
0x13e750: mov      w1, #-0x64
0x13e754: mov      x2, x21
0x13e758: mov      w3, #0x80000
0x13e75c: mov      w4, wzr
0x13e760: stlrb    wzr, [x8]
0x13e764: bl       #0x148b30
```

This seed is the fresh 32-bit urandom word `S`; it is not libc `rand()` and not a clock-derived seed.

### 3.2 Context initialization

At `0x1437ec`, the incoming word is stored first and the LCG context follows:

```asm
0x143810: add      x19, x0, #8
0x143824: mov      x9, x0
0x14384c: str      w1, [x9], #0x10
0x143854: bl       #0x13e030
0x143858: sub      x0, x29, #0x18
0x14385c: mov      x1, x19
0x143864: bl       #0x143c88
```

`args[1].toUInt32()` at the hook boundary and `ctx.readU32()` after return are therefore independent cross-checks of the same `S`.

### 3.3 VM entry and descriptor loop

VM entry is at `0x100094`:

```asm
0x100094: sub      sp, sp, #0x160
0x100098: stp      x29, x30, [sp, #0x100]
0x1000d0: mov      x20, x1
0x1000d8: mov      x19, x0
0x1000fc: mov      w26, w2
```

The field loop establishes the descriptor representation:

```asm
0x100114: cmp      x23, x26
0x100118: b.eq     #0x100228
0x10014c: ldr      x27, [x8]
0x100150: add      x9, x20, x23, lsl #3
0x100154: mov      x22, xzr
0x100158: add      x28, x9, #0x20
0x10015c: ldr      w8, [x27]
0x100160: lsr      x21, x8, #2
...
0x10016c: ldr      x8, [x27, #8]
```

At instruction `0x100154`, `x27` already contains the current descriptor node, and `x23` is the iteration index. A descriptor node is:

```text
+0x00  u32 w0
+0x04  4 bytes padding
+0x08  u64 data_ptr
```

The node decodes as:

```text
len_dwords = w0 >> 2
tag        = w0 & 3
raw_length = 4 * len_dwords + tag
```

For the aligned 50-key capture in the workspace, #10 is 90 dwords / 360 bytes. The bytes begin directly with the claim serialization (`4b6c6341` in that capture, i.e. ASCII `AlcA...` in little-endian dword display). Do not reverse or rebuild these bytes for capture. The VM's later `rev` is part of execution; the raw descriptor payload itself is the little-endian memory serialization consumed by FinEx.

The corrected descriptor VA order is:

```python
VA_ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
```

Therefore #10 is descriptor iteration `x23 == 6`. Hooking VM entry's `x1` is insufficient: it is the preloaded stream/field array, while descriptor nodes arrive through the variadic state and are reached through the loop.

### 3.4 JNI nSign entry

The exported native method begins at `0xdb1cc`; its signature is effectively:

```text
nSign(JNIEnv*, jobject, Context, LinkedHashMap, byte[] H, int sdk)
```

Relevant entry instructions include:

```asm
0xdb1cc: sub      sp, sp, #0x130
0xdb1fc: mov      w22, w5
0xdb204: mov      x19, x0
```

This is the best native per-invocation boundary because it encloses seed draw, context initialization, descriptor construction, VM execution, and native output construction.

## 4. Runtime module base and the `0x54000` mapping

All RVAs above are ELF virtual-address offsets and must be added to the **load bias/module base**, not to an arbitrary stack or `/proc/maps` line.

Use this discovery order:

1. `Process.findModuleByName('libsigner.so')`.
2. Fall back to `Process.enumerateModules()`, accepting a module whose name or path contains `libsigner`.
3. Validate that `base + 0xdb1cc` and `base + 0x100094` are in executable ranges if the Frida API exposes them conveniently.
4. Emit both the base and module size once.

The executable mapping is noted in existing captures as beginning at APK file offset `0x54000`. That is an ELF/APK layout fact, not an extra constant to add to every RVA. Frida's `Module.base` is the load-bias base used for ELF RVA lookup. Do **not** add or subtract `0x54000` a second time.

Frida 17 on this device does not expose the old global `Java` object to a plain source script. The working agents import `Java` from `frida-java-bridge` and are bundled with the local `frida-compile` installation in `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\agent`.

## 5. Existing instrumentation inventory

### 5.1 Reusable Frida work

| Artifact | Existing behavior | Assessment |
|---|---|---|
| `C:\Users\Apps\Downloads\com.penti.app\adj9\device\foldhook.js` | Polls for the native module; hooks `get8random` `0x13e0e4`, wrapper `0x143794`, fold driver `0x144214`; captures seed/context/fold words; wraps `NativeLibHelper.a` for exact blob Base64; exposes RPC minting | Closest reusable base. It lacks the precise raw #10 hook and same-row `sign_id` correlation. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\device\foldhook.py` | Supports attach, `--spawn`, event collection, and RPC minting | Useful loader pattern; the spawn sequence loads before resume. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\device\entryhook.js` | Hooks VM entry/workhorse/field loop and selected register snapshots | Diagnostic only; does not dump descriptor payload. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\device\vmhook.js` | Enumerates modules and logs VM/workhorse registers | Diagnostic only. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\device\vmtrace.js` | Spawn-oriented VM/EMIT/rand/srand trace and anti-guard handling | Useful infrastructure, but its assumed 16-byte linked descriptor walk does not capture the current node payload. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\device\stealth.js` | Swallows the poisoned guard fault; blocks Java/native self-kill; hooks d3, u2, and nSign | Proven guard pattern. Historical direct-attach failure was route/timing-specific, not a general Frida limitation. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\agent\main2.js` | Frida-17 bundled guard, Java hooks, and RPC `Signer.sign(...)` mint | Proves spawn/bundled agents and on-demand signing work. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\agent\sign_src.js` | Explicitly retries `Java.perform` because ART is not ready at spawn load | Correct spawn timing pattern. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\device\harvest_spawn.py` | `spawn`, attach, create/load agent, then `resume`; retries attempts | Proven lifecycle order. |
| `C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool\*.py` and `device\appcap_fast.py` | Connect to forwarded `127.0.0.1:27042`; several use fast attach or spawn | Host-side infrastructure, not a native S/#10 capture. |

The historical contradiction is reconciled as follows: old notes saying “Frida attach is killed” describe a direct attach after the app had already latched anti-instrumentation state. Later evidence records successful Frida-17 agents, a 39,673-event live EMIT trace, and working RPC signing. For this capture, use spawn mode when available; otherwise use the documented fast-attach-before-guard path and the guard bypass. Do not depend on late attach.

### 5.2 Java/Xposed oracle and JNI

`C:\Users\Apps\Downloads\com.penti.app\adj9\module\src\com\adj9oracle\Hook.java` is a comprehensive Java Xposed oracle. It records:

- `d3.a(String)`: canonical string.
- `u2.a(LinkedHashMap, byte[])`: map size, `map_toString`, exact ordered `map_order` using U+0001/U+0002 separators, key2/HMAC length and hex, and the returned Authorization header.
- `NativeLibHelper.a(Context, LinkedHashMap, byte[], int)`: input map/context summaries, `arg3_hex`, SDK/level/environment values, nano enter/leave, and the exact returned blob hex.
- `o3.a(...)`: `adj_verification`.
- A chosen-input signer reading `/data/local/tmp/adj9_sign_in` and writing `AUTH <idx> <authorization>` to `/data/local/tmp/adj9_sign_out`.

No native `.c`/`.cpp` Xposed/JNI implementation exists under `adj9\module\src`; that source tree contains only the Java module. The only native C++ source found in the workspace is `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\aosp_rand.cpp`, which is unrelated to a signer inline hook.

### 5.3 `/proc/<pid>/mem` scripts

`C:\Users\Apps\Downloads\com.penti.app\adj9\device\ctxcap` contains `cap.sh`, `cap2.sh`, `cap3.sh`, `cap4.sh`, `loop.sh`, `offsets.sh`, `watch.sh`, `watch2.sh`, and many `ctxsnap*` helpers. They enumerate worker threads and attempt external memory sampling. Historical captures produced thousands of stack dumps but missed the desired state.

The reason is structural: the random key-state context is a short-lived stack object during a roughly millisecond-scale native call, while the captured pointers/regions are not one stable persistent array. Sampling cannot synchronize with the call. A synchronous hook at `get8random onLeave` and descriptor loop removes the race.

`C:\Users\Apps\Downloads\com.penti.app\adj9\device\caploop.sh` is a different Scudo heap capture script. It is useful for heap forensics but is not an `S`/context capture mechanism.

## 6. Capture-method comparison and recommendation

### A. Frida `get8random` onLeave — recommended

**Pros**

- Captures the provenance value before any derived state.
- The output pointer and eight-byte write are unambiguous.
- The same thread state can be joined to `ctx_init`, VM #10, and Java output.
- Existing `foldhook.js` already demonstrates this hook.
- Exact descriptor bytes can be read synchronously at `0x100154`.

**Cons / mitigations**

- Needs a Frida-17 bundle for Java capture and the proven guard/spawn route.
- A late attach can be killed. Mitigate with spawn-before-resume, the targeted poisoned-fault handler, and self-kill blocking already present in `main2.js`/`stealth.js`.
- The raw eight-byte draw and the context can be overwritten later; copy both immediately.

### B. `ctx_init(ctx, S)` — required cross-check, not primary

`args[1]` is the exact `S`, and `ctx[0]` stores it. This is an excellent assertion. However, it observes derived context initialization rather than the urandom output itself. Use it to prove that the primary draw was interpreted correctly.

### C. nSign context read after the hub wrapper

Hooking wrapper `0x143794` and reading the context after return can confirm the initialized Park–Miller/shuffle state. It is useful for validating FinEx internals, but a broad context dump alone is weaker for provenance: context layouts evolve, the object is transient, and later folds mutate it. The current concrete context is 0xd0 bytes; reading a guessed 0xe0 tail is unnecessary for the requested capture. Read at least the head immediately after `ctx_init`; read the complete 0xd0 region only as an optional validation event.

### D. Native Xposed inline/PLT hook

A native module could inline-hook `get8random` or patch the nSign call site and would avoid Frida's user-space agent. It is operationally more invasive, requires JNI/native Xposed infrastructure that the workspace does not currently contain, and introduces ARM64 relocation/stack/thread bookkeeping risks. It is not more reliable for this one capture than a known-working Frida route.

### E. `/proc/<pid>/mem` polling

This has no synchronization guarantee, is highly timing-sensitive, and historically missed. It is appropriate only as a fallback/debug technique, not the production capture method.

## 7. Same-signing correlation and oracle fields

### 7.1 Definitive key

Use:

```text
(process identity) + sign_id + tid
```

`sign_id` is a monotonic counter assigned at `nSign` entry. Native events and Java return events must carry it. The TID protects against concurrent signings and nested/reentrant calls; a per-thread stack is preferable to a single global current record.

For each completed row retain:

```text
sign_id, tid
S_u32, random8_hex
ctx_init_arg_u32, ctx_head_word0
descriptor10_w0, descriptor10_length, descriptor10_hex
nSign input H/HMAC, SDK, map_toString/map_order
blob_hex, blob_b64
Authorization when available
second
```

The Java `NativeLibHelper.a` wrapper supplies the exact blob. A base64 string preserves every byte and is easier to transport than raw binary through Frida messages.

### 7.2 Existing oracle correlation quality

- `SIGN_OUT`: strongest external batch key because it has an explicit task `idx` and the exact Authorization. Decode the Authorization blob and match its bytes to the Frida `blob_hex`/`blob_b64`. The native `sign_id` is still needed to identify which seed/#10 event produced that blob.
- `map_toString` / exact `map_order`: identifies claim content and ordering and is excellent for verifying the Java input, but equal maps can be signed repeatedly and therefore do not by themselves identify one invocation.
- `map hash`: useful as a compact claims fingerprint, not a unique invocation ID.
- `second`: necessary to FinEx, but not unique; multiple calls can occur in the same second. It is an input/correlation fallback, never the primary key.
- `gps_adid`: identifies an Adjust request/advertiser family and can be shared across repeated calls. It is weaker than exact map/blob matching.
- Native `sign_id + tid`: definitive within one process and exactly what the new agent should add.

`u2.a` runs after nSign and receives the blob. Match its blob to the most recent completed native record on the same TID, with a fallback search over the small recent-record list by exact blob bytes. Emit a single `sign_complete` row rather than asking the host to infer the join from separate global events.

The signing `second` can be recovered from the already-proven header law, but the best practice is to capture/log the canonical claim string or timestamp as well and verify that the recovered second agrees with it.

## 8. Recommended Frida source skeleton

The following is a source skeleton, not a new file. Save it as `seedcap.js` under the local `frida-compile` project when implementing. It intentionally emits separate events for diagnosis, all stamped with the same `sign_id`, and then emits one exact Java blob event.

It includes the proven guard primitives in condensed form. The poisoned address range is narrowly bounded; unrelated faults are returned to normal handling.

```js
import Java from 'frida-java-bridge';

'use strict';

const NSIGN = 0xdb1cc;
const GET8 = 0x13e0e4;
const CTX_WRAP = 0x143794;
const CTX_INIT = 0x1437ec;
const DESC_ITER = 0x100154;
const DESC10_ITER = 6;
const MAX_DESC = 1024 * 1024;

let base = null;
let nativeInstalled = false;
let nextSignId = 1;
let recent = [];

// Per-thread stacks: safer than one global current value.
const active = Object.create(null);
const javaPending = Object.create(null);
const lastCanonical = Object.create(null);

// The SDK guard intentionally faults in this private poisoned range.
Process.setExceptionHandler(function (details) {
  const s = details.address ? details.address.toString() : '0x0';
  const n = parseInt(s, 16);
  const poisoned = s.indexOf('0x600') === 0 && !isNaN(n) &&
    n >= 0x600000000000 && n <= 0x700000000000;
  if (!poisoned) return false;
  try { details.context.pc = details.context.lr; } catch (_) {}
  return true;
});

// Block native self-kill used by the guard. These hooks are process-local and
// apply only while this agent is loaded.
try {
  const pthreadExit = Module.findExportByName('libc.so', 'pthread_exit');
  const exitPtr = Module.findExportByName('libc.so', 'exit');
  const killPtr = Module.findExportByName('libc.so', 'kill');
  const tgkillPtr = Module.findExportByName('libc.so', 'tgkill');

  if (exitPtr) {
    Interceptor.replace(exitPtr, new NativeCallback(function (_code) {
      if (pthreadExit) new NativeFunction(pthreadExit, 'void', ['pointer'])(ptr(0));
    }, 'void', ['int']));
  }
  if (killPtr) {
    const origKill = new NativeFunction(killPtr, 'int', ['int', 'int']);
    Interceptor.replace(killPtr, new NativeCallback(function (pid, sig) {
      if (pid === Process.id) return 0;
      return origKill(pid, sig);
    }, 'int', ['int', 'int']));
  }
  if (tgkillPtr) {
    const origTgkill = new NativeFunction(tgkillPtr, 'int', ['int', 'int', 'int']);
    Interceptor.replace(tgkillPtr, new NativeCallback(function (tgid, tid, sig) {
      if (tgid === Process.id && (sig === 9 || sig === 6)) return 0;
      return origTgkill(tgid, tid, sig);
    }, 'int', ['int', 'int', 'int']));
  }
} catch (e) {
  send({ type: 'guard_error', error: String(e) });
}

function tid() {
  return Process.getCurrentThreadId();
}

function stackFor(t) {
  if (!active[t]) active[t] = [];
  return active[t];
}

function topFor(t) {
  const s = stackFor(t);
  return s.length ? s[s.length - 1] : null;
}

function hexBytes(ab) {
  const a = new Uint8Array(ab);
  let out = '';
  for (let i = 0; i < a.length; i++) {
    out += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
  }
  return out;
}

function hexPtr(p, n) {
  try {
    if (p === null || p.isNull()) return null;
    return hexBytes(p.readByteArray(n));
  } catch (e) {
    return 'ERR:' + String(e);
  }
}

function emit(rec, type, extra) {
  const out = Object.assign({
    type: type,
    sign_id: rec ? rec.sign_id : null,
    tid: rec ? rec.tid : tid()
  }, extra || {});
  send(out);
}

function findSigner() {
  let m = Process.findModuleByName('libsigner.so');
  if (m) return m;

  const all = Process.enumerateModules();
  for (let i = 0; i < all.length; i++) {
    const name = all[i].name || '';
    const path = all[i].path || '';
    if (name.indexOf('libsigner') !== -1 || path.indexOf('libsigner') !== -1) {
      return all[i];
    }
  }
  return null;
}

function installNative() {
  if (nativeInstalled) return true;
  const m = findSigner();
  if (!m) return false;

  base = m.base;
  nativeInstalled = true;
  send({ type: 'native_ready', base: base.toString(), size: m.size, pid: Process.id });

  // Per-signing boundary. Native arguments are JNI handles, so the Java
  // wrapper below supplies map/HMAC/sdks; this boundary owns sign_id/TID.
  Interceptor.attach(base.add(NSIGN), {
    onEnter: function () {
      const t = tid();
      const rec = {
        sign_id: nextSignId++,
        tid: t,
        t_enter_ms: Date.now(),
        seed: null,
        random8_hex: null,
        ctx_init_arg: null,
        ctx_head_word0: null,
        desc10_w0: null,
        desc10_length: null,
        desc10_hex: null,
        native_return: null
      };
      this.rec = rec;
      stackFor(t).push(rec);
    },
    onLeave: function (ret) {
      const rec = this.rec;
      if (!rec) return;
      rec.native_return = ret.toString();
      emit(rec, 'native_nsign_leave', {
        has_seed: rec.seed !== null,
        desc10_length: rec.desc10_length
      });
      // Do not pop here: Java NativeLibHelper.a attaches the exact output
      // immediately after this native return, on the same thread.
    }
  });

  // Primary S capture: get8random writes exactly 8 bytes, then returns.
  Interceptor.attach(base.add(GET8), {
    onEnter: function (args) {
      this.out = args[0];
      this.rec = topFor(tid());
    },
    onLeave: function (_ret) {
      const rec = this.rec;
      if (!rec) return;
      try {
        const random8_hex = hexBytes(this.out.readByteArray(8));
        const seed = this.out.readU32() >>> 0; // low LE word == wrapper w1
        rec.random8_hex = random8_hex;
        rec.seed = seed;
        emit(rec, 'seed', {
          seed_u32: seed,
          seed_hex: ('00000000' + seed.toString(16)).slice(-8),
          random8_hex: random8_hex
        });
      } catch (e) {
        emit(rec, 'seed_error', { error: String(e), out: this.out.toString() });
      }
    }
  });

  // Exact argument cross-check at ctx_init(ctx, seed).
  Interceptor.attach(base.add(CTX_INIT), {
    onEnter: function (args) {
      this.ctx = args[0];
      this.seedArg = args[1].toUInt32() >>> 0;
      this.rec = topFor(tid());
      if (this.rec) {
        this.rec.ctx_init_arg = this.seedArg;
        emit(this.rec, 'ctx_init_enter', {
          seed_arg_u32: this.seedArg,
          matches_get8random: this.rec.seed === this.seedArg
        });
      }
    },
    onLeave: function (_ret) {
      const rec = this.rec;
      if (!rec) return;
      try {
        const head = this.ctx.readU32() >>> 0;
        rec.ctx_head_word0 = head;
        emit(rec, 'ctx_init_leave', {
          ctx: this.ctx.toString(),
          ctx_head_word0: head,
          ctx_head_hex: hexPtr(this.ctx, 0x30),
          seed_all_equal: rec.seed === this.seedArg && head === this.seedArg
        });
      } catch (e) {
        emit(rec, 'ctx_init_error', { error: String(e) });
      }
    }
  });

  // Optional complete context immediately after the hub wrapper. The concrete
  // context is 0xd0 bytes; this is validation material, not the #10 source.
  Interceptor.attach(base.add(CTX_WRAP), {
    onEnter: function (args) {
      this.ctx = args[0];
      this.rec = topFor(tid());
    },
    onLeave: function (_ret) {
      if (!this.rec) return;
      emit(this.rec, 'ctx_wrapper_leave', {
        ctx: this.ctx.toString(),
        ctx_d0_hex: hexPtr(this.ctx, 0xd0)
      });
    }
  });

  // At 0x100154, x27 was loaded by 0x10014c and x23 is the descriptor index.
  // VA_ORDER[6] == descriptor #10. Read the real payload, not a model.
  Interceptor.attach(base.add(DESC_ITER), {
    onEnter: function () {
      const rec = topFor(tid());
      if (!rec) return;
      const i = this.context.x23.toInt32();
      if (i !== DESC10_ITER) return;

      try {
        const node = this.context.x27;
        const w0 = node.readU32() >>> 0;
        const data = node.add(8).readPointer();
        const length = 4 * (w0 >>> 2) + (w0 & 3);
        if (length < 0 || length > MAX_DESC) {
          emit(rec, 'desc10_error', {
            iter: i, node: node.toString(), w0: w0, length: length
          });
          return;
        }

        rec.desc10_w0 = w0;
        rec.desc10_length = length;
        rec.desc10_hex = hexPtr(data, length);
        emit(rec, 'desc10', {
          iter: i,
          node: node.toString(),
          data_ptr: data.toString(),
          w0: w0,
          tag: w0 & 3,
          len_dwords: w0 >>> 2,
          length: length,
          bytes_hex: rec.desc10_hex
        });
      } catch (e) {
        emit(rec, 'desc10_error', { iter: i, error: String(e) });
      }
    }
  });

  return true;
}

function bytesToHex(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) {
    s += ('0' + (b[i] & 0xff).toString(16)).slice(-2);
  }
  return s;
}

function popTop(t) {
  const s = active[t];
  if (!s || !s.length) return null;
  return s.pop();
}

function findByBlob(t, hex) {
  const s = active[t];
  if (s && s.length) {
    for (let i = s.length - 1; i >= 0; i--) {
      if (s[i].blob_hex === hex) return s[i];
    }
  }
  for (let i = recent.length - 1; i >= 0; i--) {
    if (recent[i].tid === t && recent[i].blob_hex === hex) return recent[i];
  }
  return null;
}

function installJava() {
  try {
    Java.perform(function () {
      const B64 = Java.use('android.util.Base64');
      const StringC = Java.use('java.lang.String');

      // Java self-kill guards.
      try { Java.use('java.lang.System').exit.implementation = function (_c) {}; } catch (_) {}
      try { Java.use('android.os.Process').killProcess.implementation = function (_p) {}; } catch (_) {}
      try { Java.use('java.lang.Runtime').halt.implementation = function (_c) {}; } catch (_) {}

      try {
        const d3 = Java.use('com.adjust.sdk.sig.d3');
        d3.a.overload('java.lang.String').implementation = function (s) {
          const v = this.a(s);
          const canonical = Java.cast(v, StringC).toString();
          lastCanonical[tid()] = canonical;
          send({ type: 'canonical', tid: tid(), canonical: canonical });
          return v;
        };
      } catch (e) {
        send({ type: 'java_hook_error', hook: 'd3.a', error: String(e) });
      }

      try {
        const NLH = Java.use('com.adjust.sdk.sig.NativeLibHelper');
        NLH.a.overload(
          'android.content.Context', 'java.util.LinkedHashMap', '[B', 'int'
        ).implementation = function (ctx, map, hmac, sdk) {
          const t = tid();
          javaPending[t] = {
            map_toString: map === null ? null : map.toString(),
            hmac_b64: hmac === null ? null : B64.encodeToString(hmac, 2),
            sdk: sdk,
            canonical: lastCanonical[t] || null
          };

          const result = this.a(ctx, map, hmac, sdk);
          const rec = topFor(t); // same TID as native nSign
          const pending = javaPending[t] || {};
          delete javaPending[t];

          if (rec) {
            Object.assign(rec, pending);
            rec.blob_len = result === null ? -1 : result.length;
            rec.blob_b64 = result === null ? null : B64.encodeToString(result, 2);
            rec.blob_hex = result === null ? null : bytesToHex(result);
            emit(rec, 'nsign_blob', {
              sdk: sdk,
              map_toString: rec.map_toString,
              canonical: rec.canonical,
              hmac_b64: rec.hmac_b64,
              blob_len: rec.blob_len,
              blob_b64: rec.blob_b64,
              blob_hex: rec.blob_hex
            });
            recent.push(rec);
            while (recent.length > 256) recent.shift();
          } else {
            send({ type: 'nsign_blob_unmatched', tid: t,
                   blob_len: result === null ? -1 : result.length });
          }

          popTop(t);
          return result;
        };
      } catch (e) {
        send({ type: 'java_hook_error', hook: 'NativeLibHelper.a', error: String(e) });
      }

      // u2 receives the already-produced blob and returns the Authorization.
      // Match by exact blob, preferring same TID.
      try {
        const u2 = Java.use('com.adjust.sdk.sig.u2');
        u2.a.overload('java.util.LinkedHashMap', '[B').implementation = function (map, blob) {
          const blobHex = blob === null ? null : bytesToHex(blob);
          const result = this.a(map, blob);
          const t = tid();
          const rec = findByBlob(t, blobHex);
          if (rec) {
            rec.authorization = result === null ? null : String(result);
            rec.u2_map_toString = map === null ? null : map.toString();
            emit(rec, 'sign_complete', {
              complete: rec.seed !== null && rec.desc10_hex !== null &&
                        rec.blob_hex !== null,
              authorization: rec.authorization,
              u2_map_toString: rec.u2_map_toString,
              seed_u32: rec.seed,
              desc10_length: rec.desc10_length,
              desc10_hex: rec.desc10_hex,
              blob_hex: rec.blob_hex
            });
          } else {
            send({ type: 'authorization_unmatched', tid: t, blob_hex: blobHex,
                   authorization: result === null ? null : String(result) });
          }
          return result;
        };
      } catch (e) {
        send({ type: 'java_hook_error', hook: 'u2.a', error: String(e) });
      }

      send({ type: 'java_ready' });
    });
  } catch (_) {
    // On spawn ART is not ready at load time. Retry Java.perform itself.
    setTimeout(installJava, 150);
  }
}

function pollNative() {
  if (!installNative()) setTimeout(pollNative, 150);
}

setTimeout(pollNative, 100);
setTimeout(installJava, 150);

rpc.exports = {
  // Host-side collection is normally the `send` stream. This also provides a
  // small recent-row fallback for a fast driver.
  recent: function () { return recent; },
  base: function () { return base ? base.toString() : null; },
  installed: function () { return nativeInstalled; }
};
```

### 8.1 Implementation cautions

- The report code deliberately separates events. The host collector should group by `sign_id` and accept the row only when `seed_u32`, `desc10_hex`, and the Java `blob_hex` are present and `seed_all_equal` is true.
- `descriptor10_length` is derived from `w0`, then used for the read. Do not hard-code 360 for all claims maps; use the live `w0` and assert the observed row is plausible.
- The VM iteration callback fires repeatedly. Only `x23 == 6` is accepted. A duplicate #10 event should have the same bytes; keep the first as canonical and report a mismatch if a later duplicate differs within the same signing.
- The current per-thread stack is intentionally simple. If the application can re-enter nSign on a thread, preserve the same push/pop discipline in the Java wrapper; do not replace it with a global `lastSeed`.
- If only the native portion is loaded before ART, the native record remains valid. The Java blob can be joined later by process/TID and exact blob bytes. The recommended full agent retries Java setup, as in `sign_src.js`.

## 9. Proven loading sequence

The working infrastructure is:

- `C:\Users\Apps\Downloads\com.penti.app\adj9\device\fsloop.sh` keeps `/data/local/tmp/fs17 -l 127.0.0.1:27042` alive.
- `C:\Users\Apps\Downloads\com.penti.app\adj9\device\fs_up.py` starts the server as root with a parked adb shell and verifies `frida.get_device_manager().add_remote_device('127.0.0.1:27042')`.
- `C:\Users\Apps\Downloads\com.penti.app\adj9\device\harvest_spawn.py` demonstrates the critical order: `spawn`, `attach`, create/load the agent, then `resume`.
- `C:\Users\Apps\Downloads\com.penti.app\adj9\device\foldhook.py --spawn` demonstrates the same ordering for a native/Java signing agent.
- For Java under Frida 17, build the source from a directory containing `frida-java-bridge` and the local `frida-compile`; the package manifest is `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\agent\package.json`.

Historical records contain two viable routes:

- **Preferred:** spawn and load before native initialization; this gets inside before the guard latches. Some ROM/Frida combinations refused `dev.spawn`, so the workspace retains fast-attach-first launch scripts.
- **Fallback:** launch and attach within roughly the first 2.5 seconds, before the guard engages, then load the guard-aware agent. `device\appcap_fast.py` documents this approach.

The earlier statement that direct attach was killed should not be generalized to all Frida. Later successful records include a 39,673-event spawn-mode EMIT trace, real app signing under the hooks, and RPC `Signer.sign(...)` minting. The safe conclusion is: **use spawn-before-resume where possible, or fast attach; do not use a late unguarded attach.**

## 10. Acceptance test for byte-exact FinEx

For each accepted row:

1. Confirm `S == ctx_init_arg_u32 == ctx_head_word0`.
2. Confirm #10 iteration is 6 and descriptor `w0` decodes to the captured `length`; preserve `desc10_hex` exactly as read.
3. Confirm Java blob length is 192 and retain exact `blob_hex`/`blob_b64`.
4. Recover/record the signing `second` and verify the proven header law.
5. Run `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\fin_vm2.py` / the existing FinEx harness with the same raw #10 and seed.
6. Require output window equality `48/48` dwords (192 bytes), not merely a similar header or a matching map.

A same-row native/Java join is the decisive artifact. A seed from one call, #10 from another call, and a blob matched only by second cannot establish offline byte reproduction.
