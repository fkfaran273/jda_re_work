# Wall A — slice 4: the fold's entropy is a 32-bit seed (2026-09-10, late)

Continues `WALL_A_SLICE_3.md`. Slice 3 established *what* the seal is (a
self-keyed XOR-feedback snowball). This slice establishes **where its
randomness comes from — and it is only 32 bits.**

---

## 1. HEADLINE: one `openat("/dev/urandom")`, one `read(..., 8)`, one 32-bit seed

The whole library has **exactly two `read` call sites** (PLT `read` = `0x148c60`,
derived from `.rela.plt` entry 40 = `dynsym` `read`; PLT base `0x1489d0`,
entry k at `base + 16*(k+1)`):

| site | call | frame |
|---|---|---|
| `0x13e6b0` | `read(fd, buf, 8)` | inside fn `0x13e0e4` (frame `0xa0`) |
| `0xe3c44` | `read(fd, buf, 0x800)` | inside the big seal fn (`0xe3144`, frame `0x1900`) |

The first one is the seed. Full chain, all addresses verified in
`extracted/arm64/lib/arm64-v8a/libsigner.so`:

### 1.1 The entropy helper — `0x13e0e4` (frame `0xa0`)

```
0x13e1bc  mov  x23, x0                 ; x23 = caller's out-buffer (8 bytes)
0x13e1f8  adr  x21, #0x155138          ; x21 = "/dev/urandom"   <- the ONLY ref
...
0x13e744  adr  x8, #0x155e30           ; one-shot flag
0x13e74c  mov  w0, #0x38               ; syscall 56 = openat
0x13e750  mov  w1, #-0x64              ; AT_FDCWD
0x13e754  mov  x2, x21                 ; pathname = "/dev/urandom"
0x13e758  mov  w3, #0x80000            ; O_CLOEXEC
0x13e75c  mov  w4, wzr                 ; mode = 0
0x13e760  stlrb wzr, [x8]
0x13e764  bl   0x148b30                ; syscall -> openat(AT_FDCWD,"/dev/urandom",O_CLOEXEC)
0x13e7dc  str  x0, [sp, #0x10]         ; save fd
...
0x13e6a0  ldr  x26, [sp, #0x10]        ; fd
0x13e6a4  mov  x1, x23                 ; buf
0x13e6a8  mov  w2, #8                  ; <-- COUNT = 8
0x13e6ac  mov  w0, w26
0x13e6b0  bl   0x148c60                ; read(fd, buf, 8)
0x13e6d0  bl   0x148c70                ; close(fd)
0x13e6e8  cmp  x23, #8                 ; require exactly 8
```

⇒ `get8random(uint8_t out[8])`: openat + read 8 + close, fresh fd every call.

### 1.2 Its only caller — the ctx wrapper `0x143794`

`callers_of(0x13e0e4)` returns **exactly one site: `0x1437b8`**.

```
0x143794  sub  sp, sp, #0x30            ; wrapper entry
0x1437b0  mov  x0, sp                  ; scratch buffer on stack
0x1437b8  bl   0x13e0e4                ; 8 random bytes -> [sp]
0x1437bc  ldr  w1, [sp]                ; <-- ONLY THE LOW 32 BITS ARE USED
0x1437c0  mov  x0, x19                 ; ctx
0x1437c4  bl   0x1437ec                ; ctx_init(ctx, seed=w1)
```

### 1.3 `ctx_init` — `0x1437ec`

```
0x143810  add  x19, x0, #8             ; x19 = ctx+8
0x14384c  str  w1, [x9], #0x10         ; ctx[0] = seed (32-bit), x9 = ctx+0x10
0x143854  bl   0x13e030                ; LCG init(ctx+8)
0x143858  sub  x0, x29, #0x18          ; scratch16
0x14385c  mov  x1, x19                 ; ctx+8
0x143864  bl   0x143c88                ; shuffle16(scratch16, ctx+8)
```

### 1.4 The LCG init `0x13e030` and the generator `0x13dfd0`

`0x13e030` is a flattened machine whose only real work is:

```
0x13e07c  mov  w11, w1                 ; seed
0x13e0c0  str  x11, [x0]               ; *(u64*)(ctx+8) = seed
```

`0x13dfd0` is **clean, un-flattened** Park–Miller minimal standard
(`x = 16807·x mod (2³¹−1)`, Schrage form):

```
0x13dfd4  ldr  x10, [x0]               ; state
0x13dfd8  mov  w9, #0xd924 ; movk #0x75b  -> 0x075bd924   (default when state==0)
0x13dff0  csel x9, x9, x10, eq
0x13dff8  mov  w10, #0xf31d ; movk #1    -> 0x1f31d = 127773   (q)
0x13e000  udiv x10, x9, x10            ; h = x / q
0x13e004  madd x9, x10, x11(-0xf31d), x9     ; x -= h*q
0x13e008  mov  w11, #0x41a7            ; a = 16807
0x13e00c  mul  x10, x10, x12(-0xb14)   ; -h*r   (r = 2836)
0x13e010  madd x9, x9, x11, x10        ; x = a*(x mod q) - h*r
0x13e014  mov  w10, #0x7fffffff
0x13e01c  cmp  x9, #0 ; csel x9, x10+x9, x9, lt
0x13e024  and  w0, w9, #0x7fffffff     ; return 31-bit
0x13e028  str  x9, [x8]                ; store state
```

`0x143c88` = Fisher–Yates over a 16-byte buffer: zero it, then 16 rounds of
`r = lcg(); j = r % (i+1); swap(buf[i], buf[j])` (`0x143d2c` bl 0x13dfd0,
`0x143d30` udiv, `0x143d44` msub, `0x143d4c..0x143d54` the swap).

### 1.5 Where it is called from — nSign's own hub

`callers_of(0x143794)` returns **exactly one site: `0xdb160`**, inside the
nSign hub function (`0xda99c`, frame `0x210`, called from
`Java_..._nSign` = `0xdb1cc`):

```
0xdb150  ldr  x0, [sp, #0x10]          ; ctx pointer
0xdb160  bl   0x143794                 ; seed it from /dev/urandom
```

## 2. Consequence — this changes the cost of the offline decoder

The fold's 16 source words (`ctx+0x10..0x30`) are generated **only** from
Park–Miller output, and Park–Miller is seeded with **one 32-bit value**. So:

* The 176-byte body is a deterministic function of
  **(32-bit seed, claims, env-verdicts)** — nothing else is random.
* Park–Miller `mod 2³¹−1` has state space ≤ 2³¹−1, so the effective search is
  **≤ 2³¹ seeds**, not 2¹²⁸-class. A forward-simulating brute force over 2³²
  candidates is a *compute* problem, not a cryptanalytic one — minutes to hours
  in C, and trivially parallel.
* This also finally explains the per-call re-randomisation *and* the earlier
  negative results: the entropy is 4 bytes, so "no constant positions / no
  repeated block" is expected, and no key exists to find.

**Correction to slice 3's framing:** slice 3 said the ctx "carries per-call
entropy". True, but it is a single 32-bit seed, not a nonce pool. The 2048-byte
read in §3 below is a *different*, still-unresolved consumer.

## 3. The other read — 2048 bytes (unresolved path)

```
0xe3c34  ldr  x27, [sp, #0x60]         ; fd
0xe3c38  add  x1, sp, #0xe0            ; buf
0xe3c3c  mov  w2, #0x800               ; 2048 bytes
0xe3c40  mov  w0, w27
0xe3c44  bl   0x148c60                 ; read
0xe3c48  mov  x24, x0                  ; bytes read
0xe3c50  bl   0x148c70                 ; close
```

**Frame correction (important).** `0xe3c44` does **not** belong to a function
starting at `0xe3c0`. There is no `ret` between `0xe3144` and `0xe4a74`, and
`0xe3144` is a real prologue:

```
0xe3144  sub  sp, sp, #1, lsl #12      ; sp -= 0x1000
0xe3148  sub  sp, sp, #0x900           ; sp -= 0x900   -> frame 0x1900
```

So the enclosing function is **`0xe3144`, frame `0x1900`** (big enough for the
2048-byte buffer at `sp+0xe0`), and `0xe3c0`'s `sub sp,sp,#0x130` is a nested
allocation, **not** a function prologue. `WALL_A_SLICE_3.md` §1 should be read
with that correction. The openat feeding this read is at `0xe1f88`
(`openat(AT_FDCWD, x22, 0, 0)`), path register `x22` not yet resolved —
candidates are the env-detection files (`/proc/cpuinfo` is ~1–2 KB).

## 4. The ctx layout is now exact (from the assembler itself)

`0x11d14` builds it. Read straight off the code:

```
0x11d20  mov  x8, sp
0x11d24  sub  x9, x8, #0xc0 ; sp = x9      ; ctx = sp0 - 0xc0
0x11d30  sub  x26, sp, #0xa0 ; sp = x26    ; buffer A (0xa0)
0x11d3c  sub  x27, x24, #0x10 ; sp = x27   ; buffer B (0x10)
0x11d4c  sub  x20, x21, #0x10 ; sp = x20   ; buffer C (0x10)
0x11d64  mov  x0, x26 ; w1 = 0 ; w2 = 0x96 ; memset(bufferA, 0, 0x96)
0x11d70  stp  x10, x9, [x8, #-0xc0]        ; ctx[0x00] = va 0x151d18, ctx[0x08] = 0x151d28
0x11d84  stp  x10, x9, [x8, #-0xb0]        ; ctx[0x10] = 0x151d30, ctx[0x18] = 0x151d40
0x11d98  stp  x10, x9, [x8, #-0xa0]        ; ctx[0x20] = 0x151d50, ctx[0x28] = 0x151d58
0x11dac  stp  x10, x9, [x8, #-0x90]        ; ctx[0x30] = 0x151d68, ctx[0x38] = 0x151d70
0x11dc0  stp  x10, x9, [x8, #-0x80]        ; ctx[0x40] = 0x151d80, ctx[0x48] = 0x151d8c
0x11dd4  stp  x10, x9, [x8, #-0x70]        ; ctx[0x50] = 0x151d98, ctx[0x58] = 0x151da0
0x11de8  stp  x10, x9, [x8, #-0x60]        ; ctx[0x60] = 0x151da8, ctx[0x68] = 0x151db8
0x11dfc  stp  x10, x9, [x8, #-0x50]        ; ctx[0x70] = 0x151dc8, ctx[0x78] = 0x151dd8
   ... (continues; 26 pointers total = 0xD0 bytes)
```

**So the ctx *is* the 26-pointer marker array**, laid out `ctx+0x00 .. ctx+0xCF`.
Two consequences:

1. The device-side search signature is confirmed and precise: 26 consecutive
   ascending 8-byte pointers to `base+0x151d18 … base+0x151e50`. That is what
   the capture scripts look for.
2. It re-reads slice 3 §2.2: `derive16`'s "144-byte region `ctx+0x30..0xc0`
   vs 8-word table `ctx+0xc0..0xd0`" is a comparison **inside the pointer
   array** — words 0x18..0x47 against words 0x60..0x67. The "key" derived there
   is therefore a function of the marker pointers, i.e. **partly of the lib's
   ASLR base**, not of any secret.

## 5. The complete live string table (from the `.data` dump)

`device/rwdata2.bin` (live `/proc/pid/mem`, lib base `0x7b82a02000`,
dump va base `0x14C000`) decodes the whole table in place. It is the record's
**field vocabulary**:

```
claims / header        0x151c20 client_sdk   0x151c50 com.adjust.sdk.sig.Signer::sign
                       0x151c70 AdjustSigner 0x151c80 ActivityPackageSender
                       0x151c98 android      0x151ca0 secret_id
                       0x151cb0 1500000      0x151cb8 headers_id
                       0x151cc8 native_version 0x151cd8 5.0.0
                       0x151ce0 adj_signing_id 0x151cf0 algorithm  0x151cfc adj9
env markers (26)       0x151d18 Emulator 0x151d28 AMIDuOS 0x151d30 AndroidStudio
                       0x151d40 Android Studio 0x151d50 ARChon 0x151d58 Bluestacks
                       0x151d68 Droid4X 0x151d70 Genymotion 0x151d80 KoPlaMEmu
                       0x151d8c Remix 0x151d98 Xamarin 0x151da0 YouWave
                       0x151da8 LeapDroid 0x151db8 KoPlayer 0x151dc8 Robotium
                       0x151dd8 Bot-Bot 0x151de0 SeeTest 0x151de8 MonkeyRunner
                       0x151df8 Ranorex 0x151e00 Appium 0x151e08 Automator
                       0x151e18 google_sdk 0x151e30 Android SDK built for x86
                       0x151e50 redfinger
env inputs             /proc/net/tcp, /proc/self/maps, /proc/self/fd, /proc/self/cmdline,
                       ro.build.version.release, ro.build.version.sdk, os_version,
                       api_level, app_version, android_id, fire_adid, publicSourceDir,
                       SHA1, /dev/socket/qemud, /dev/qemu_pipe, /sys/devices/virtual/dmi/id/*,
                       VirtualBox, innotek, goldfish, qemu, ranchu, vbox86, microvirt,
                       fstab.andy/nox/vbox86, init.nox.rc, /system/bin/memud, ... (~300 entries)
```

This is the concrete "data and data formats" the server reads inside the
envelope: identity claims + the emulator/instrumentation verdict vocabulary.

## 6. Device capture — attempts and current status

Goal: dump the live ctx (the 26-pointer array) from a thread's stack during an
nSign window.

**What was done** (scripts in `device/ctxcap/`):

* Enumerated the Adjust worker threads (`Adjust-pool-18…24`) and the main
  stack; the module also spawns `adj9-oracle` for its 24-call re-sign burst.
* `cap.sh` / `cap2.sh` / `cap3.sh` / `cap4.sh` / `watch.sh` — all **self-resolving
  on-device**: they read `/proc/<pid>/maps`, take the region end, strip the low
  3 hex digits and compute `skip = $((0x<hi> - 0x10))`. This is the
  host-computed-pattern idea generalised: the value is small enough
  (`0x7b9f4e8` < 2³¹) that **mksh's 32-bit arithmetic handles it**, so no
  device-shell arithmetic bug can occur.
* Verified `$((0x7b9f4e8 - 0x20))` = `129627336` on-device before relying on it.
* Captured 300 + 227 dumps (128 KB tops) across two launches, and 1600 dumps
  (64 KB tops) across an 8-thread set.

**Result so far: the ctx was not captured**, and the reason is now understood
and is *not* a bug in the capture:

* `nsign_in` count is **14** over the whole session and signings are **minutes
  apart** (observed gaps: 60 s, 49 min, 35 min, 3 min, 30 min). A launch does
  not reliably produce a signing, so a short post-launch window mostly misses.
* Dumps that *did* land in a window (`nsign_in` 13→14 during `cap.sh`) still
  showed no array in the top 128 KB of `Adjust-pool-*` — consistent with the
  dump landing outside the ~860 ms native section rather than with the array
  being elsewhere (the assembler in §4 puts it within ~0x240 of the frame).

**Fix in flight:** `watch.sh` (launched detached) polls
`grep -c nsign_in` on the oracle log and, on the *first* increment, sleeps 1 s
then hammers 120 rounds of `dd` over `adj9-oracle` + `Adjust-pool-*` + main.
This keys the capture to the signing itself instead of to a launch. It is
waiting for the next signing; status at `/data/local/tmp/ctxcap4/status.txt`.

## 7. What is left

1. **Land the ctx dump** (`watch.sh` result) — then `layer2.py` +
   `fold_roundtrip.py` replay the fold against the same-session blob.
2. **Or skip the dump entirely**: with a 32-bit seed, brute-force the seed
   against a captured blob by forward-simulating the fold, once the record
   layout (from §5's vocabulary + the 0x10594 block order) is pinned. §4 now
   gives the ctx's first 0xD0 bytes exactly.
3. Resolve the 2048-byte read's path (`x22` at `0xe1f88`) if it turns out to
   matter.
