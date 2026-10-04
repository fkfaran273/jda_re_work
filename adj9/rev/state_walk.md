# state_walk — sub_8d6f4 unflattened: bounds, tags, ordered ctx fill, tile structure, THE PER-CALL SEED

Date: 2026-09-23. Pure static pass (no device, no Unicorn). Library:
`extracted/arm64/lib/arm64-v8a/libsigner.so`. Tooling: `rev/dump_at.py` (capstone 5.0.7),
`rev/state_walk.py` (existing mechanical unflattener — chain parse + DFS walk, run log
`rev/state_walk_run.log`, 491 steps / 781 states), plus new one-off scanners (in-lined in
this session: e2948-call pairing, spill-slot dataflow, whole-lib `bl rand/srand/time`,
descriptor-maker census, lrand48 inversion attempt).

---

## 1. TASK 1 — true bounds and ALL entry points

```
sub_8d6f4  = 0x8d6f4 .. 0x95fc4   (0x88d0 bytes = 8756 instructions; linear-decodes cleanly)
entry tag  = 0xCDB13B067E1DEE4A   (materialized in x6 by the prologue, 0x8d72c-0x8d774)
```

Prologue facts (0x8d6f4..0x8d798): saves d8-d15/x19-x29, `sub sp, sp, #0x580`, and spills the
args into the O-LLVM frame slots used everywhere below:

| frame slot (x29-off) | content |
|---|---|
| 0x118 | arg0 (x0 at entry) |
| 0x120 | **ctx** (x2 at entry) |
| 0x5A0 | arg1 (x1 at entry) |
| 0x5A8 | &ctx+0x64 |
| 0x5B0 | &ctx+0x60 |

### Entries — exactly TWO (the "VM enters at multiple points" hint resolved)

| entry | reached by | role |
|---|---|---|
| **0x8d6f4** | `bl` from the VM at **0xfb64** (`bl 0x8d6f4(x0, x1, ctx=sp+0x38, x3)`) | the region builder (main pass) |
| **0x956e0** | `bl` from the VM at **0x10440** — `add x0, sp, #0x38; bl 0x956e0` (x0 = the SAME ctx) | **second pass = ctx destructor**: its own prologue, materializes hub-B tags (x28 = 0x7dce225ef81f8277 / 0x14994d0932fadb7e chosen by `cmp x0,#0`) and dispatches into hub B 0x9579c; its work blocks (0x95d74/0x95ddc/0x95e5c/0x95e80/0x95f64...) walk the ctx qwords, `free()` (PLT 0x148a00) each non-null heap pointer and zero the slot (`str xzr,[x19,#0x20/0x30/0x50]`, counter loop at 0x95f40) |

No other external branch/data-pointer enters the range (whole-binary sweep: only 0xfb64 and
0x10440; no .data/.rodata pointers into it). The previous real function ends at 0x8d6ec
(ret of the screen-whitelist checker 0x8d400, see §5).

### Flatten shape — two tag hubs, 296 tags

```
HUB_A 0x8d798 : state reg x0, source reg x6   — 266 tokens (cmp/b.eq chain; aliases re-materialize x6)
HUB_B 0x9579c : state reg x9                  —  30 tokens (shared with the 0x956e0 second entry)
```

Full token→work-block tables are produced by `python state_walk.py chain`; the DFS walk
(`python state_walk.py walk`, log `state_walk_run.log`) from the entry tag reproduces the
straight-line order for the whole probe phase and the start of the map phase, then stalls on
data-dependent loops (revisit policy). Work-block ends materialize the next 64-bit tag by
mov/movk into x6 (hub A) or x9 (hub B) and `b` the hub; ~40 branch sites carry two candidate
tags via `csel` guarded by real conditions (flag/CAS checks, malloc-null checks, loop counters).

---

## 2. TASK 2 — ordered fill trace (verified against walk steps S1–S137 + static dataflow)

### Phase 0 — decryptor gates (S1–S2)
CAS-acquire flag (0x1483e0) + per-blob decryptor gate (`load w14, [0x155000+0x926]`-style flag
bytes). All name/sig blobs below are decrypted IN PLACE before use by the in-block
`ldr q/d; eor v, key; str` + `ldrb/eor/strb` decryptors.

### Phase 1 — the 13 __system_property_get probes (S3–S120)

One iteration per probe (8 flattened states each: decrypt-gate → malloc → zero-ctx-slot →
copy-loop → **fill-ctx-slot + call-next-probe**). Chain proven by static dataflow (each fill
block loads the previous probe's malloc pointer from its dedicated spill slot and calls the
NEXT probe in the same block):

```
0x92d90  [init]  out=sp-0x60 zeroed; adr x0,0x1524a8(^0x66 "ro.bootloader"); bl 0xe2948
B(0x91868)  CTX[0x48] = heap copy of ro.bootloader ; call 0x1524d0(^0x60 "ro.product.manufacturer")
B(0x939dc)  CTX[0x08] = heap copy of manufacturer  ; call 0x1524f0(^0xcf "ro.product.model")
B(0x90ec0)  CTX[0x18] = heap copy of model         ; call 0x152560(^0xa4 "ro.product.device")
B(0x93aa8)  CTX[0x20] = heap copy of device        ; call 0x152740(^0x1c "ro.build.display.id")
B(0x90964)  CTX[0x28] = heap copy of display.id    ; call 0x1525d0(^0x6c "ro.product.name")
B(0x93340)  CTX[0x00] = heap copy of name          ; call 0x152488(^0xb5 "ro.build.host")
B(0x92bc0)  CTX[0x58] = heap copy of host          ; call 0x152600(^0x61 "ro.build.fingerprint")
B(0x91314)  CTX[0x30] = heap copy of fingerprint   ; call 0x153640(^0x32 "ro.build.type")
B(0x93714)  CTX[0x38] = heap copy of build.type    ; call 0x152540(^0xe9 "ro.product.brand")
B(0x944c0)  CTX[0x10] = heap copy of brand         ; call 0x153650(^0xb1 "ro.build.user")
B(0x94e50)  CTX[0x50] = heap copy of build.user    ; call 0x152468(^0xa9 "ro.hardware")
B(0x93560)  CTX[0x40] = heap copy of hardware      ; call 0x153660(^0x35 "ro.product.cpu.abilist")
B(0x92110)  CTX[0x68] = heap copy of cpu.abilist   ; x3 = 0x153680(^0xd0 "SENSOR_SERVICE"); bl 0xc1af0
```

Per-iteration idiom (fill block B, example CTX[0x48]):

```
0x91878  adr   x0, #0x1524d0        ; NEXT probe's still-encrypted name blob
0x91880  sub   x8, x29, #0x20
0x91884  ldur  x9, [x9, #-0x100]    ; = malloc'd copy of PREVIOUS probe's value (slot x29-0x1f0)
0x91888  ldur  x8, [x8, #-0x100]    ; = ctx (slot x29-0x120)
0x9188c  str   x9, [x8, #0x48]      ; *** CTX[0x48] = heap string pointer
0x91894  ldur  x1, [.. #-0x100]     ; 0x60-byte zeroed out-buffer (slot x29-0x110)
0x91898  bl    0xe2948              ; __system_property_get(next name, out)
```

Each `bl 0xe2948` site pairs 1:1 with a fill store (13 sites, 13 fills). Effective per-blob
keys above = XOR of that blob's in-place pass keys (scanner-extracted; e.g. 0x152560 site
0x91440 `movi v1.16b,#0xa4`, 0x1524a8 site 0x94568 `eor w,#0x66` ×6).

**CTX LAYOUT MAP (offset → source):**

| ctx off | source | wire/notes |
|---|---|---|
| 0x00 | ro.product.name | heap copy (malloc+byte-loop copy of the 0x60 out-buffer) |
| 0x08 | ro.product.manufacturer | heap copy |
| 0x10 | ro.product.brand | heap copy |
| 0x18 | ro.product.model | heap copy |
| 0x20 | ro.product.device | heap copy |
| 0x28 | ro.build.display.id | heap copy |
| 0x30 | ro.build.fingerprint | heap copy |
| 0x38 | ro.build.type | heap copy |
| 0x40 | ro.hardware | heap copy |
| 0x48 | ro.bootloader | heap copy |
| 0x50 | ro.build.user | heap copy |
| 0x58 | ro.build.host | heap copy |
| 0x60 | **DisplayMetrics.widthPixels** | JNI GetIntField via 0xbe168 @0x912d0 (name 0x153690 ^0x58) |
| 0x64 | **DisplayMetrics.heightPixels** | JNI GetIntField via 0xbe168 @0x93814 (name 0x1536a0 ^0xea) |
| 0x68 | ro.product.cpu.abilist | heap copy |

**CORRECTION to writer_findings/WALL_145:** `0x93a00 str x9,[x8,#8]` is NOT a claims length —
it is the ordinary probe-fill store `CTX[0x08] = heap copy of ro.product.manufacturer`
(x9 = the malloc result spilled to slot x29-0x1f8 at STEP 14). The claims byte-length appears
in the WIRE as descriptor #7 (0x168 / 0x183 in rand_hunt.log), not at ctx+8.

### Phase 2 — map/getBytes bridge (S121–S151)

- Init: `bl 0xc1af0` (SENSOR_SERVICE), `0xcba34`, `0xb53bc` (S121–S122).
- Counted loop head **0x9226c** (guard `cmp w23, w14; b.lt` @0x922b4 — S124/S131/S138):
  body per map entry = `0xb5ea8 → 0xca8ec → 0x9c478 → 0xcb160 → 0x9c478 → 0x95174`
  (S125–S130), loop back while `cmp w0,#0; b.eq 0x9226c` @0x92488.
- Interleaved indirect JNI vtable calls (`CALL* x8`) at 0x90ab8 / 0x93000 / 0x92710 /
  0x93190 / 0x934ac — the getBytes bridge (String → byte[]) over the ~50-entry
  LinkedHashMap (this materializes the claims bytes; wire descriptor #7 = claims length).

### Phase 3 — JNI ints + cleanup (S153–S160, S280/S289)

- `bl 0xc797c`, `bl 0xc8b1c` (S153–S154) — DisplayMetrics glue.
- **0x91298: `bl 0xbe168` @0x912d0 → *(&ctx+0x60) = widthPixels** (S157; name decrypted by
  the ^0x58 block at 0x90868).
- **0x937dc: `bl 0xbe168` @0x93814 → *(&ctx+0x64) = heightPixels** (S160; ^0xea block 0x90d60).
- `bl 0x9e0c0` ×2 (S280/S289) — finalization helpers.
- Builder returns w0 status; VM checks it at 0xfb84 (`cmp w0,#0; csel` two failure tags).

### Phase 4 — VM post-pass and serialization (ctx→B relationship)

- VM (0xfb00) calls **0x956e0(ctx)** at **0x10440** — destructor pass (frees the 13 heap
  strings, §1).
- VM then runs the **wire builder**: 11 descriptors {u32 nbytes; ptr} are created by
  `bl 0x147d3c` (calloc(1,16) node) at 11 sites — sizes seen: **0x90 (#0, 144 B)**,
  **0x20 (#4, 32 B)**, 0x10 (#8), 0x14 (#9 = SHA-1), others computed (claims material);
  the 144-byte #0 buffer (arg+0x50) and its descriptor are pre-created at RESUME time by
  0x12cb74 (called from nOnResume, see §4), filled per signing.
- Serializer entry **0x100094**, called by `bl` at **0x12d39c** with w2 = **0xb (11
  descriptors)**: per descriptor emits each dword big-endian (`ldr w8,[data,idx<<2];
  rev w3,w8; bl 0x146ed8` — 304 EMIT sites), sub-word kinds for nbytes&3 = 1/2/3, then the
  LENQ tail (`bl 0x147630` w2=0x19 / w2=0, `bl 0x147734` ×2, emit [x20+8]...).
- The descriptor data pointers are the heap struct B fields: B+0x94 ↔ #0 (144 B),
  B+0x74 ↔ #4 (32 B), B+0x60/0x64 ↔ the width/height ints copied from ctx+0x60/0x64,
  B+0x134..0x154 ↔ #8/#9 + claims lengths. So **ctx→B = plain copy for the ints; #0/#4 are
  built straight into B by the VM's wire builder (never stored through ctx — the only
  ctx-relative stores in 0x8d6f4..0x95fc4 are the 36 sites of §2 Phase 1, offsets 0x00–0x68).**

---

## 3. TASK 3 — tile construction and the key schedule

### Observed wire shape (device, 10 signings — d0_struct.log / rand_hunt.log)

```
#0 (36 dwords, 144 B) = W0 [, W1] || T0 T1 T2 T3 ×8 || T0 T1 T2      (only 4-6 distinct words)
#2 (1 dword)          = one more per-call word (fb1a8296 / 7c933329 / 4bce691e ...)
#4 (8 dwords)         = 8 per-call words (sparse-bit patterns, e.g. 00100400 04144000 8000c440 88104c05 ...)
#7                    = claims byte length (0x168 / 0x183)  — constant for identical claims
#8/#9                 = static table / cert SHA-1 — constant
```

So tile_i is trivially `tile = T0..T3 repeated`; the unknown is the 16-byte T (plus the
1-2 lead words W0/W1, #2, and #4's 8 words). All of these change on EVERY signing.

### The 81 eor sites are NOT the tile keyer

`0x8d6f4..0x95fc4` contains exactly **81 eor/eon sites** (17 vector + 64 scalar) — every one
of them is a blob decryptor pass (in-place `eor v0.16b/v0.8b, key` for the name strings,
plus byte-fixups). There are NO 16-stride fill runs, no `stp q0,q0` tile replication, and no
writeback-16 stores anywhere in the library. Conclusion: the tile is not XOR-materialized in
sub_8d6f4 at all — it is produced in the VM's wire-builder states (0x100094..0x12e2xx region)
and/or lands in B directly.

### Where the per-call words come from — see §4. The static evidence chain:

1. Only three rand-family call sites exist in the whole library:
   `bl rand` @ **0x12a2fc**, `bl rand` @ **0x12a31c**, `bl srand` @ **0x12cbc0**.
2. The two `bl rand` sites sit in the VM's wire-builder flattened machine (same shared exit
   0x100318 as the 0x100094 emit blocks); each does
   `ldr x21,[x20] (out buf); bl rand; mov w2, w0; bl 0x147630 (append value)` — raw rand
   dwords appended to the wire. Flattened loops re-enter these states, so >2 draws per
   signing are possible with only 2 static sites.
3. The wire words exceed 2^31 in both lead and tile positions (seed_bf2.log), while
   bionic rand() outputs are 31-bit ⇒ the appended rand values are mixed with per-site
   constants (the 474 mov/movk immediates = that key material) before/while emission. The
   exact per-word arithmetic is the one piece not yet pinned statically (needs the full
   wire-builder state walk, or a Unicorn run with breakpoints on 0x148d10/0x148d30).
4. deriv3's zero hits are consistent: it brute-forced static keys and entropy RUNS against
   standard families, but the wire words are a (rand-stream ⊕/+ per-site-constant) mixture
   seeded by a wall-clock srand — not a fixed-key derivation of captured inputs.

### Tile pseudo-code (as far as statically reachable)

```
# at nOnResume (once per resume):
srand(time(NULL))                                  # 0xdafe4 -> 0x12cbbc bl time; 0x12cbc0 bl srand
make_descriptor(nbytes=0x90, buf=arg+0x50)         # 0x147d3c — the #0 descriptor, pre-created

# per signing (VM wire builder, states 0x12a2f8..0x12a32c etc.):
r_i    = rand()                                    # continuous stream, NOT reseeded per signing
word   = mix(r_i, per_site_constant)               # 474 mov/movk immediates feed mix()
# descriptor #0 (144 B): W0 [, W1] then T = 4 words (16 B) replicated 8× + 3;  #2: 1 word;
# #4: 8 words;  #7: claims length;  #8/#9: static/cert-SHA1
emit(rev32(word))                                  # 0x100094 descriptor walk, BE dwords
```

`mix()` is the remaining unknown; the ENTROPY SOURCE is fully identified (§4).

---

## 4. ★ THE PER-CALL SEED (the single most important answer)

**The per-call varying input is the C-library PRNG stream — `srand(time(NULL))` is called
once per nOnResume, and each signing consumes the advancing `rand()` stream.**

Evidence chain (all static, every link verified in disassembly):

1. **nOnResume seeds it.** JNI export `nOnResume` (0xda4b0) calls the function 0x12cb74 at
   **0xdafe4** (its only caller). 0x12cb74 does, with zero intervening instructions:
   ```
   0x12cbbc  bl  time    (PLT 0x148d20)   ; x0 = time(NULL) — current UNIX SECOND
   0x12cbc0  bl  srand   (PLT 0x148d30)   ; srand(that second)
   ```
   then pre-creates the 144-byte descriptor for #0 (`bl 0x147d3c(&d, 0x90, x19+0x50)`).
2. **Every signing consumes it.** The wire-builder states at **0x12a2fc** and **0x12a31c**
   (`bl rand` → append via 0x147630) are inside the VM machine that nSign drives
   (nSign 0xdb1cc → 0x95fc4 → VM 0xfb00 → wire builder → serializer 0x100094 via 0x12d39c).
3. **The stream persists and advances across signings.** srand fires only on nOnResume;
   within one process, signing N+1 continues the stream where signing N stopped —
   so two signings with identical claims in the SAME SECOND still draw different values.
   (If an onResume re-seeds between two same-second signings, the sequences would reset —
   the measured differing pair simply had no reseed between them.)
4. **Nothing else varies.** The 13 property values, width/height, package name, cert SHA-1
   (#9), #8 table, HMAC (identical claims ⇒ identical HMAC), map bytes, claims length (#7)
   are all constant across the measured pair. `rand/srand` are the only PRNG imports in the
   entire signing path (whole-lib `bl` sweep); no `/dev/urandom`, `getrandom`,
   `clock_gettime`, `pthread_self` or tid read feeds the wire builder (the 0xe2xxx syscall
   family only serves the property/file probes; clock_gettime PLT refs at 0x18aa0/0x13dec0
   are outside the signing path; the 0x13de90 elapsed-time helper only touches the worker).

This also explains why deriv3 (87.2M comparisons) found nothing: the varying words are a
PRNG-stream mixture seeded by wall-clock time, not a fixed-key function of the captured
inputs. Reproduction path: model bionic `rand()` exactly (this is the glibc/BSD TYPE_3
additive-feedback generator on modern bionic — `rev/bsd_random.py`/`rev/glibc_rand.py`
already implement both candidates), seed with the resume-time second, then recover the
`mix()` constants from two known signings (two signings at known seconds ⇒ recover both the
stream offset and the per-site constants). A direct falsification test on the existing
captures failed for RAW lrand48 output (no consecutive-output solution for the tile words),
which independently confirms a mixing transform sits between rand() and the wire.

---

## 5. Side findings

- **0x8d400..0x8d6f0** (directly before the builder; called from VM 0x102f8) = screen-size
  whitelist: flattened checker loading the SHA-1-const block 0x35d0-0x3630 plus ~20 64-bit
  immediates, reading `[x0,#0x60]`/`[x0,#0x60+4]` = width/height, comparing against ~13
  known resolution pairs in a 0..8 loop, returning `w0 = width < 2^N`-style bit. Anti-emulator.
- The walk's early phases (S1-S120) run in true order; DFS branch arms explain the later
  "revisit" noise. Steps 121-320 confirm the map loop, the two be168 calls and 0x9e0c0 calls;
  the walk does not reach the tile/emit states (data-dependent loops) — those were analyzed
  statically instead.
- `same_second.json`'s mint1/mint2 pair is a python-minted pair (ok:false), not a device
  capture — its identical 192 B blobs do not contradict the per-call variance seen on device.
- Descriptor-maker census (`bl 0x147d3c`, 11 sites): nbytes 0x90 (#0), 0x20 (#4), 0x10 (#8),
  0x14 (#9), rest computed — matches the 11-descriptor serializer call (w2=0xb @0x12d36c).

## 6. Reproduction

```
python adj9/rev/state_walk.py chain     # 266 + 30 token tables
python adj9/rev/state_walk.py walk > state_walk_run.log
# scanners used (session-inlined): e2948 pairing, spill-slot dataflow, ctx-store catalog,
# whole-lib rand/srand/time sweep, 0x147d3c census, lrand48 pair-solve inversion
```
