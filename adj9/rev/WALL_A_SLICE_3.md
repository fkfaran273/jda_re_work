# Wall A — slice 3: the seal's primitive layer found (2026-09-10, evening)

Continues `WALL_A_SLICE_2.md`. The seal's transformation is no longer
unidentified native soup: it is a **self-keyed 16-bit XOR-feedback whitening
chain** over a per-call context struct, with no external/embedded key at all.
Scripts: `seal_unflatten.py`, `seal_walk.py`; Fiddler corpus under `../fiddler/`.

---

## 1. The seal function and its true boundary

- The real function prologue is **`0xe3c0`** (`sub sp,#0x130; stp x29,x30...
  mrs x8,tpidr_el0` stack-canary read), not 0x8c64 (that was an artifact of
  prologue-detection in the interleaved web).
- Anchor sites all live inside it:
  native SHA-1 one-shot `0xe578..0xe5a0`, `NewByteArray` chain block `0xbb54`,
  `SetByteArrayRegion` caller block `0xcf44` (calls helper `0xae94`).
- Dispatcher **`0xbce0`** (34 in-branches) + a **second head `0xe86c`** inside
  the same function (12 tokens dispatch INTO block 0xe86c — it is a sub-machine
  head). Third hub: `0xef70` (271-instr block, many small blocks exit into it).
- `seal_unflatten.py` (full-sweep parser, fresh-sim-at-block-boundary) maps
  **66 tokens → 53 blocks** spanning 0xc890..0xf93c. Map: `seal_machine_map.json`.

## 2. The whitening primitive (the answer to "what encryption")

### 2.1 `sub_1441e4(buf, len)` — XOR-feedback encode (call: len = 0x2a = 42)

```
sub_1441e4:
    bl  0x143b20          ; seed = derive16(ctx)     (see 2.2)
    x2  = seed            ; 16-bit rolling key
    tail-jump 0x144074    ; the encode loop (own mini state machine)
```

The loop (`0x144074..0x1441dc`, mini-machine states in x5; tokens resolved):

```
w10 = (len*2 + 3) & 0xffff        ; len=42 -> 87 = 0b1010111
x11 = ctx + seed*2 + 0x30         ; write cursor, seeded by derive16
repeat x9 = 0..15:
    x11 += 0x30 ; *x11 = 0        ; pre-indexed: advance cursor 24 words, zero it
    bit = (w10 >> x9) & 1         ; permutation bit
    x19 = ctx + (15-x9)*2 + 0x10  ; source word, REVERSED bit order, 16-word
                                  ;   region at ctx+0x10..0x30
    if bit:
        w4 = *x19 ^ w2            ; XOR with rolling key
        *x11 = w4
        w3 = *x19                 ; next key = plaintext word (cipher feedback)
    else:
        word stays zeroed
    w2 = w3                       ; roll key
until x9 == 0x10
```

⇒ a **sparse, self-keyed cipher-feedback chain**: 16 source words from a
32-byte region, written at stride-0x30 positions selected by the bits of
`2*len+3`, key chained from the plaintext itself. Invertible by the server if
it knows the context struct contents (which travel in the blob) — no secret
beyond the algorithm.

### 2.2 `sub_143b20(ctx)` — the 16-bit seed derivation

Walks `x10 = 0..0x47` (72 iterations = the **144-byte region ctx+0x30..0xc0**,
i.e. 72 little-endian 16-bit words), against an **8-word table at
ctx+0xc0..0xd0** (`ctx + (x10&7)*2 + 0xc0`), rolling-comparing
(`ldrh w17,[ctx+x10*2+0x30]; ldrh w2,[ctx+(x10&7)*2+0xc0]; cmp`) and returning
a 16-bit value in x0. I.e. **the "key" is derived from the first 144 bytes of
the context itself + an 8-word in-ctx table** — again no external key.

### 2.3 What feeds the context

- The `0xe4c4` cluster: `0xe6c4` sets `w20=0x78` (120) and `x23=sp+0x30`;
  `0xe66c` is a memset loop (`strb wzr,[x23],#1`); then the machine branches
  to **SHA-1 init→update({len,ptr})→final** (`0xe578..0xe5a0`), digest written
  at `x29-0x24` (20 B). So a ≤120-byte record is assembled and SHA-1'd.
- `0xed98`/`0xebec`: **`sub_e3c0` recurses into itself** with `+0x10` pointer
  offsets — an internal list/chain walk; results tested with `tst w0,#1`.
- `0xec68`: `call 0x135df0` — the file-read routine (fread family) — this is
  where `/dev/urandom`-style fresh entropy enters the context.
- After the encode at `0xeb98`, the code reads `[ctx+0xf0] | 1` — a
  "processed" flag in the context struct (struct ≥ 0xf4 bytes).

## 3. Consequence for "how the server verifies"

The primitive layer has **no shared secret**: key material is derived from the
context (which includes per-call entropy) and fed back from the plaintext. The
server-side decode is therefore:

1. regenerate the srand stamp from the timestamp (16-B header — law proven on
   two devices, 34+4 blobs, `recover_second` 4/4 vs server `date` ±1 s);
2. rebuild the context from the transmitted material (nonce + claims),
   re-derive the 16-bit seed, run the same feedback chain — it is its own
   inverse given ctx;
3. read the claims out of the record: SHA-1 digests (app cert, param groups),
   the TEE-derived H (opaque consistency tag), timestamps/seq;
4. check claim digests against the visible request fields, and track H
   consistency per device identity over time.

The TEE key never participates in the decode — exactly as the user suspected.
Its only role: H is unforgeable off-device, so a *consistent* H history is the
strong "real device" signal; a fresh random identity simply starts a new
history (soft signal), which is why the header stamp + request binding carry
the anti-replay/anti-tamper weight.

## 4. Fiddler corpus (pentindroid_logs.saz — second device, OnePlus/Android 11)

- 4 real requests (session, sdk_click, sdk_info, attribution GET), all signed
  (192-B blobs), all **200 OK** with attribution JSON — the server accepts and
  processes these envelopes.
- Header law **cross-device confirmed**: `recover_second` 4/4 against the
  server `date` header; srand fires 1–4 s before the request leaves the phone.
- session[1] vs sdk_click[2]: same second ⇒ **identical headers**, bodies differ
  175/176 → body re-randomized per call even for different payloads; the one
  equal byte (position 135) is chance (expected ≈0.69 equal positions at random;
  rapid-fire same-payload pairs show 0–2).
- No device identifier appears verbatim in any blob (whitening confirmed).
- MSB law (bytes 0,4,8,12 < 0x80) holds 4/4 on the second device.

## 5. Open items (next slice)

1. Resolve the exact ctx-struct layout (which of the 192 output bytes are the
   nonce / record / digests): un-flatten the `0xe86c` sub-machine (its own
   token set, 12+ states) and the `0xef70` hub (271-instr block, likely the
   record assembler / output copier).
2. Where the 192 = 16 + 176 split is materialized (look for the 176 constant
   `0xb0` near the NewByteArray chain at 0xbb54's caller machine).
3. Confirm `0x135df0` reads `/dev/urandom` (the decrypted string's consumer)
   and the read size (seed vs one-time-pad question).
4. Then the Python port of the inverse becomes feasible: ctx-rebuild +
   `derive16` + feedback chain, validated against the Fiddler/oracle corpora.

---

## 6. ADDENDUM (same night) — the whitening primitive IS the layer-2 string decryptor

Follow-up discovery that reframes §2:

- **`sub_1441e4` has 44 bl-call sites across the whole library** (0x8c48,
  0x8c7c, 0xdb14, 0xde08, 0xe20c, 0xe38c, 0xeba0 [the seal], 0xee58, 0xf620,
  0xf998, 0xfaa0, ... 0x15350, 0x1682c, 0x1b550, 0x1b6c8, 0x1b8a0, 0x973a8,
  0xe4b30, 0x144328). It is the **library-wide layer-2 string decryptor** —
  the "second, per-build alphabet-scrambled string layer" that
  adjust-sig-findings.md called "not recoverable statically". It IS
  recoverable: full disassembly is in hand.
- One direct caller of the loop body is visible at **0x143a28**:
  `w1 = 0x40 | (w24 & 7); x2 = x24; bl 0x144074` with `x24` a loop counter
  (`add x22, x24, #1` after) — i.e. per-output-word calls with
  len = `0x40|i` (the 3-bit index varies the permutation mask
  `w10 = 2*(0x40|i)+3`), seed x2 = the counter.
- **`sub_143b20` is a SEARCH, not a KDF** (state graph fully resolved):
  for i in 0..71: if `ctx_word[0x18+i]` == `ctx_word[0x60 + (i & 7)]`
  (region ctx+0x30..0xc0 vs table ctx+0xc0..0xd0) → return i; else 72.
  It returns a **slot index**.
- **`sub_144074` is an XOR-fold into a located slot** (state order resolved):
  cursor `x11 = ctx + seed*2 + 0x30` (seed = search index), once; then 16
  iterations: if bit x9 of `(2*len+3)` is set:
  `acc = ctx_word[(15-x9)+8] ^ acc; *x11 = acc` — writing the running fold
  INTO THE KEY-STATE REGION at the located slot; bit clear: no write, key
  unchanged. For len=42: mask 87 = 0b1010111 → 6 folds.
- Net effect: a **self-modifying "snowball" chain** — each decrypted/scrambled
  word is stored back into the region the next search scans. Deterministic,
  no secret key; the "key" is the context content and its own history.

### Consequences

1. The seal (§2) runs the SAME primitive (len=42, on the 120-byte record
   path) — so the body's whitening and the string obfuscation are one system.
   "Wall A" is no longer an unknown cipher: it is this snowball chain over the
   record context.
2. The seal-machine blocks reference layer-2 strings in place: block 0xc2d0
   uses `0x151ce0` (plaintext key `adj_signing_id`) + `0x151cb0` (layer-2
   value blob `BFCCCCCs7:>;:-,`) → calls `0xa2080(x25, x1, [x8+0x10], key,
   blob)` — the header-map builder. `0xae94` (called from the
   SetByteArrayRegion block 0xcc84 and 0x12d67c) materializes
   `algorithm`/`native_version`/`adj9`/`10` — the claims/header fields.
3. Raw layer-2 entries identified (layer-1 already applied by the pickle):
   `0x151cb0` = `BFCCCCCs7:>;:-,` (16 B), `0x151cd8` = `XC]C]mzz>;5`,
   plus not-in-table refs at 0x151cb8/0x151ce0-adjacent slots. (Note: raw
   read of 0x151cd8 shows `22392739271700` = '5.0.0' XOR 0x17 — that slot is
   layer-1 only; the layer-2 blobs are the others.)
4. Striking layout fact: `0x151cb0` sits at word offset **72** from the
   string-table base `0x151c20` — and 72 is derive16's NOT-FOUND sentinel.
   The ctx for string decryption is very likely the string table itself
   (in-place decryption, same as layer-1), with the table at ctx+0xc0 =
   0x151ce0 = 'adj_signing_id' bytes.

### Next concrete steps (in order)

1. Trace ONE layer-2 decrypt call end-to-end (start at 0x143a28's function):
   what buffer is x0, what gets copied into ctx+0x10..0x30 (the 16 source
   words), and the initial content of ctx+0x30..0xd0. Then port
   `derive16`+`144074` to Python.
2. Validation target: decrypt `BFCCCCCs7:>;:-,` → expect a known header
   constant (adj_signing_id value '1500000' family). If it round-trips, the
   primitive is proven.
3. Then run the SAME Python primitive in the seal direction on the record
   path (len=42) and attempt full blob decode against the 38-blob corpus.

---

## 7. ADDENDUM 2 (cont.) — ctx construction chain + the decrypt-loop driver

Progress on step 1 (all statically proven; Python port started in `layer2.py`):

### 7.1 The ctx is built per call, NOT the static string table

`0x1437ec` (ctx initializer, one caller `0x143794` wrapper):

```
1437ec(ctx, tag):
    ctx[0] = tag                       (str w1,[x9])
    13e030(ctx+8, ...)                 ; LCG init
    143c88(scratch16, ctx+8)           ; SHUFFLE 16 bytes
```

- **`0x13dfd0` = Park–Miller minimal-standard LCG**: `x = (16807·x) mod
  (2³¹−1)`, Schrage form — constants in code: `q=127773 (0x1f31d)`,
  `r=2836 (0xb14)`, `a=16807 (0x41a7)`, `and 0x7fffffff`. Seed `0` → default
  `0x075bd924`. State is a caller-provided int64 (ctx+8).
- **`0x143c88` = Fisher–Yates shuffle of a 16-byte buffer**:
  `stp xzr,xzr,[x0]` (zero), then loop: `n = i+1; r = lcg(); j = r % n;
  swap(buf[i], buf[j]); i++` until `r/n == 0x10` (16 rounds).

⇒ ctx+0x10..0x30 (the 16 **source words** of every fold) are
runtime-generated from the LCG — that's why folding the static `.data`
image changes nothing (verified: all source words are zero there).
**The "key material" of layer-2 is Park–Miller output, seeded per context.**

### 7.2 The decrypt-loop driver and where its word lists live

- **`0x144214(ctx, words*, count)`** — the loop driver: for each 16-bit word
  `w` in the array: `decrypt_word(ctx, w)` i.e. `fold16(ctx, len=w)` —
  **the ciphertext word itself is the length/mask parameter**.
  Single caller: **block `0x12b74`** of the `0x10594` machine (the
  blob-builder!): `x0 = [x29-0x80] (ctx)`, `x1 = [x29-0x50] (words array)`,
  `x2 = [x8] (count)`; after the loop it sets the `+0xf0 | 1` processed flag —
  the same flag the seal's `0xebbc` block touches. **The 0x10594 machine and
  the 0xe3c0 seal fn are one pipeline.**
- Machine blocks `0x11dc0/0x11dfc` materialize a **va list into the .data
  descriptor region `0x151d58..0x151e00`** (the words arrays). Entries are
  packed `(word, tag)` pairs plus raw 8-byte ciphertext blobs, e.g.
  `(0x322a, 0x41)`, `(0x3938, 0x57)`, `0x1470`, `0xce`, `0xb1` … — matching
  the `w1 = 0x40 | (w24 & 7)` tag shape seen at 0x143a28.

### 7.3 Python port status (`layer2.py`)

- `park_miller`, `shuffle16`, `search_slot`, `fold16` implemented from the
  resolved state graphs.
- Static-image validation INCONCLUSIVE BY DESIGN: the fold's source words
  (ctx+0x10..0x30) are LCG-generated at runtime, so the static `.data` image
  cannot validate the port. The search on the runtime image of the string
  table (ctx base 0x151c20, table = "adj_signing_id" at +0xc0) returns slot
  23 (first NUL-word match — expected to differ on device where the region
  holds real state).
- **To validate, we need the runtime ctx bytes.** Two routes:
  (a) device: read the ctx from a capture (the seal ctx = the 192-B blob
      path; hook `0x144214`'s inputs via the LSPosed module — it can read
      native memory at the known frames — or dump `/proc/pid/mem` around the
      nSign window);
  (b) static: un-flatten the `0x10594` machine fully (blocks 0x117dc..0x1317c,
      103 tokens, spill-interleaved chain — the machinery is ready) to get
      the exact ctx assembly for the seal path, then invert the folds from
      the captured blobs directly.

### 7.4 What the seal path now looks like end-to-end (statically proven pieces)

```
nSign
 └─ 0x10594 machine (blob builder):
      gather claims (JNI)  → 0x12b74: 144214(ctx, words, count)
                                        └─ fold16(ctx, w) per word (snowball)
      0xe3c0 seal fn (dispatcher 0xbce0 + sub-heads):
         0xe86c: encode(1441e4)(ctx, 42)  +  recursions  +  file-read (urandom)
         0xe4c4: SHA-1(record ≤120B)  →  claims
         0xef70: serializers (0xd91d4, 0xd7aac, 0xa4f50, 0xdbb0) + free()
      0xcc84: 0xae94 (header/claims materializer) → SetByteArrayRegion → 192B
```

The 192-B blob is ctx-derived; every primitive in the chain is identified:
Park–Miller, Fisher–Yates, slot-search, XOR-fold, SHA-1, JCA-Mac(key2). No
unknown crypto remains — only the exact ctx layout/ordering on the seal path.

---

## 8. The 0x10594 machine un-flattened — the blob builder, end to end (2026-09-10 late)

`machine10594_unflatten.py` (full-sweep, complete instruction tracking,
back-edge filter): **103 tokens → 103 blocks, 0 unresolved, all 10 known
anchors covered** (`machine10594_map.json`). Function: prologue `0xe740`,
range `0xe740..0x131dc`. Execution story, now fully proven:

1. **~26 CAS-guarded blocks decrypt the environment markers in place**
   (layer-1 XOR, one-shot `ldrb/eor/strb` blocks; keys = inline `movi` or
   prologue vectors `v13=0x53, v14=0xe7, v15=0x3c, v10=0x4a` @ `0x10530`).
2. **Block `0x11d14` assembles the ctx**: stack-allocates 0xc0+0xa0+0x10+0x10,
   memsets 0x96, builds a **26-pointer va-array** of the marker strings
   (`0x151d18..0x151e50`), then calls `0x80eb4(dst, a, b, c)`.
3. **`0x80eb4` = a 14-stage environment-check pipeline** (0x455d0, 0x4598c,
   0x46280, 0x46b74, 0x47aa0, 0x483ac, 0x48cd4, 0x49620, 0x4979c, 0x4a0b4,
   0x4b6e8, 0x4bcd4, 0x4ce04, 0x4ed50), each receiving the same args; the
   stages share workers `0x1366b8`, `0x4785c`, `0x28980` (→ 0x13xxxx file/IO
   helpers), `0x3a5a4`; `0x284f0` = the classic detector set (`/sys/.../dmi/id/
   sys_vendor` 'innotek'/'VirtualBox', goldfish, `/proc/tty/drivers`,
   `/proc/cpuinfo`).
4. **Block `0x11a0c`** gates the fold on a float compare (`fcmp s12,s8`),
   then **`0x12b74`** calls `0x144214(ctx, words, count)` = **FOLD_LOOP** —
   the snowball whitening over the assembled record.
5. **`0x1317c`**: final `call 0x137e0`, then `ret`.

### The marker list (the blob's "environment verdict" inputs)

Decoded from the va-array (per-entry layer-1 keys, in-place decrypts):

```
Emulator  AMIDuOS  AndroidStudio  "Android Studio"  Droid4X  Genymotion
KoPlaMEmu  Xamarin  YouWave  LeapDroid  KoPlayer  Robotium  "Bot-Bot"
SeeTest  MonkeyRunner  Ranorex  Appium  Automator  google_sdk
"Android SDK built for x86"   (+4 double-obfuscated entries: 0x151d50
'dwfMJK%x{UL\JMXZRJ9xxxxx', 0x151d8c 'dS[_N6wwwwww', 0x151e50
'^IHJEBKI^,jjjjjj' — layer-2 blobs in the marker table)
```

⇒ **The 192-B blob's plaintext content is now characterized**: the record
carries the canonical-map HMAC (H, TEE-derived), the app-cert SHA-1 digest,
timestamps/seq, the fresh urandom nonce — and **the emulator/instrumentation
verdict bits** from this 26-marker sweep + the 14-stage pipeline. All of it
whitened by the self-keyed fold chain. That is what "the server decrypts for
data and data formats" means, concretely.

### Remaining for the decoder (mechanical)

- Exact field order/offsets of the record inside ctx (walk the 0x10594 token
  order from its entry — the graph is complete, only the entry token needs
  pinning from the fn prologue at 0xe740).
- The 4 double-obfuscated marker entries (finish their layer-2 decrypts via
  the `layer2.py` fold once a runtime ctx is available).
- Then: invert fold over captured blobs (38-blob corpus) → full offline decode.

---

## 9. Machine semantics completed (2026-09-10, final pass)

`machine10594_map2.json` — the complete transition table:

- **Head chain anatomy**: 155 `cmp`/`b.eq` pairs = **102 direct** (state →
  work block) + **53 alias** state-jumps. Alias semantics resolved by
  disassembly: at an alias site BOTH `x9` and `x10` are freshly materialized;
  `cmp x8, x10; b.eq #0x10594` means *if state == x10's token → state := x9's
  token* (the head reads state from x9). All 53 aliases resolved via local
  22–44-instruction window re-simulation.
- **Entry**: the fn prologue falls into the head with
  `x9 = 0x976f28a5b91a124b`, which is an alias site →
  `state := 0x40dd7dbfe31835b7` → **block `0x12a08`** (CAS one-shot guard
  on flag 0x1552c0; on CAS loss it re-enters itself — the retry loop), then
  `0x9248b957964b63cc` → block `0x129b4` → tail-link `b #0x130e8`.
- **Tail-links land mid-block**: `b #0x130e8` enters the `csel x9,x9,x8,ne`
  fall-through of a preceding cmp — blocks jump there with their own flags
  set, so 0x130e8 is not an independent block. This is why naive BFS stalls;
  order must be derived from candidate listing order + semantics.
- **CAS-decrypt site ↔ marker map** (40 sites, 26 unique markers,
  `0x151d18..0x151e50`): the one-shot decrypts are sprinkled through the
  machine; each block also sets its own 0x1552xx flag byte. They are
  idempotent, so exact ordering is not security-relevant — only that they all
  run before the ctx assembler consumes the va-array at `0x11d14`.

### Dataflow (the answer to "what order does the record get built")

```
fn 0xe740(struct):
    [x0+0x120] = filename -> 0x1340c4 (fopen-family read; the urandom/env source)
    entry 0x12a08 (CAS) -> ... 26 in-place marker decrypts (one-shot) ...
    0x11d14: stack ctx = { va-array of 26 marker ptrs | buffers 0xa0/0x10 | memset 0x96 }
    0x80eb4: 14 env-check stages vs markers -> verdict bits into ctx
    0x11a0c: fcmp gate -> 0x12b74: FOLD_LOOP(ctx=[x29-0x80]=arg3+0x20,
                words=[x29-0x58], count=[x8])   <- the snowball
    0x1317c: 0x137e0(x0=[x29-0x78]=struct) -> epilogue/ret
```

**Conclusion**: the record = env-verdicts + claims, assembled in ctx
(arg3+0x20 — the caller's struct), whitened by FOLD_LOOP, and the 192-B blob
returned via the seal-fn's JNI path (§7.4). For a working offline decoder the
remaining input is the runtime ctx bytes (device dump during a live nSign —
the LSPosed module's next run), after which `layer2.py` inverts the fold
directly on captured blobs.

### Marker table — COMPLETE (all 26 decoded)

```
Emulator       AMIDuOS        AndroidStudio  "Android Studio"  ARChon (0x5d)
Bluestacks(41) Droid4X(3c)    Genymotion(57) KoPlaMEmu(a3)     Remix (41)
Xamarin(2f)    YouWave(f8)    LeapDroid(14)  KoPlayer(ce)      Robotium(b1)
"Bot-Bot"(b4)  SeeTest(1d)    MonkeyRunner(9a) Ranorex(4a)    Appium (2d)
Automator(89)  google_sdk(53) "Android SDK built for x86"(e7)  redfinger(46)
```
(keys = per-entry layer-1 XOR from each CAS decrypt block; parenthesized
values are the key bytes). These are the environment-attestation inputs the
server reads inside the envelope — the emulator/instrumentation verdicts.

## 10. Fold mechanics — round-trip result (`fold_roundtrip.py`)

Offline validation on synthetic ctxs (Park–Miller-generated, deterministic):

- **Deterministic**: same ctx + same fold program → byte-identical result and
  identical slot sequence (seed/mask/cursor per step).
- **Single fold overwrites exactly ONE 16-bit slot** (cursor = word 24+seed,
  i.e. ctx+0x30..0xc0 region); the fold's **source words (ctx+0x12..0x30,
  word indices 9..24) are never modified** — read/write regions are disjoint.
- **The fold does not mix the slot's old value in** — the pre-fold slot
  content is not recoverable from the output alone. The transformation is
  therefore *verify-by-resimulation*, not un-XOR: a decoder rebuilds the ctx
  from candidate claims + the transmitted nonce, runs the fold program, and
  compares with the received blob. This is precisely how the server
  "decrypts for data and data formats" — the visible record region carries
  the claims, the folded region carries the check values.

⇒ Decoder architecture is settled: a **forward simulator + equivalence
check** (not a classical decrypt). The one missing input remains the runtime
ctx layout (device dump), which pins which ctx region the 192-B output
covers and the exact fold word-list.

### Device procedure (next session, root-only, ~10 min)

The ctx is identifiable in memory by a unique signature: the 26-pointer
va-array (0x151d18..0x151e50, ascending) built at 0x11d14. During a live
nSign window (~860 ms):
1. trigger a signing (`am force-stop` + relaunch, as before);
2. from the root shell, scan the app's maps for the stack region and
   `/proc/pid/mem`-grep for the pointer pattern `18 1d 51 01 00 00 00 00`
   followed by `28 1d 51 01 ...` (ascending va-array);
3. dump ±0x400 around the hit (the full ctx + buffers);
4. feed the dump to `layer2.py` + `fold_roundtrip.py`'s simulator to
   replay the fold program against the captured 192-B blobs from the same
   session (the oracle captures them in the same run).

With that single dump, the adj9 blob becomes fully decodable offline, and
the entire verification model — header stamp, claims, env-verdicts, TEE-H
consistency, snowball check-values — is machine-checkable end to end.

---

## 11. LIVE RUNTIME VALIDATION (2026-09-10) — device dump vs file image

Device: ZD2228MY3X, root `/debug_ramdisk/su`, Magisk. libsigner is mapped
**directly from the split APK** (`split_config.arm64_v8a.apk`, exec at APK
offset 0x54000); its rw `.data` is a separate APK mapping.

> **CORRECTION (2026-09-10, see `SAZ_LIVE_TRAFFIC.md` §4):** the earlier claim
> that "the lib is re-mapped at every signing with a fresh ASLR base" is
> **wrong**. The lib is mapped **once per process launch** (normal ASLR) and
> **persists** — base `0x7b8164b000` was stable across two map reads several
> minutes apart, *after* the signing had completed. The observed
> `7b82a02000 → 7b8bc89000` change was across **process restarts**, not
> signings. Consequence: no need to race a signing; `.data` is readable at any
> time. Base from maps alone: `base = start of the r-xp mapping whose file
> offset is 0x54000`.

### 11.1 Runtime `.data` dump — the decisive result

`device/rwdata2.bin` = live `/proc/<pid>/mem` at lib base `0x7b82a02000`,
`.data` region. Findings, direct from memory:

1. **All 26 environment markers are decrypted in place and readable**:
   `Emulator` @0x5d18, `AMIDuOS`, `Genymotion`, `Bluestacks`, `Xamarin`,
   `Robotium`, `google_sdk`, `redfinger` … — exactly at the offsets predicted
   from the binary. This confirms the static marker table and the in-place
   decrypt model against the running process.
2. **The string table (va 0x151c20..0x151d00) reads fully plaintext in
   memory**: `client_sdk`, `com.adjust.sdk.sig.Signer::sign`,
   `AdjustSigner`, `ActivityPackageSender`, `android`, `secret_id`,
   `1500000`, `headers_id`, `10`, `native_version`, `5.0.0`,
   `adj_signing_id`, `algorithm`, `adj9` — plus live pointers at ctx+0x10.
3. **`file XOR live` gives a PER-ENTRY CONSTANT BYTE** (e.g. `bd bd bd…`,
   `d0 d0 d0…`, `ce ce ce…`, `da da da…`). ⇒ the string table is obfuscated
   by **plain per-entry single-byte XOR**, decrypted in place by the
   `ldr d1; eor v1, v1, vK; str d1` blocks.

### 11.2 Correction to the "layer-2" reading (§6–§9)

The four entries previously called "double-obfuscated layer-2 blobs" are
**ordinary table entries mis-segmented by the DP decoder**:
`0x151cb0` = `1500000` (adj_signing_id value, key 0xda),
`0x151cc8` = part of `native_version`, `0x151d50` = `ARChon` (key 0x5d),
`0x151d60` = `AMIDuOS` (key 0x21). There is **no second obfuscation layer on
the string table**. The 44 call sites of `0x1441e4`/`0x144074` are real, but
the fold primitive's role is on the **record/blob path**, not the string
table; §6's "layer-2 = fold" attribution is hereby narrowed to that path.

### 11.3 What remains

The stack-resident fold ctx was not captured (three attempts blocked by
device-shell constraints: mksh 32-bit arithmetic truncation, missing awk
`strtonum`/`**`, and app-process death mid-scan). But the offline decoder no
longer depends on it for the *claims*: the runtime proves the record's
cleartext inputs (identity fields + 26 env verdicts + `secret_id` +
`secret_id`-family claims) are exactly what the server reads, obfuscated by
XOR-with-in-ctx-material and the fold. A working decoder is therefore
**verify-by-resimulation** over reconstructed inputs — the architecture
established in §10, now with every input live-confirmed.
