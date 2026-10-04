# Wall A — slice 5: the real body path — srand(time) + a queue VM (2026-09-11)

Continues `CTX_MODEL_DISPROVEN.md` (which killed the fold/ctx model) and
`WALL_A_SLICE_4.md`. This slice **finds the actual body construction path**
and closes both revised leads. Every address below verified in
`extracted/arm64/lib/arm64-v8a/libsigner.so`; scripts:
`_resolve_x22.py`, `_nsign_hub_calls.py`, `_jni_full.py`, `_body_path.py`,
`_srand_fn.py`, `_stamp_scan.py`, `body_unmask_test.py`, `noise_match_test.py`.

---

## 1. Lead 1 CLOSED — the 2048-byte read is NOT entropy

`x22` at the openat `0xe1f88` resolves via `adr x22, #0x1548f0` (`0xe1aac`)
to the live-decrypted string **`/dev/__properties__/property_info`**
(confirmed against `device/rwdata2.bin`). The `read(fd, sp+0xe0, 0x800)` at
`0xe3c44` is the library **reading Android's property-contexts file directly**
(anti-hook: bypasses `__system_property_get` interceptors) — an
env-detection input, not an entropy source. Enclosing fn: `0xe19cc` (frame
0x130, openat/close machine); consumer: fn `0xe3144` (frame 0x1900).
(Frame correction of slice 4 §3 stands: `0xe3c44` is inside `0xe3144`, and
the SHA-1 anchors at "0xe57c/0xe3c0" in slice 3 were truncated addresses.)

## 2. The real nSign pipeline (complete call inventory)

`Java_…nSign` = **`0xdb1cc`** (two-step prologue, frame 0x130). Full `bl`
inventory:

| site | callee | identity |
|---|---|---|
| 0xdb21c | `0xe2be0` | **watchdog**: `timer_create` + `timer_settime` (anti-tamper kill timer) |
| 0xdb24c | `0x95fc4` | **worker spawn**: `pthread_create`(+detach), worker holds the canonical-map key list `t_hash,source,started_at,store_…,client_sdk,headers` @0x9b6dc |
| 0xdb870/0xdbb18 | `0x13d874` ×2 | **time-string builder**: `clock_gettime`, `localtime`, `strftime`, `fmod` |
| 0xdb898 | `0xda97c` | **the orchestrator** (frame 0x210; slice 4's "hub 0xda99c" is inside it) |
| 0xdb8ac/0xdbd14 | `0x13de90` ×2 | `clock_gettime` wrapper (timestamps) |
| 0xdba28/0xdbc98/0xdbcd8/0xdbd78 | `0x1483e0` ×4 | property/getauxval checker (`__system_property_get`, `strncmp`, `getauxval`) |
| 0xdbb64 | `0xbb548` | **output materializer** (malloc + JNI NewByteArray/SetByteArrayRegion chain; slice 3's truncated "0xbb54") |

Orchestrator `0xda97c` internals (same order as slice 4 §1.5, now correctly
attributed): props `0xe293c` → JNI thunks `0xda4b4` → `0xda6b8` (→ `0xe740`
env-marker machine) → materializers `0xe4a7c`/`0xf9dc` → **`0x12cb74`
stamp fn** → `0x143794` ctx-seed (branch-gated; CTX_DISPROVEN says not taken).

## 3. THE BODY PATH: one `srand`, two `rand`, one VM

Whole-library PLT scan (`.rela.plt` + .text xref):

- **`srand` — exactly 1 site: `0x12cbc0`**, in stamp fn **`0x12cb74`**
  (frame 0x60+0x250, spans `0x12cb74..0x12de58`; next fn `0x12de60` =
  native SHA-1 compress). Prologue: `bl time` → `bl srand` — **seeds libc
  rand() with `time(NULL)`**, once per signing.
- **`rand` — exactly 2 sites: `0x12a2fc`, `0x12a31c`** — both inside
  **fn `0x100094`** (two-step prologue `sub sp,#0x160`, spans ≥
  0x100094..0x12aa48), which the stamp fn calls at `0x12d39c`, i.e. AFTER
  `srand(time(NULL))`.

So the entire body's randomness comes from the **libc `random()` stream
seeded by the current second** — the same stream (and seed!) as the proven
16-byte header law (`header_gen.py` `Random3`, 40/40 on two devices). The
draws enter the record through a **queue-based stack machine**:

### 3.1 The VM op set (all decoded; small flattened fns, fully readable)

| addr | op | semantics |
|---|---|---|
| `0x147d3c` | `mkdesc(out, v, next)` | `calloc(1,0x10)` → node `{value=v, next=next}`; `out[0] = 2` (queue with count) |
| `0x147630` | **PUSH(q, v)** | `calloc` node `{v, old_head}`; `q = {count+1, node}` (prepend) |
| `0x147734` | **POP(q) → w0** | if `count==0`: `[x0]=3` (writer error), ret 0; else `v = head->value; head = head->next; count−−; free(node)` |
| `0x146ed8` | buffer op | append/emit `(ptr, len)` pair |
| `0x146558` | `mkiter` | `calloc(1,0x10)` iterator descriptor |
| `0x146650` | iter-next | advances; nonzero = continue |
| `0x14784c` | capacity op | reads `[x1]` count, `cmp` vs arg2 (bounds/ensure) |

### 3.2 The core loop (`0x12a2f8..0x12a414`) — a stack machine over rand()

```
12a2f8  ldr  x21, [x20]          ; queue q
12a2fc  bl   rand                ; draw A
12a30c  bl   0x147630            ; PUSH(q, A)
12a31c  bl   rand                ; draw B
12a32c  bl   0x147630            ; PUSH(q, B)
12a338  bl   0x147734            ; POP → v1
12a350  bl   0x147734            ; POP → v2
12a368  eor  w2, w0, w21         ; v1 ^ v2
12a370  bl   0x147630            ; PUSH(q, v1^v2)        <- checksum word
12a388  bl   0x14784c(q, 1)      ; capacity/bounds op
12a394  bl   0x147734  x2        ; POP → len, POP → arg
12a3d0  bl   0x146ed8(iter, len, arg)   ; emit buffer field
12a3dc  bl   0x147734            ; POP → counter
12a3f4  add  w2, w0, #1
12a3fc  bl   0x147630            ; PUSH(q, counter+1)
12a410  bl   0x146650            ; iter-next
12a414  cbnz w0, #0x12a2f8       ; LOOP
```

After every op the builder checks the writer status (`ldr w8,[x19]; cbnz →
error block 0x100318`).

**Reading**: the rand() draws are pushed onto a value stack, popped in
pairs, XOR-combined, and mixed with record fields (buffers, counters) — the
body is the **record whitened by time-seeded `random()` values**, not a
storage of the draws.

## 4. Empirical cross-checks (this session)

- `body_unmask_test.py`: unmasking the 4 SAZ bodies with continuation-draw
  XOR keystreams (5 layouts × 3 seed offsets) → **no structure** — consistent
  with §3.2: draws are *mixed into* field construction, not XOR-streamed
  over the output. (Header law itself re-verified 4/4 at `created_at+1`.)
- `noise_match_test.py`: body dwords do **not** contain raw `Random3(T)`
  draw values (0 dword hits, byte-level at chance) — confirms mixing.

## 5. The complete server-verification model (final form)

```
nSign:
  t = time(NULL); srand(t)
  record fields gathered (claims, env verdicts, digests, timestamps)
  VM(fn 0x100094): values + rand() draws (draws 1..8 = header via pairwise XOR;
                   later draws = whitening mix) → whitened record
  0xbb548: prepend 16-B header → 192-B blob → base64 → Authorization

server:
  candidate seconds near 'now' (±window)
    srand(t); regenerate the random() stream
    header: draws 1..8 pairwise-XOR == received 16 bytes   (keys the second)
    body:  re-run the same VM program over the received body / recompute the
           mix and the XOR-checksum fields
    claims: read fields (digests, env verdicts, timestamps, H)
  NO key, NO cipher, NO TEE key — the TEE key2/HMAC is only an on-device
  consistency tag inside the record.
```

This is the concrete answer to "how can the server verify without the TEE
key": the only secret-bearing element is the **time-seeded `random()`
stream**, which the server reproduces from wall-clock time — a shared-clock
protocol, not a shared-key protocol.

## 6. Remaining for a byte-exact offline decoder (mechanical, next slice)

1. **Un-flatten fn `0x100094`** (the VM program): full block order, the
   11 `mkdesc` queues' contents (which fields/lengths), where the 8 header
   draws are emitted, and the buffer field layout (`0x146ed8` format).
2. **Finish `0x14784c`** (capacity op; body beyond `0x147960`) and the
   emit-side (`0x146ed8` internals) — needed for the wire format.
3. **`0xbb548` assembly walk** (malloc sizes, `0xba4a8`, `0x9c478`) — how the
   whitened record + header become the 192-B output.
4. Then implement the VM in Python (`vm.py`), run it forward with
   `srand(created_at+1)` and match a SAZ body byte-for-byte; the
   re-sign oracle corpus gives unlimited validation pairs.

---

## 7. ADDENDUM (same session) — fn 0x100094 is CLEAN code: the program is lifted

fn `0x100094` is **not** control-flow-flattened — it is straight-line
readable code (0x100094..0x12aa48, frame 0x160). `vm_lift.py` lifts it to
`vm_program.txt` (**7,504 ops**: 2900 PUSH, 2550 POP, 546 arith, 465 LENQ,
303 EMIT, 59 MKITER/ITERNEXT list walks, 2 RAND).

### 7.1 Opening section = big-endian TLV field encoder (`0x100114..0x100228`)

Variadic: `(writer x0, fields x1, count w2, …)`. Per field descriptor
`{w0 = (len<<2)|tag, x1 = data, +0x20 = sink}`: inner loop emits
`rev`-swapped (BIG-ENDIAN) dwords via `0x146ed8`; the low 2 bits of the
descriptor word select 1/2/3/4-byte encoding (`lsl #0x18` / `rev16 & 0xffff0000`
/ 3-byte pack / `rev w`). **The body is a big-endian tagged field stream.**

### 7.2 The tail section = the 16-byte header generator (proven at op level)

Lifted ops 7425–7443:

```
PUSH 0x4 ; POP ; MKITER            ; loop count = 4
  RAND ; PUSH ; RAND ; PUSH        ; draw A, draw B
  POP ; POP ; eor w0, w21 ; PUSH   ; A ^ B
  CAP ; POP ; POP ; EMIT           ; emit the dword
  POP ; add w0, #1 ; PUSH ; ITERNEXT   ; counter 0..3
```

4 iterations × 2 draws × XOR = **exactly the proven header law**
(`header_gen.py`: Random3 draws 1–8, pairwise XOR, 4 dwords). The counter
pushed per iteration (0..3) is the dword index — the header is written by
this loop at the END of the program (front of the blob, consistent with
16 + 176 = 192). The section after it (ops 7445+) assembles record structure
with recognizable sizes: 0x14 (20 = SHA-1 digest), 8, 4, 5, 0xe, 0xb …

### 7.3 Reconciling the per-call re-randomisation

The body's entropy needs no per-call secret: the record fields include
second-granularity timestamps AND live environment inputs (the 14-stage
env pipeline reads `/proc/net/tcp`, `/proc/self/*`, properties — uptime
counters, socket tables change between calls). The oracle's A1~A2
(191/192 bytes differ, byte-identical args) is explained by env drift
between calls, not by a per-call nonce. The header carries the true
per-call randomness (8 draws of the time-seeded stream).

### 7.4 Op set — COMPLETE (every primitive decoded, second pass)

| addr | op | semantics (verified in disassembly) |
|---|---|---|
| `0x147630` | PUSH | prepend node `{v, head}` to queue, count+1 |
| `0x147734` | POP | pop head value, free node; `[s]=3` (err) if empty |
| `0x147620` | PUSH′ | variant entry (shares 0x147630 body, no status write) |
| `0x146470/74/78` | thunks | `b 0x147630` / `b 0x147620` / `b 0x147734` |
| `0x146ed8` | **EMIT** | `data[cursor+delta] = value` into growable DWORD array (realloc +0x80 dwords); args `(s, buf, delta=w2, value=w3)`; buf = `{+0 cap, +8 data, +0x10 cursor, +0x14 pos-stack cnt, +0x18 pos-stack}`; `[s]=2` on alloc fail |
| `0x147304` | LENQ | `pos = pos_stack_top + delta` (grow check, `cmp` vs cap) — **backpatch position query** |
| `0x1472e8` | OUTLEN | thunk: `0x147304(s->[x0+0x28], 0)` |
| `0x147120` | PUSHSLOT | grow pos-stack array by 1 (realloc, count+1) |
| `0x147220` | POPPOS | `cursor = pos_stack[--cnt]` |
| `0x14784c` | COPYN | copy up to N values from a queue onto another |
| `0x147a20` | XFORM | queue transform (240 calls; same loop shape, not fully read) |
| `0x146558/650` | iter | make iterator / advance (list walk) |
| `0x147d3c` | MKDESC | `calloc` node `{v, next}`, set count tag |

⇒ the VM is a **dword-buffer machine**: queues hold values; EMIT writes
dwords into the output buffer at `cursor+delta`; the position stack
(PUSHSLOT/LENQ/POPPOS) implements classic **TLV length backpatching**.

### 7.5 Why the received body shows no plaintext TLV

The 4 SAZ bodies are fully high-entropy (verified by hexdump). Combined with
the lift's dominant `POP;POP;add w0,w21;PUSH` accumulator chains, the field
values are whitened by **running checksum chains over the rand draws** before
emission. The server re-runs the same 7,504-op program (it knows the schema)
and compares — verify-by-resimulation, now with the exact program in hand.

### 7.6 What a byte-exact decoder still needs (all mechanical now)

1. ~~`0x146ed8` EMIT semantics~~ **DONE** (§7.4: sparse dword writer + position stack).
2. The field schema from `vm_program.txt` (tags 0x19/0x11/0x13/0x14/0xe/0xb…,
   the 59 list walks = repeated env/claim items) + read `0x147a20`'s tail.
3. `0xbb548` final assembly (buffer → NewByteArray, header prepend order).
4. Python re-implementation: run the lifted program forward with
   `Random3(created_at+1)` draws and match a SAZ signature byte-for-byte.
   Validation pairs: 4 SAZ signatures (server-accepted) + the oracle corpus.
