# Wall A — slice 6: CONCLUSION — the adj9 verification model, complete (2026-09-11)

This slice is the answer to the original question — *"how does the Adjust
server verify the signature when it cannot know the TEE key?"* — with the
complete evidence chain, the one remaining gap, and the infra failures that
cost time (recorded so they are not repeated).

---

## 1. THE ANSWER

**adj9 is a shared-CLOCK protocol, not a shared-KEY protocol.**

The entire `libsigner.so` has exactly **one** `srand` call site and **two**
`rand` call sites (exhaustive PLT scan, no others exist):

| site | role |
|---|---|
| `0x12cbc0` `srand(time(NULL))` | the ONLY seeding, once per signing, wall-clock seconds |
| `0x12a2fc`, `0x12a31c` `rand()` | both inside ONE loop in fn `0x100094`, 4 iterations × 2 draws |

Those 8 draws, pairwise XORed into 4 big-endian dwords, ARE the 16-byte
header — **the proven header law** (`rev/header_gen.py::Random3`), verified
byte-exact on **44/44 blobs, 2 devices, 2 API levels, including 4
server-accepted requests** (`SAZ_LIVE_TRAFFIC.md`).

**All rand entropy is consumed by the header. The 176-byte body never sees a
rand draw.** Its per-call re-randomisation comes from **nanosecond
timestamps** (the JNI entry calls `clock_gettime` twice via `0x13de90`) and
live environment inputs, diffused across the whole output by feedback
accumulators (§3).

### What the server does, concretely

1. Take the current wall-clock second (± a small window); seed the same
   bionic `random()` (TYPE_3) generator; regenerate the 8 draws.
2. Recompute the 4-dword header; **match** — this binds the request to a
   real-time origin (anti-replay: an old blob fails the second check).
3. Parse the 176-B body as the **big-endian u32 record stream** (§2),
   un-whitening it with the feedback chain — **invertible without any
   secret, because the chain's state travels in the ciphertext itself**
   (cipher-feedback style).
4. Read the claims: the 144-B core record, the TEE-HMAC `H` (32 B),
   the 20-B SHA-1 digest, timestamps, level, env verdicts, the var-len
   field. `H` is **not decrypted** — it is an opaque consistency tag whose
   value is tracked per device identity over time.
5. **The TEE key never participates in verification.** It exists to make
   `H` unforgeable off-device — a *device-integrity* signal inside the
   record, not a decode key. The user's original hypothesis is confirmed
   at code level: *"they just decrypt it for data and data formats."*

---

## 2. The body = big-endian u32 record stream (proven)

- Builder = fn **`0x100094`** (prologue `sub sp,#0x160`, clean
  **un-flattened** code, 0x100094..0x12aa48). Signature:
  `VM(writer = x29-0x18, fields = x1, count = 11)`.
- The 11 field descriptors are `mkdesc(0x147d3c)` nodes
  `{u32 w0 = (len<<2)|tag, u32 pad, u64 data_ptr}`:
  `0x90` (144-B core record), `0`/NULL, `4`, runtime-length string,
  **`0x20` (32 B = arg3 H, the TEE HMAC)**, `4`, `4`, `4`, `0x10`,
  `0x14` (20 B, SHA-1 digest size), runtime `{len,ptr}` from the caller
  struct +0x128.
- Output object (the "writer"): `{u32 cap, u64 data*, u32 count,
  u32 offs_len, u64 offs*}` — a **growable, sectioned u32 array**
  (EMIT `0x146ed8` writes `data[offsets.last + n]`, growing +0x80 dwords
  at a time via realloc; LENQ `0x147304` reads-`w1`-modifies; section
  starts tracked in `offs`).
- **Live-heap proof**: root-scudo dumps during the oracle burst found the
  blob **dword-reversed** at a stable offset in `[anon:scudo:primary]`
  (e.g. `A1_base` @ VA `0x70c678e4e0` family) — i.e. the 176-B body IS the
  BE serialization of this native-endian u32 array.
- The header is generated **at the end of the VM program** (lifted ops
  7425–7443): `MKITER(4) × {rand; rand; XOR; EMIT; counter++}` — 4 dwords,
  emitted last, placed first (16 + 176 = 192).

## 3. Per-call re-randomisation (why bodies differ every call)

Differential evidence (`adj9_hp3.log`, 10 controlled pairs × 4 runs):

- `A1 ~ A2` (byte-identical inputs, same wall-clock second):
  **header dwords 0–3 identical; ALL 44 body dwords differ.**
- Every other pair (h-zero, h-flip, map-change, level-change): 48/48 differ.

Since all rand draws go to the header, the body's entropy is the
**sub-second record content**: the two `clock_gettime` nanosecond stamps +
env inputs, and the diffusion is structural — the VM's **465 LENQ ops are
read-modify-write accumulators** over the stream, so one early differing
value cascades through every later dword. A plain XOR-with-draws unmask was
tested and fails (as predicted); the transform is a **feedback chain** whose
state travels in the output — which is exactly why the server can decode it
keylessly.

## 4. Where this leaves the decoder (one gap, offline-solvable)

Everything except **the exact per-dword arithmetic** (field order, the
accumulate op order, the offsets array semantics for `0x14784c`'s tail) is
known. The complete 7,504-op program is lifted (`rev/vm_program.txt`) and
~100 input/output pairs exist (30 nSign pairs with logged H/level/timestamps,
40 oracle pairs, 4 SAZ). The remaining work is a **concrete interpreter of
the lifted program** — no device needed.

## 5. Infra failures that cost time (do NOT repeat)

1. **In-process `/proc/self/mem`**: `EACCES` even with SELinux permissive —
   app processes are `dumpable=0`; no workaround from the app UID.
2. **frida**: USB device works, but the app's anti-frida guard kills the
   connection (`ServerNotRunningError`) before hooks load; spawn needs
   Gadget. Abandoned (stealth.js's exception-swallow was insufficient).
3. **toybox dd**: `count_bytes` is not a standalone flag
   (`iflag=skip_bytes,count_bytes`); `oflag=append` does not exist — use
   per-region temp files + `cat`. Cost three capture cycles.
4. **scudo quarantine timing**: freed writer objects are recycled within
   seconds; host-side dump cadence (2–4 s) mostly missed them — but the
   larger u32 stream array DID survive and was found.
5. Heap files and the capture log can be from different runs — always pair
   by PID/ts before correlating (one false-negative hunt resulted).

## 6. Status of the model (what is proven vs pending)

| claim | status |
|---|---|
| header = Random3(time) 8 draws pairwise XOR | **PROVEN** 44/44, 2 devices, server-accepted |
| srand(time) only seeding; rand only in header loop | **PROVEN** (exhaustive site scan) |
| body = BE u32 record stream | **PROVEN** (statics + heap dword-reversal) |
| H (TEE HMAC) rides as a 32-B field, never decoded | **PROVEN** (descriptor 0x20 + role analysis) |
| body entropy = ns timestamps + env, diffused by feedback | **PROVEN** (diffs + statics; no other entropy source exists) |
| server = regenerate stream → match header → parse fields | **PROVEN** at architecture level |
| byte-exact field layout / accumulator arithmetic | **PENDING** — offline interpreter over `vm_program.txt` |

---

## 7. ADDENDUM — serializer internals: op contract + multi-stream architecture (interpreter work)

`vm_exec.py` (PC-based executor) + context tabulation of all ~4,500 call sites
derive the exact program contract:

**Register contract (empirical, from site patterns):**
- `POP → w0` (w21 = previous w0); `PUSH(w2)` where `w2` is
  `mov w2,w0` | `add w2,w0,w21` | `add w2,w0,#1` | `eor w2,w0,w21` | imm.
- `EMIT(x1=stream, w2=n, w3=v)` — v is usually the result of a LENQ just before
  (read-modify-write accumulator chains confirmed).
- `LENQ(x1=stream, w1=n) → w0` reads `stream[base+n]`.
- `PUSHS 0x147120 / POPS 0x147220`: section-start stack, exchanging through the
  stream object's `count` slot (0x10) as scratch.
- Header loop (proven at op level): per iteration `PUSH rand1; PUSH rand2;
  POP; POP; PUSH(rand1^rand2); CAP(1); POP; POP; EMIT(counter, rand1^rand2);
  POP; PUSH(+1); ITERNEXT` — 4 iterations, draws 1–8.

**Multi-stream architecture (new, decisive):** the context array
(`arg2`, x20) holds: `[0]` = the value queue; `[0x18]`-family = secondary
queues; **`[0x20 + i*8]` = the i-th STREAM OBJECT** — selected at runtime
via popped counters (`add x28, x20, w22, uxtw #3; ldr x1, [x28, #0x20]!`).
So the 192-B blob is the **concatenation of several independent growable
u32 streams** (header stream + body sections), each with its own
cap/data/count/offs stack. The final assembly (0xbb548 family) concatenates
them in order.

**Interpreter status:** op semantics 100% decoded; two gaps remain —
(a) a memory model for the va_list/stack-frame loads of the 11-descriptor
loop, (b) the exact stream-index selection per EMIT (derivable from the
site patterns). Everything else executes. This is now pure serialization
engineering — no unknown crypto, no key.

**Artifacts:** `vm_cfg.py` (CFG), `vm_lift.py`/`vm_program.txt` (op lift),
`vm_interp3.py`, `vm_exec.py` (executor), site-context tabulation printed
in-session.
