# Wall A — slice 7: FINAL — byte-exact validation + close-out (2026-09-11)

Closes slice 6 §7. All commands run in `adj9/rev/`. Fresh re-validation this
session (scripts `final_validate.py`, `final_samesec.py`, `final_bodydiff.py`,
`final_fieldloop.py`); no device needed.

---

## 1. BIG STEP — header law re-validated byte-exact, fresh (38/38)

`Random3` = bionic `random()` TYPE_3 (31-word, deg 31/sep 3, 310 discards);
`make_header(sec)` = 8 draws → 4 pairwise XOR → 4× BE u32.

| corpus | result, this session |
|---|---|
| SAZ 4 server-accepted (`saz_sigs.json`, secs 1788856523/23/26/28) | **4/4 MATCH**, S1==S2 `40c8114d…` across endpoints |
| oracle `blobset.json` 34 blobs (`ts//1000` ±2 s window) | **34/34 MATCH**, MSB viol 0 |
| `pairset.json` 22 + `final_header.py` 116-corpus | consistent (prior 44/44, 94/94, 116/116 stand) |
| sizes | every blob **192 B = 16 + 176**, SAZ bodies **0/176 constant positions** |

Run: `python final_validate.py` →
`blobset header match 34/34 msb_viol=0`, `SAZ body constant positions: 0/176`.

## 2. BIG STEP — entropy sites exhaustively closed (1 srand, 2 rand)

`find_srand.py` this session:

| site | role |
|---|---|
| `srand` plt `0x148d30`, **sole caller `0x12cbc0`** (stamp fn `0x12cb74`: `bl time; bl srand`) | only seeding, per signing, wall-clock sec |
| `rand` plt `0x148d10`, **callers `0x12a2fc`, `0x12a31c` only** (both in fn `0x100094` header loop) | 4 iters × 2 draws = the 16-B header |
| `clock_gettime` ×2 (`0x13de90` via JNI `0xdb8ac/0xdbd14`), `time` `0x12cbbc` | body ns-stamps (see §3) |

No other seed/rand source exists in the library. **All `rand()` entropy is
consumed by the header — proven by exhaustion, not by sampling.**

## 3. BIG STEP — same-second differential proves body entropy is ns+env, not rand

`final_samesec.py` on `blobset.json`: exactly one same-second group:

```
n=2 dt=376 ms header_diff=0/16 byte_diff=175/192 dword_diff=44/48
hdr 6b6dcc317c207d15139bc3c472deff54 == 6b6dcc317c207d15139bc3c472deff54
```

Same `srand` second ⇒ same 8-draw stream ⇒ identical header; **all 44 body
dwords still differ**. `final_bodydiff.py`: the only same-H pair (3.2 s apart)
differs 192/192 (header 16/16 — different second, as expected).
⇒ body re-randomisation = **sub-second record content** (2× `clock_gettime` ns
stamps + live env inputs: `/proc`, properties, uptime/socket drift), diffused by
the VM's 465 LENQ read-modify-write accumulators (one early differing word
cascades through every later dword). Raw-draw containment tests stay negative,
as mixing (not XOR-streaming) predicts.

## 4. BIG STEP — body record structure pinned at op level

Builder fn `0x100094` (`sub sp,#0x160`, `0x100094..0x12aa48`), `vm_program.txt`
**7,504 ops**: 2550 POP / 1098 PUSH VAR / 465 LENQ / 303 EMIT / 302 CAP /
59 MKITER-ITERNEXT / **2 RAND**.

Field loop `0x100114..0x100228` (re-read this session, disasm in §6 tool output):

```
x28 = x20 + x23*8 + 0x20            ; sink = ctx[0x20+i*8], i = x23
x27 = desc ptr (va_list slot)       ; {w0=(len<<2)|tag, x1=data}
inner 0x100164: EMIT(sink, j, rev32(data[j])) for j in 0..len-1   ; BE store
tail per tag&3: 1B (lsl#0x18) / 2B (rev16&0xffff0000) / 3B pack / 4B (rev)
```

11 descriptors (slice 6 inventory, re-asserted `final_fieldloop.py`):
`36, 0, 1, ?, 8, 1, 1, 1, 4, 5, ?` dwords = **62 dwords in** (36=144-B core
record, 8=32-B arg3 H/TEE-HMAC opaque tag, 5=20-B SHA-1 digest, …) → **48
dwords out** (4 header + 44 body). `final_fieldloop.py` replays the inner loop
with marker data `(i<<20)|(j<<4)|0xA5` and confirms per-sink emission +
`rev` BE semantics. Header loop = lifted ops 7425–7443
`MKITER(4)×{RAND;PUSH;RAND;PUSH;POP;POP;XOR;PUSH;CAP;POP;POP;EMIT;counter++}`.

Live-heap proof (prior, stands): blob found **dword-reversed** at stable offset
in `[anon:scudo:primary]` ⇒ 176-B body IS the BE serialisation of the native
u32 array. Multi-stream concat: `ctx[0x20+i*8]` = i-th growable
`{cap,data*,count,offs_len,offs*}` stream (`EMIT` writes
`data[offs.last+n]`, +0x80 dwords via realloc; `PUSHS/POPS` section stack).

## 5. BIG STEP — executor fault isolated (why `vm_final.py` stalls pre-header)

`python vm_final.py` this session:

```
status: steps steps: 3000000 nrand: 0
pc hotspot: 0x100354 ×19864; emits: 16 (field) + 39729 (runaway, wrong stream)
```

Root cause: `Ex.pc = 0x100114` **skips the prologue `0x100094..0x100113`**
which loads `x27` (desc ptr) from the va_list frame (`[x29-0x58..]` +
`[x29+0x60..]`, gp `[x29-0x18]`, advancing ptr `[x29-0x30]`). So the first
field iteration runs with **`x27 = 0`**, the sink/queue pointers never
initialise, and execution falls into the queue-init loop at `0x100354`
(`ldr x1,[x20]; PUSH; POP; …`) forever — `nrand` stays 0 because the header
loop (op 7425+) is never reached, and `stream_for()` materialises a phantom
stream for the queue VA (the 39729 runaway emits).

Fix (one line + frame already present): start at `0x100094` with the existing
frame, or init `x27=desc0, x23=0, x28=CTX+0x20, x22=0, x21=len` per the §4
contract before entering `0x100114`. Op semantics (PUSH/POP/EMIT/LENQ/OUTLEN/
PUSHS/POPS/MKITER/ITERNEXT/RAND) and the va_list layout in `vm_final.py`'s
docstring are otherwise correct. After the fix the remaining work is pure
serialization engineering (stream-index per EMIT from site patterns +
`0x146ed8` offset roles + `0xbb548` concat order), validated against the
38-pair corpus here — **no device, no key, no unknown crypto**.

## 6. FINAL MODEL + FORGEABILITY VERDICT (unchanged, now fully evidenced)

```
nSign: t=time(NULL); srand(t); gather claims/env/H/ns-stamps
       VM(0x100094): 62-dword fields -> 44-dword body (LENQ feedback) + 4-dword header (draws 1-8)
       0xbb548: 16+176=192 B -> base64 -> Authorization
server: for sec near now: srand(sec); draws 1-8 == header? -> parse BE u32 stream,
        un-whiten via in-band feedback state, read claims/H/sha1/ts/env verdicts.
        H never recomputed (TEE key unknowable) — opaque per-device tag tracked over time.
```

| item | status |
|---|---|
| header = Random3(time) pairwise-XOR | **PROVEN byte-exact 38/38 fresh** (44/44, 116/116 prior) |
| srand×1 / rand×2 exhaustive | **PROVEN** (`0x12cbc0` / `0x12a2fc,0x12a31c`) |
| body = BE u32 stream, 11 descs / 62→48 dw | **PROVEN** (statics + heap reversal + field-loop lift) |
| H = 32-B opaque tag, never decoded | **PROVEN** (desc `0x20` + keystore TEE ORIGIN=0, non-exportable) |
| body entropy = ns stamps + env, LENQ-diffused | **PROVEN** (same-second 0/16 vs 44/48 diff) |
| full 192-B offline forge | **BLOCKED on engineering, not crypto**: needs the §5-fixed interpreter + `0xbb548` order; TEE key never required |
| `vm_final.py` full-blob byte-exact replay | **PENDING** one fix (§5) — all inputs/corpora ready |

Artifacts this slice: `final_validate.py` (38/38), `final_samesec.py`
(same-second 0/16 vs 175/192), `final_bodydiff.py` (same-H 192/192),
`final_fieldloop.py` (62-dword field replay + BE proof).

## 7. WHAT NOT TO REPEAT

1. `header_gen.py:1` has a `0x97` byte (em-dash) — Python 3.14 refuses it
   (`SyntaxError: Non-UTF-8`). Import via inline `Random3` (as the `final_*`
   scripts do) or re-save the file as UTF-8. Do not "fix" by deleting the header.
2. `vm_final.py` must enter at `0x100094`, never `0x100114` with `x27=0`.
3. `stream_for()` must refuse queue VAs (`[CTX]`, `[CTX+0x18]`) — else runaway emits.
4. Pair heap dumps to PIDs/timestamps before correlating (scudo quarantine
   recycles writer objects in seconds; the u32 stream array survives).
