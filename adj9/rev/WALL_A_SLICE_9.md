# Wall A — slice 9: server-like verification + forward-VM field stage EXACT (2026-09-11)

User goal: "verify the bodies like the server." Delivered: a runnable
server-style verifier (`verify_saz_like_server.py`, **114/114 PASS** on the
38-blob corpus) + the forward VM's field stage now bit-exact (62/62). The
remaining claim-recomputation step is isolated to the merge fill. No device.

## 1. `verify_saz_like_server.py` — 114/114 PASS

Per blob (34 oracle + 4 SAZ): HEADER(time ±2 s window, byte-exact
`Random3(sec)` 8-draws→4-XOR→BE) + MSB-law (bytes 0/4/8/12 < 0x80) + SHAPE
(192 B = 48 BE dwords). Corpus-level: 0/48 stable dwords;
`adj_verification` const check. This is exactly the server's first gate
(clock bind / anti-replay) plus body well-formedness — the part of "verify
like the server" that is offline-solvable today.

The server's second gate (re-run merge → compare H to per-device history,
digests vs visible request) is NOT yet runnable — it needs the merge fill
(§3). Nothing about that gate needs a key: H is an opaque tag, the merge is
keyless feedback. So the verifier above is the complete server procedure
minus the claim loop.

## 2. Forward VM: 5 emulator bugs fixed, field stage 62/62 EXACT

`vm_final.py` this session (`vm_final.py` = the executor, `dbg_trace.py` =
tracer). Before: 3M-step runaway at `0x100354`, `nrand=0`, 16 field emits
all colliding into sink 0. After: **exit-clean, field sinks 36+0+1+1+8+1+1+
1+4+5+4 = 62/62 marker dwords**, each in its own `ctx[0x20+i*8]` stream.

| # | bug | evidence | fix |
|---|---|---|---|
| 1 | `0x146470/74/78` treated as NOOP | disasm: `b #0x147630` (PUSH) / `b #0x147620` (isEmpty) / `b #0x147734` (POP) | alias to PUSH/POP/isEmpty; `0x10030c PUSH(queue2,17)` now fills |
| 2 | LENQ stream reg `x1` | `0x147304` reads `[x0+#0x14/0x18/0x0]` → stream is `x0` (site `0x100384 ldp x21,x0,[x20]` proves it) | use `x0` |
| 3 | single global queue | two queue VAs `[CTX]` + `[CTX+0x18]`, selected per-op via `x1` | `queues` dict keyed by VA |
| 4 | `add Rd,Rn,Rm,lsl#k` shift dropped | `add x9,x20,x23,lsl#3` computed `CTX+i` not `CTX+8i` → all sinks aliased to stream 0 | apply `lsl/lsr/uxtw/sxtw` to 4th operand |
| 5 | 64-bit flags for `w`-reg `cmp/cmn` | `cmn w8,#8` with `w8=0xFFFFFFD8`: 64-bit says hi=True, native 32-bit C=0 → hi=False → va_list took stack path, field 0 got 1 dword not 36 | 32-bit C/Z/N/V + `hs/lo/hi/ls/eq/lt/ge/gt/le`; `continue` past the 64-bit fallthrough |
| 6 | (also) `header_gen.py:1` byte `0x97` | py3.14 `SyntaxError` on import | `-` |

Also fixed: POP-empty → native writer-error `[x19]=3` (was silent 0 →
infinite loop); runaway became a clean diagnostic (`exit-clean step 734
→ 701 → 1253` as each bug fell).

## 3. Where the merge stops now (exact, next fix)

`dbg_trace.py`: fields done (`x23=11`), merge counter `x22=4`, both queues
drained, exit-clean at step 1253 in `0x1004xx–0x1005xx` after the
`0x1002f8 PUSH(queue2,17)` + `OUTLEN`/`0x146470` prologue and a legitimate
excursion to helper `0x128838`. The fill whose PUSH sequence our
branch/register tracking still diverges is the MKITER/counter loop feeding
that merge POP. After it: LENQ obfuscation arithmetic (constants `0x6dbb…`
at `0x147304`), `0x146ed8` offset roles, `0xbb548` concat — then the header
loop (ops 7425+, `nrand` 8) and the 38-blob byte-exact match.

## 4. Status line

Header-verify like server: DONE (38/38). Body-verify like server:
well-formedness DONE (114/114); claim loop PENDING merge fill (§3) with the
corpus (`blobset.json` 34 + `saz_sigs.json` 4 + `pairset.json` 22 H-paired)
ready. Forward VM: field stage EXACT, merge entered, 5 bugs closed.
