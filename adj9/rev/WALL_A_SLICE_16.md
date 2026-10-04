# Wall A — slice 16: EMIT dual-mode proven + in place (2026-09-11)

## 1. EMIT `0x146ed8` exit blocks (all verified, args `x0=writer x1=stream
w2=n w3=v`, frame saves `w2→[x29−0xc]`, `w3→[x29−8]`, `x0→[sp+8]`)

| block | action |
|---|---|
| `0x14701c` | `[stream+0] = count` (limit init) |
| `0x14703c` | **STORE** `v → x23[w20]`, `x23=[stream+8]` (workspace buf) |
| `0x147054` | writer error: `[writer] = 2` |
| `0x147074` | **GROW**: `x0 = malloc(x23)`; `[stream+8] = new` |
| `0x1470b8` | **ACC**: `[stream+0x10] = w20+1` |
| `0x1470d4–0x1470fc` | index math: `w8=count−1; TOP=data[w8]; w20=TOP+n; cmp w20,w27; csel-lo route` |
| `0x147100` | epilogue → `ret` (`0x14711c`) |

So: `idx = data[count−1] + n; buf[idx] = v; acc = idx+1` (buf = `[+0x8]`),
malloc-grow on demand, error 2 on alloc-fail. Read/write pair coherent with
LENQ (`offs[TOP+n]`, slice 14): the workspace table is `[+0x8]`, indexed by
data-TOP-relative values. `vm_final.py` implements exactly this as MERGE
mode (plus acc sync); the `+0x80`-dword realloc quantum (slice 6) is the
only unmodeled detail (approximated by list extend).

## 2. INIT vs MERGE discriminator (regression caught and fixed same session)

First attempt (`fresh ⇔ data empty`) broke the field loop after emit #1
(streams collapsed to 1 dword — caught by the 62/62 check before anything
was documented). Correct rule, now in code: **INIT ⇔ `n == len(data)`**
(append position). Field loop always appends (`j = 0..len−1` into an empty
stream); merge passes computed positions. Field stage re-verified 62/62
(36+0+1+1+8+1+1+1+4+5+4) after the fix.

## 3. State

Merge still exits clean at step 1253 (`nrand=0`) — unchanged, expected:
with placeholder inputs the value dispatch (`0x100554+`) takes edge paths
and drains (slices 10/13). Emulator-side primitives are now complete and
proven: PUSH/POP/isEmpty, LENQ (exact), OUTLEN (exact), EMIT dual-mode
(exact store/acc/grow-shape), MKITER/ITERNEXT, header loop. Remaining is
inputs (7 payloads + ns, R4) + `0xbb548` concat order. No regressions:
`verify_saz_like_server.py` still 114/114 (untouched).
