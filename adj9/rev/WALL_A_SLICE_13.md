# Wall A — slice 13: stream allocators + struct model (2026-09-11)

## 1. Allocators / call graph (all verified in `libsigner.so`)

- `0x148b90` = calloc (PLT `br`). Direct users: MKDESC `0x147d3c`
  (`w0=1, w1=0x10` → 16-B desc nodes `{w0,w1}`), `0x147f8c`
  (`w0=1, w1=0xa0` → 160-B object), stamp `0x12dc90`
  (`w0=LENQ-result, w1=1` → **count-sized dynamic buffer**).
- Stamp fn `0x12cb74` (1209 insns, 14 `bl` targets): `0x147d3c` ×11
  (the 11 descriptors), `0x147e2c` ×11 in the epilogue (`0x12ddb4…`,
  x0 = streams) → teardown-half; `0x147e84` ×1 (`0x12ddac`) = 4-ptr
  teardown.
- Destructor `0x147e84` frees `[x+0x08]` via `0x1473d8`, `[x+0x10]` via
  `0x146810`, `[x+0x18]` via `0x14647c` → stream ≥ 0x20 B:
  `{+0x0 limit, +0x8 offs, +0x10 acc, +0x14 count, +0x18 data, +0x28 nested}` —
  every slot independently confirmed by LENQ (`+0x14/-1, +0x18, +0x0, +0x8`),
  OUTLEN (`+0x14/-1, +0x18, +0x10`), trampoline `0x147e30`
  (`[x0+0x28] → LENQ`), destructor (frees +0x8/+0x10/+0x18).
- VM call `0x12d39c`: `x0=x29-0x18` (stack writer cell), `x1` = fields array,
  `w2=0xb` (11), `x3–x7` = descs 0–4, rest overflow on stack — matches the
  `vm_final.py` frame model byte-for-byte.
- EMIT-sibling `0x146b68` (via `0x147e3c`: sink + LENQ + emit) and the
  `0x146470/74/78` PUSH/isEmpty/POP trampolines catalogued (slice 9).

## 2. Struct model in `vm_final.py` (`patch_struct.py`, kept)

`StreamObj` now syncs a native-layout struct to fake mem
(`+0x0=0x7FFFFFFF, +0x8/+0x18` derived backing VAs, `+0x10=0, +0x14=count,
+0x28=self`) with data/offs mirrored. LENQ = `offs[TOP_value+n]`
(maze bypass: live exit assumed at `0x1473a0→0x1473d0`, flagged). OUTLEN =
`[+0x10]−data[count−1]` exact (7-insn fn, no maze).

## 3. Result: still exit-clean step 1253, `nrand=0` (why — no surprise)

Field stage intact (62/62). The merge still drains at the value dispatch
(`0x100554+`, routes on queue VALUES `0x2d…0x37e`): with marker/zero
descriptors the popped values take edge paths, and OUTLEN now returns
`0−TOP` (huge) which is pushed as a bogus length downstream. Both failure
contributors are *input* problems (8 unknown descriptor payloads incl. ns
stamps), not newly discovered code problems. The emulator is now
structurally complete through the merge gate; what it needs is real bytes.

## 4. Offline limit reached — order stands

Done offline: header, adj_verification, field stage (real values), struct
model, allocator/call graph, maze entry/exit addresses, golden pack, R1.
Genuinely device-gated from here: R2 (MessageDigest hook → #9), real
descriptor bytes (#0/#2/#3/#6/#7/#8/#10 + ns stamps), then the 38-match and
the claim loop run without further RE. No key is ever needed.
