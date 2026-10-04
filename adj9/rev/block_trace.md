# block_trace — provenance of `record[46:78)` in the adj9 signature

Target: the 32-byte block of the 144-B pre-whitening **record**.

```
record = 144 B, first-write low bytes of stream 0x5450001000 @ [1134 .. 1278)
block  = record[46:78)  ==  stream 0x5450001000 @ [1180 .. 1212)
```

Row 7 of `all_signings.json` == `pair_h3.json` `i=7` (the `second` of that
pair, `second = 1789240512`).  Tool: `fin_vm2.FinEx` (forward VM), driven by
`block_trace.py`.

Reproduce:

```
python block_trace.py            # pass 1 (emit inventory) + pass 2 (provenance)
python block_trace.py --pass1    # pass 1 only, ~16 s
```

Outputs: `block_trace.json`, `block_trace_slices.txt` (per-byte chain),
`block_trace_window.txt` (annotated disassembly of the window),
`block_trace_blops.txt` (every VM primitive op in the window),
`block_trace_lenq.txt` (every LENQ), `block_trace_emits.txt` (writes to the range).

Baseline run: `status=exit-clean`, **9,871,985 steps**, 8 RAND draws, 21,542
EMITs into stream `0x5450001000`, ~16 s.

---

## Result in one line

The block is **not computed** — it is a **byte-for-byte copy** of 9 dwords
that the VM had already written into the *same* stream earlier:

```
block = BE(M[11])[2:4] ++ BE(M[12]) ++ BE(M[13]) ++ ... ++ BE(M[18]) ++ BE(M[19])[0:2]
M[i]  = dword i of stream 0x5450001000 as of VM step 2828853
```

verified byte-exact by `block_trace.py` (`block_formula_ok: true`, and the
same relation holds for all 100 bytes of `record[44:144)`, 0 mismatches).

---

## (a) Which ops write there

Exactly **one** op writes the block: `EMIT` (`bl #0x146ed8`, pc `0x119538`),
one EMIT per byte, 32 EMITs.

| | |
|---|---|
| op | `EMIT` — `bl #0x146ed8` (pc `0x00119538`), 32 calls |
| stream | `0x5450001000` (`TOP = 620`, so `n = 591 … 560` → `idx 1211 … 1180`) |
| value | one byte per dword: `0x0000000c … 0x000000cb` (only the low byte set) |
| steps | `2829360 … 2835696`, ~184 steps apart, **descending index order** |
| record | `1211→1210→…→1180` = `record[77] → record[77-1] → … → record[46]` |

The whole 144-byte record is produced by the *same* descending loop
(144 first-writes, steps `2815952 … 2845029`, ~202 steps/byte); the block is
the 32-iteration slice `1211 … 1180` of it.

There are **1,744** EMITs into `[1180,1212)` over the whole run (steps
`2829360 … 5818455`). Only the **32 first writes** count — the record is
first-write-wins (same rule `_rec_probe.py` uses). The other 1,712 are later
scratch re-use of the same stream slots (the stream is a rolling workspace;
`MAIN[341…]` is later reused for the 176-byte body).

Ops in the per-byte loop body (all on queue `0x5400000000`):

```
POP                      -> w21 = W        (the 32-bit source dword)
POP                      -> w0  = S        (shift 0/8/16/24)
lsr  w2, w21, w0         ; PUSH w2        (the extracted byte)
CAP_PUSH k=5 ; POP       -> w21 = n        (the emit slot index)
POP                      -> w3  = byte
EMIT(stream, n, w3)
```

`POP = 0x147734`, `PUSH = 0x147630`, `CAP_PUSH = 0x14784c`,
`CAP_SWAP = 0x147a20`, `ITERNEXT = 0x146650`, `LENQ = 0x147304`.

## (b) Which inputs contribute

Per byte: `byte = (W & mask) >> S`, then the *same* `W` reused for the other
three byte lanes.

| record idx | byte | `W` (masked) | mask | `S` | source dword `W` | from |
|---|---|---|---|---|---|---|
| 1211 | `0c` | `000c0000` | `00ff0000` | 16 | `c60c05e3` | `LENQ(MAIN,19)` |
| 1210 | `c6` | `c6000000` | `ff000000` | 24 | `c60c05e3` | `LENQ(MAIN,19)` |
| 1209 | `96` | `00000096` | `000000ff` | 0 | `5eeea896` | `LENQ(MAIN,18)` |
| 1208 | `a8` | `0000a800` | `0000ff00` | 8 | `5eeea896` | `LENQ(MAIN,18)` |
| 1207 | `ee` | `00ee0000` | `00ff0000` | 16 | `5eeea896` | `LENQ(MAIN,18)` |
| 1206 | `5e` | `5e000000` | `ff000000` | 24 | `5eeea896` | `LENQ(MAIN,18)` |
| 1205 | `6b` | `0000006b` | `000000ff` | 0 | `d990ac6b` | `LENQ(MAIN,17)` |
| … | | | | | | (pattern repeats: 4 lanes × 1 dword) |
| 1181 | `6a` | `0000006a` | `000000ff` | 0 | `bd04cb6a` | `LENQ(MAIN,11)` |
| 1180 | `cb` | `0000cb00` | `0000ff00` | 8 | `bd04cb6a` | `LENQ(MAIN,11)` |

Full per-byte table in `block_trace_slices.txt` / `block_trace.json:per_byte`.

Contributing inputs, in order of depth:

1. **`LENQ` (0x147304) on stream `0x5450001000`** — pc `0x0011930c`, at
   `bl`-sites `2828853, 2829668, 2830483, 2831298, 2832113, 2832928,
   2833743, 2834558, 2835373` — reading `n = 19,18,17,16,15,14,13,12,11`
   (descending, 815 steps apart). Values:

   ```
   n=19 c60c05e3   n=18 5eeea896   n=17 d990ac6b   n=16 70b93697
   n=15 7253dc2d   n=14 96c9aa0a   n=13 8622426f   n=12 72a2bc41
   n=11 bd04cb6a
   ```

   These LENQs *are* the root `PUSH` of each source dword (the
   `PUSH` immediately after each `LENQ` is the one the byte ultimately pops).
   Same values are also read by two earlier code sites (`pc 0x102d7c` with
   `n=352…360`, and `pc 0x12187c` with `n=11…19` at steps `2812590…2812710`).

2. The stream slots `MAIN[11..19]` — written long before (first writes at
   steps `2334 … 13413` and re-written many times; the same values are also
   present at `MAIN[352..360]`).

3. Nothing else. No descriptor word, no `RAND`, no queue-carried hash state
   participates directly. `nrand = 8` for the whole run and none of the 8
   draws is in this chain.

## (c) Can the block be computed without the full VM?

**No — not as a closed form, and not without running the VM (or an exact
re-implementation of it) up to step ~2,818,853 (28.5 % of the 9.87 M-step
run).**

What *is* computable without the VM is only the last hop, and it is pure data
placement, not arithmetic:

```
block = be32(M[11])[2:4] + be32(M[12..18]) + be32(M[19])[0:2]
```

Reasons there is no shorter formula:

* The 32 bytes carry **no transformation** — no hash, no mixing, no
  derivation. They are an exact `LENQ` re-read of memory the VM already owns.
* The source window `M[11..19]` is itself a **self-reference of the record**:
  `record[44 + 4j + i] = byte i of BE(M[11+j])` holds for all
  `j = 0…24, i = 0…3` (all 100 tail bytes verified). So the record tail is a
  re-serialisation of a staging copy of itself. There is no upstream "seed"
  formula to collapse.
* That staging copy is assembled by the VM's earlier phases: the bytes are
  written **one at a time** into `MAIN[341…376]` as `byte << 24`
  (e.g. `idx 341 = 0x01000000`, `idx 352 = 0xbd000000`, `idx 360 = 0xc6000000`,
  `idx 374 = 0x0e0e0e0e`, at steps `2743472 … 2813577`, ~1,988 steps apart)
  and later merged into whole dwords at `MAIN[11..35]`. The 4 byte-lanes are
  written by different code paths at different times, so even the staging
  step needs the VM.
* Consequently `M[11..19]` is a function of everything the VM computed in
  steps `0 … 2,818,853` — claims string, region descriptors `#0/#2/#4/#9/#10`,
  `Random3(second)`, etc. Short-circuiting it means re-implementing the VM.

Practical consequence: a forger can only shortcut this by re-using the
existing `fin_vm2.FinEx` execution (≈16 s/row) or by lifting the whole
record-assembly phase — there is no block-level shortcut below that.

## (d) The formula

Immediate formula (verified, `block_formula_ok: true`):

```python
import struct
def block_from_main(M):                      # M: dict idx -> u32 of stream 0x5450001000
    be = lambda n: struct.pack(">I", M[n] & 0xFFFFFFFF)
    return be(11)[2:] + b"".join(be(n) for n in range(12, 19)) + be(19)[:2]
# -> cb6a72a2bc418622426f96c9aa0a7253dc2d70b93697d990ac6b5eeea896c60c
```

Generalised to the whole record tail (`block_trace.py` verifies it):

```python
record[44 + 4*j + i] == (M[11 + j] >> (24 - 8*i)) & 0xFF     # j = 0..24, i = 0..3
```

Byte-lanes are consumed in the order `i = 1,2,3,0` per dword (i.e. the record
is serialised **descending**), which is exactly the descending EMIT order
observed in (a).

---

## Method notes / gotchas

* `FinEx.run` keeps a FAST dispatch path and only calls `_step_hook` when
  `_fast` is false, so a naive hook turns a 16 s run into a multi-minute one.
  `block_trace.py` rebuilds `FinEx.run` from its source with two textual
  edits (force `_fast = True`, gate the hook on a step window). Same
  interpreter, ~18 s for a 66,736-step provenance window.
* The hook fires at the **top** of step `S`, so a register change seen there
  was produced by the instruction at `S-1`, address `pc-4`. Getting this
  wrong attributes every def to the wrong instruction.
* The first hooked step must not be diffed — the window opens mid-execution,
  so its state is not the product of any in-window instruction.
* `EX.st` writes: **0** in the window. The record path is pure queue/stream
  traffic; it never touches the fake memory heap.
* Window `[2769360, 2836096]` is sufficient — no def of any block byte falls
  outside it. Op histogram in-window: `POP 4752, PUSH 3405, LENQ 437,
  CAP_SWAP 933, CAP_PUSH 975, CAP_PUSH0 375, EMIT 414, ITERNEXT 211,
  MKITER 34, PUSHS/POPS/OUTLEN/ISEMPTY 8 each`.
* `all_signings.json` row 7's `#0` region (`d0`) is the synthetic repeating
  pattern from `mint_pipeline`/`F.py`, not a real device region, so the block
  is not a transform of `d0`/`d2`/`d4` (checked: no occurrence in `d0`,
  `d2`, `d4`, the 176-B body, or the 192-B blob).
