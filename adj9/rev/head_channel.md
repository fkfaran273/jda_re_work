# HEAD channel provenance

## Verdict

The register observed as `x2` at `0x14419c` is not a stack slot, PRNG draw, or
wire value.  It is a local 16-bit feedback value in the whitener.  The whitener
starts each call with a caller-supplied index/state and updates that register
from the just-produced whitened halfword.

The variable `d0` head in the device corpus is not produced by a permutation or
rotation of one fixed key multiset.  The available captures have different
lengths and different values (including `0x07` in one row and `0x42/0x43` in
the old rows).  The current `libsigner.so` contains twelve additional calls to
the whitener whose `w1` values are literal VM/interpreter call-site constants.
Those literals explain the stable emulator-era head, but they are not a
schedule-derived table in this binary.

Consequently, the device-varying head is not explained by the local `x2`
register recurrence, nor by a d4 PRNG stream.  It must be selected by a
runtime control-flow/code-path difference (or a different native build) not
present in the traced emulator image.  The evidence does not support checking
it as a fixed multiset, previous-signing continuity, or a pid/tid relation.

## 1. Whitener data flow

`dump_at.py 0x144074 108` gives the relevant ARM64 instructions:

```text
0x1440f0  add   x11, x0, x2, lsl #1
0x144114  strh  wzr, [x11, #0x30]!
0x144118  sub   x7, x15, x9
0x14411c  lsr   w6, w10, x9
0x144120  tst   w6, #1
0x144124  add   x19, x0, x7, lsl #1
0x144128  csel  x6, x14, x13, eq
0x14418c  ldrh  w4, [x19]
0x14419c  eor   w4, w4, w2
0x1441a4  strh  w4, [x11]
0x1441b4  mov   w4, w2
0x1441cc  cmp   x9, #0x10
0x1441d0  mov   w2, w3
0x1441dc  ldr   x19, [sp], #0x10
```

`w10` is the bit mask `(w1 << 1) + 3`, masked to 16 bits at `0x1440c0` and
`0x1440ec`.  For each set bit, `0x14418c` loads a d4-derived halfword into
`w4`, then `0x14419c` XORs it with the current `w2`.  For a clear bit,
`0x1441b4` copies `w2` to `w4`.  At the end of each eight-bit group,
`0x144170` copies `w4` into `w3`; `0x1441d0` copies `w3` back into `w2`.
Thus the effective recurrence is:

```text
k = initial x2
for each selected bit:
    k = source_halfword XOR k       # set-bit path
    # clear-bit path leaves k unchanged
store(k)
```

There is no load from the stack into `x2` in this function.  The only stack
operation in the range is the saved `x19` frame at entry/exit.  The source
halfword is loaded through `x19`, which points into the d4 work area; that is
the source-data dependency, not a hidden key source.

### Caller-supplied initial state

The ordinary 72-call loop is at `0x143a28..0x143a38`:

```text
0x143a28  mov   w1, #0x40
0x143a2c  ldur  x0, [x29, #-0x20]
0x143a30  bfxil w1, w24, #0, #3
0x143a34  mov   x2, x24
0x143a38  bl    #0x144074
```

A trace at `0x143a38` captured 72 calls with:

```text
x1 = 40 41 42 43 44 45 46 47 40 ... 46 47
x2 = 00 01 02 03 04 05 06 07 08 ... 46 47
```

So the first 72 calls have a counter-derived x1/x2 input.  The final twelve
calls are not part of that loop.  They enter through `0x1441e4`, which first
calls the selector at `0x143b20` and then tail-calls `0x144074`:

```text
0x1441e4  stp ...
0x1441f0  mov  w19, w1
0x1441f4  mov  x20, x0
0x1441f8  bl   #0x143b20
0x1441fc  mov  x2, x0
0x144200  mov  x0, x20
0x144204  mov  w1, w19
0x144210  b    #0x144074
```

`0x143b20` returns the selector/index placed in `x0`; that value becomes the
initial `x2` for the final call.  In the traced run the twelve returned
indices were `0,1,...,11`.  This is a register return value, not a stack slot.
The selector does read the context passed in `x0` (the VM work/context area),
but the whitener's `x2` recurrence itself is local register feedback.

## 2. What writes the variable head

The twelve extra calls are issued by twelve separate VM/interpreter call sites.
Their `w1` immediates are visible in the image:

| return address observed at `0x144074` | call-site instruction | `w1` |
|---:|---|---:|
| `0x973ac` | `0x973a4 mov w1, #0x30; bl 0x1441e4` | `0x30` |
| `0x8c4c` | `0x8c44 mov w1, #0x2b; bl 0x1441e4` | `0x2b` |
| `0xde0c` | `0xde04 mov w1, #0x34; bl 0x1441e4` | `0x34` |
| `0xe390` | `0xe388 mov w1, #0x37; bl 0x1441e4` | `0x37` |
| `0xee5c` | `0xee54 mov w1, #0x38; bl 0x1441e4` | `0x38` |
| `0x15560` | `0x15558 mov w1, #0x3b; bl 0x1441e4` | `0x3b` |
| `0x16830` | `0x16824 mov w1, #0x3c; bl 0x1441e4` | `0x3c` |
| `0x152b8` | `0x152b0 mov w1, #0x35; bl 0x1441e4` | `0x35` |
| `0x152ec` | `0x152e4 mov w1, #0x36; bl 0x1441e4` | `0x36` |
| `0x14df8` | `0x14df0 mov w1, #0x2d; bl 0x1441e4` | `0x2d` |
| `0x1b554` | `0x1b54c mov w1, #0x48; bl 0x1441e4` | `0x48` |
| `0xfaa4` | `0xfa9c mov w1, #5; bl 0x1441e4` | `0x05` |

The emulator therefore has a stable current-image head:

```text
30 2b 34 37 38 3b 3c 35 36 2d 48 05
```

This is the source of the era-2 head, rather than a stack slot being reused
between the 72 ordinary calls.  The call sites are in the VM interpreter and
are reached as separate operations; they overwrite the first twelve outputs
(`d0[0..5]`) after the ordinary materialization.

The device-derived values reported in `F_fresh_validation.md` are different:

```text
old pair_h3:       22 2e 42 43 | 44 45 46 47 40 41 42 43
fresh row 0/1:     2b 22 25 2e | 44 45 46 47 40 41 42 43
fresh row 2:       2b 07 22 25 2e 45 | 46 47 40 41 42 43
```

The stable tail is a property of the observed device stream.  The varying head
is not written by the `x2` recurrence at `0x14419c`; it is the sequence of
`w1` values supplied to the final calls.  In this emulator image those values
are static call-site literals.  A real device that emits different values must
be executing a different call-site sequence, a different native build, or a
runtime path that supplies different operands; it cannot be explained by a
changed `x2` stack slot in the shown function.

## 3. Cross-V comparison

`fill_lift.py` records 734 events and 84 whitener calls in every requested V
trace: 72 ordinary calls plus 12 final calls.  The ordinary call shape and the
four 8-bit groups are stable, but the pre-event `x2` stream changes with V
because the d4 source halfwords change with the seed.

The first ordinary call's `x2` values at the three set-bit `eor` sites were:

| trace | first-call pre-event `x2` | final-call pre-event `x2` |
|---|---|---|
| `lift_V+0.json` | `0000 0d0c fd60` | `0000 0d0c 3781` |
| `lift_V+1.json` | `0000 760e c573` | `0000 760e 078e` |
| `lift_V+2.json` | `0000 6648 aed0` | `0000 6648 aed0` |
| `lift_V+3.json` | `0000 7254 10c5` | `0000 7254 10c5` |
| `lift_V+100.json` | `0000 3aba f8b0` | `0000 3aba f8b0` |
| `lift_V+100000.json` | `0000 5a15 73ca` | `0000 5a15 73ca` |

The first key is the call's initial selector/index and is stable; subsequent
keys are the feedback values after XOR with V-dependent d4 halfwords.  Thus
“pre-event key varies across V” does not mean that the key schedule is
V-derived.  It means the same register recurrence is being applied to a
different source table.

The final-call `w1` operands are not taken from these V traces as a changing
random stream.  They are the twelve literal operands listed above.  A
same-image rerun therefore has a stable final-call head even though all of the
`x2` values at `0x14419c` change with V.

## 4. Permutation/rotation test

There is no evidence for a fixed multiset or rotation:

- old and fresh captures have different values (`0x42/0x43` versus `0x07` and
  `0x25`);
- the recovered prefix lengths differ (four values in the old rows, four in
  fresh rows 0/1, six in fresh row 2);
- the current emulator image's twelve literals are neither a rotation nor a
  permutation of the device sequences.

The most defensible description is a variable-length runtime call/control-flow
stream, with a device-stable tail in the observed corpus.  It is not a fixed
set that a server can validate by sorting.

## 5. Server-verifiability verdict

| proposed check | verdict | reason |
|---|---|---|
| Recompute exact d0 head from V/pid/tid | **No** | Device head changes with the call while d2/d4 remain exact; no V/pid/tid law exists. |
| Fixed multiset or rotation | **No** | Captures have different values and lengths; no common multiset. |
| Continuity with previous signing | **No demonstrated law** | Rows can share a head or change it one second later; no deterministic transition or server-visible state is present. |
| pid/tid relation | **No** | d2 pins the seed and refutes the pid term; tid is not consumed on the materializer path. |
| Wire-derived head | **No evidence** | Emulator wire body is separate from descriptor merge; d2/d4 are exact while only d0 head changes. |
| Structural region laws | **Yes** | The known descriptor laws remain checkable (with the emulator/device L3 caveat). |

Therefore a server can validate structural consistency, but cannot justify a
specific variable head from the transmitted material.  A synthetic region
with a chosen head may satisfy the structural laws, but it is not
byte-faithful to a captured device signing.  An exact device-faithful mint
still requires the per-call head from the matching native code path; minting
from `(V, pid, tid)` alone remains unproven and, for the fresh corpus,
refuted.
