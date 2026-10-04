# F lift findings

## Scope and status

This is an offline lift of the native adj9 region transform in
`C:\Users\Apps\Downloads\com.penti.app\adj9\rev\F_vm_candidate.py`. No network,
adb, or tracker activity was used. The candidate now implements the complete
seed-to-region path for the saved native ABI:

- d4: PRNG, native shuffle, pair consumption, and 16x16 transpose;
- d0: the complete 0x144074 whitening/materializer sequence;
- d2: the native combined-seed store and public byte-order conversion.

`region(V, pid, tid)` is no longer reference-backed and does not require a
captured V table.

## Seed and d2

The combined native seed is

```text
S = tv_sec ^ (pid << 16) ^ tv_usec
  = V ^ (pid << 16), where V = tv_sec ^ tv_usec.
```

The d2 producer is the helper call at `0x1437b8..0x1437c4`:

- `0x1437b8` calls the VM seed helper `0x13e0e4`;
- `0x1437bc` loads its 32-bit result into `w1`;
- `0x1437c0` moves the descriptor base into `x0`;
- `0x1437c4` calls the builder at `0x1437ec`;
- `0x14384c` stores `w1` at `0x300000ffd20`.

The stored native word is `S`. The descriptor contract interprets the four
bytes big-endian, so the returned d2 word is the byte-swap of `S`:

```python
d2 = int.from_bytes((V ^ ((pid & 0xffff) << 16)).to_bytes(4, "little"), "big")
```

For the V-only captures this gives the observed `0x00149b5a`, `0x01149b5a`,
etc. The d2 path consumes pid through the seed but not tid. The saved
`lift_pidtid.json` changes pid from 12345 to 12346 and tid from 12346 to 12347;
its d2 is exactly the pid-12346 prediction for the same capture-time
`V=0x6aa21400`.

## d4 slice

The d4 path is:

- `0x1437ec`: builder entry and d4 work area;
- `0x143c88`: 16-byte zero-initialized shuffle;
- `0x13dfd0`: deterministic 31-bit Schrage step;
- `0x1439c4..0x143a1c`: construct 16 pre-transpose halfwords;
- `0x143d98..0x143f68`: 16x16 bit-matrix transpose and d4 writes.

The PRNG step is the positive 31-bit operation previously verified from the
trace:

```python
def step(x):
    if x == 0:
        x = 0x075bd924
    q = x // 0x1f31d
    y = (x - q * 0x1f31d) * 0x41a7 - q * 0x0b14
    if y < 0:
        y += 0x7fffffff
    return y & 0x7fffffff
```

The shuffle is not a normal Fisher-Yates over `range(16)`: the native buffer
starts as 16 zero bytes. For each `i`, it computes `j = r % (i+1)` and swaps
`perm[i]` with `perm[j]`. The output state is consumed in pairs: even outputs
use the high 16 bits, odd outputs use the low 32 bits. The post-transform is a
16x16 bit transpose, and the resulting halfwords are serialized little-endian
into the raw d4 buffer. Public d4 words are then read big-endian.

For V0 (`S=0x5a9b1400`), the final d4 halfwords are:

```text
0001 8001 0003 0041 9042 000a 1060 1802
0260 1428 8672 908b 1854 3a8d f06c 0d0c
```

## d0 materializer

The previously unresolved bridge is now fully identified. The builder VM
repeatedly dispatches to `0x144074` from the state-machine path at
`0x143a28`. The function is a one-word XOR whitener, not a 16-word loop:

1. `x0` is the d2 descriptor base `0x300000ffd20`.
2. The source halfwords are read at `x0 + 0x20 + 2*(7-b)` for each set bit `b`
   of the mask, i.e. from raw d4 bytes `0x300000ffd40..0x300000ffd4f`.
   These are d4 halfwords 8 through 15.
3. The accumulator starts at zero. For every set bit `b` in
   `mask = (2*x1 + 3) & 0xffff`, it XORs source halfword `7-b` and finally
   writes the 16-bit result at `0x1441a4`.

The first 72 calls use `x1 = 0x40..0x47` cyclically and destination halfword
indices 0 through 71. A final twelve-call pass overwrites d0 halfwords 0..11
with `x1` values:

```text
30 2b 34 37 38 3b 3c 35 36 2d 48 05
```

This exactly explains the apparent source overlap: all whitening source
addresses are in d4's second 16 bytes, while the destination advances through
the 144-byte d0 area. The d0 bytes are serialized little-endian as halfwords
and exposed as 36 big-endian descriptor words.

The source halfword producer is therefore the already-lifted d4 transpose at
`0x143f68`; no additional unknown VM state is consumed by d0. The complete
0x144074 call range is `0x144074..0x1441e0`, with source loads at `0x14418c`
and stores at `0x1441a4`.

## Trace alignment and tid result

The earlier large-trace comparison was a real control-flow divergence, not a
record insertion/deletion: both traces had equal record counts, the first
register difference was record 539 at `0x13e610`, and the first PC difference
was record 3648. The first seed difference is at `0x13e628`.

The d0/d2 path has no tid-dependent instruction in the recovered range. This
is also confirmed by the saved pid/tid isolation capture: its d2 and d4 match
the pure-pid prediction, and changing tid alone is not present in the d0/d2
source chain. The candidate intentionally accepts `tid` for API compatibility
and does not use it.

## Validation

The completed candidate was checked against the saved buffers, without
rerunning the expensive traces. Descriptor words were parsed big-endian from
the saved hex buffers.

| saved run | effective V | pid | d0 | d2 | d4 |
|---|---:|---:|---:|---:|---:|
| `lift_V+0.json` | `0x6aa21400` | 12345 | exact | exact | exact |
| `lift_V+1.json` | `0x6aa21401` | 12345 | exact | exact | exact |
| `lift_V+2.json` | `0x6aa21402` | 12345 | exact | exact | exact |
| `lift_V+3.json` | `0x6aa21403` | 12345 | exact | exact | exact |
| `lift_V+100.json` | `0x6aa215e4` | 12345 | exact | exact | exact |
| `lift_V+100000.json` | `0x6aac93a0` | 12345 | exact | exact | exact |
| `lift2_V0.json` | `0x6aa21400` | 12345 | exact | exact | exact |
| `lift_pidtid.json` | `0x6aa21400` | 12346 | exact | exact | exact |

The effective V values above are capture-time values. In particular, the
`lift_V+*.json` files were captured with the earlier harness time base; they
must not be recomputed using the current `emu_8d6f4.py` defaults.

## Structural-law recheck

For all six V-only rows, using the recovered d0 materializer and the unique
four-word repeating tile at `d0[6:10]`:

- L1 passes: `(d0[8] ^ d0[6]) == R || R`.
- L2 passes: `d4[6] >> 16 == R`.
- L3 still fails as `d0[1] == tile[3]` (and d0[1] equals none of the four tile
  words) for all six rows.

This is not a remaining indexing error. The phase search finds the same tile
start at word 6 for every row, and no phase rotation makes d0[1] equal a tile
word. The saved emulator corpus already records L3 as a device-corpus law
(12/13 on device captures, 0/21 in the emulator). The old-harness “era”
difference affects an extra head unit in selected old battery captures, not
the six validated V-only rows or this recovered materializer. Therefore the
correct conclusion is an emulator/device-era discrepancy in L3, not a failure
of the d0 lift.

## Files

- `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\F_vm_candidate.py`
- `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\F_LIFT_FINDINGS.md`
