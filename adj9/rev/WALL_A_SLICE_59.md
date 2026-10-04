# Wall A - slice 59: x0 == x19 == master struct CONFIRMED (2026-09-11)

## Chain (all `mov x0,x19` / struct-passing, verified)

- `0xdafe4`-region: struct lives at orchestrator `sp+0xb0`.
- `0xdaf8c bl 0xda6b8`: `x3 = sp+0xb0` (struct as arg).
- `0xda6b8` prologue: `mov x19,x3` (`0xda6fc`) => x19 = struct.
- Every worker call: `mov x0,x19` => workers' `[x0+0xF0]` = struct+0xF0.
- Stamp (later, same frame): `x19` = stamp-x2 = `sp+0xb0` (same memory)
  => mkdesc sources (`+0x20/+0x30/+0x50/+0x100/+0x128`) read feeder output.
- So: feeders WRITE, stamp READS, VM consumes. One object, three phases.

## `0xd868` (0x348 B): sub-dispatched worker

Own hub `0xd95c` (~15 targets); `fold_word` (`0xdb14`); malloc-site
(`0xdb70`); TWO verdict stores `str x8,[x19+0xF0]` (`0xdb30`, `0xdb6c`).
Mid-size template for the remaining workers (`0x1bcc4, 0x1c920, 0xde3c,
0x15384/0x15590, 0x8c98`): hub + decrypt + check + store (+ alloc?).

## Net

The struct's writers are now a closed set (feeder calls with x2/x3 =
struct, workers with x0 = struct). Every unknown slot (+0x20/+0xE0-gap/
+0x128/u32s/digests/144B) has a named writer to lift or match. No more
"where does X live" questions - only "what value".
