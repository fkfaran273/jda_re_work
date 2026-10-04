# Wall A - slice 53: the single allocator is worker-side, not output (2026-09-11)

## Fn `0xa7a54-0xa8ce0` (dispatcher, hub `0xa7adc`, ~40 targets)

- Entry saves x4 to `[sp+0x30]`; the sole NewByteArray (`0xa8324`) takes
  length from that slot.
- Sole caller `0x97e40` passes **`w4 = 1`** (constant!) + five frame slots
  in the `0x97xxx` worker-thread region (near worker spawn `0x95fc4` /
  key list `0x9b6dc`).

## Verdict: NOT the 192-B output allocator (lead withdrawn)

Length 1 (or mode-1 with length derived inside - either way, not
obviously 192). Most likely a worker-thread utility (1-byte sentinel /
mode-selected alloc). The output assembly question returns to `0xbb548`
(concrete-args problem, slice 17-18) + stamp builders `0xba4a8`/`0x9c478`.
Correction recorded; the JNI census itself (slice 52) stands - exactly one
NewByteArray exists, and it lives here, whatever its role.
