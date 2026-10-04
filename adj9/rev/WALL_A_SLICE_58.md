# Wall A - slice 58: workers are verdict-bit setters (2026-09-11)

Seven smallest workers lifted (all straight-line, no maze):

| worker | body | verdict bits ORed into `[x0+0xF0]` |
|---|---|---|
| `0xde24` | — | `0x10000000200` |
| `0xe3a8` | — | `0x20000000000` + `0x80<<48` |
| `0xee74` | — | `0x40000000000` + `0x100<<48` |
| `0xf9b4` | — | `0x80` + `8<<48` |
| `0xe374` | `fold_word(x0+0x20, 0x37)` then | `\|= 1` |
| `0xee40` | `fold_word(x0+0x20, 0x38)` then | `\|= 1` |
| `0xddf0` | `fold_word(x0+0x20, 0x34)` then | `\|= 1` |

Pattern: decrypt marker strings (fold over `x0+0x20` table) -> run the
check -> set verdict bit(s). `x0` = the worker object (CTX-ish).

## Mapping + clean-device bound

`[x0+0xF0]` with `x0` = master struct = `x19+0xF0`: inside the +0xE0 gap
(+0xE0..+0x100), 8 bytes. On a CLEAN phone (moto g42: no emulator, no
Xposed-visible test rigs... though LSPosed IS present - instrumentation
markers likeдиректор Robotium/Appium absent; emulator markers absent),
emulator/test-framework checks come back NEGATIVE. Whether negative sets
or clears its bit needs each worker's condition (still lift-owed), but the
space is now BITS not BYTES: the verdict word is near-zero with few bits.

## Next

Bigger workers (`0xd868` 0x348, `0x1bcc4` 0x550, `0x1c920` 0xb24,
`0xde3c` 0x538, `0x15384/0x15590`, `0x8c98` 0x9c4) + each worker's fire
condition (which env read gates it) + confirm x0 == x19-struct (which
`x8,[sp]`-style arg at the dispatch sites). Then #0's env segments stop
being-opaque.
