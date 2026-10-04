# Wall A - slice 70: assembly hub edge map (2026-09-11)

Method: `walk_asm2.py` (x9 := token at hub entry, 30k steps, `_calls` log).

## Edge -> block (all 9 tokens resolve to distinct work)

- x20 -> 0xbb8a0 (char loop; blr 0xbb9c8 x0=0x60)
- x21 -> 0xbb9f0 -> 0xbba7c
- x22 -> 0xbbbc0 -> 0xbbbf4: bl free(0x148a10) x1=0x1000 x2=0x2000, falls
  off 0xbbbf8 (range end - fn longer than mapped!)
- x23 -> 0xbb9f0 -> 0xbba98 (shares head with x21)
- x24 -> 0xbb9b8 (blr 0xbbb84 + 0xbb9c8, x0=0x60)
- x25 -> 0xbb948 -> 0xbb9b8 (blr x0=0x60 x1=0xffffffd8=-40 index;
  shares tail with x24)
- x26 -> 0xbba00 (malloc/len+1 region, slice-17 match)
- x27 -> same as x25 (0xbb948)
- x28 -> 0xbb8fc -> 0xbbbc0 -> free tail (shares tail with x22)

## Shared structure

Heads: 0xbb9f0 (x21/x23), tails: 0xbb9b8 (x24/x25/x27), 0xbbbc0+free
(x22/x28). blr x0=0x60 = repeated JNI-ish indirect call (2 sites:
0xbbb84, 0xbb9c8).

## Blocker for completion

Char-loops spin on fake memory (unmapped reads never terminate
strlen/strcpy). Fix: stock fake string cells with real bytes + extend
INS past 0xbbbf8, then re-walk to ret and log full call sequence.
