# Wall A - slice 44: CAP entry decoded, pad exit found, others open (2026-09-11)

## CAP `0x14784c` entry (clean, no maze yet)

```
w8 = [x1]+0 (count); x1 += 8 (now head-ptr slot)
csel x8 = (count > k)u32 ? 0xd282... : 0x09bd...   # two consts
```

then the opaque-const maze (`0x147914` hub) routes on x8.

## Exits mapped (by address, bodies partially read)

- `0x147968`-block: `PUSH(queue=[x29-0x10], value=[x21])` - THE pad path.
- `0x14794c`-block: `str w9=4,[x23]` (writer/status cell write?).
- `0x1479a4 / 0x1479c8 / 0x1479ac / 0x1479e4 / 0x1479f8`: not yet read.
- Return `0x147a14`.

## What this means for the model

My `CAP = pad iff top-huge` (slice 16) fires on the WRONG condition: native
routes on `count vs k`, pad value = `[x21]` (caller/context word, NOT a
per-queue counter). Both the trigger and the pad value in my model are
guesses; the header-loop behavior (len=X vs len=pad) hinges on exactly
this. The maze exits need the const-flow treatment (same as LENQ slice 14:
all compare consts, enumerate live exits). Bounded and named; not done.

## Standing corrections

- Slice-16 CAP model: trigger wrong (top-magnitude) and pad wrong
  (per-queue seq). Keep until replaced - it reproduces the 1-hit header
  placement shape but not values/counts.
- Fetch-order finding (slice 43-era): native fetch sequence is FIXED across
  signings (first10 identical) and NOT map order - the claim-iteration
  program is hardcoded, order known exactly (fetch_seq.json).
