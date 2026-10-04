# Wall A - slice 67: workspace anatomy + small-tail prediction (2026-09-11)

## MAIN offs at end of staged walk: 29,288 entries, TWO nonzero

`(25, 29263)`, `(36, 54)` - everything else zero. Merge EMITs with small
idx land in-range but carry placeholder zeros; big-idx writes drop (4M
cap; native: malloc-grow or fail, unobserved). X (header) values go to
DATA (append path), never to offs - LENQ reads offs, so X never feeds
back by construction (payload vs workspace split).

## Small-tail prediction (falsifiable, structural)

Native scudo heaps measure 17-26 MB (never GBs) => merge idx values stay
bounded => field/MAIN tails feeding idx math are SMALL ints (counters,
lengths, indices, checksums), not hashes/digests. Real H/SHA1 tails are
random-huge, so EITHER those streams are never idx-sources (only H/SHA1
*values* travel, via v-slots and queue, never as TOP), OR native grows
boundedly per call. Test when resim reaches live LENQ: tails small
< 64K.

## Depth vs value separation (final form)

Depths are op-count-fixed (values irrelevant); routing is value-driven;
content flows through values. The three axes are now independently
monitored (depth census, dispatch census, overlap). No experiment left
that mixes them up.
