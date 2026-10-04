# Wall A - slice 35: header sustainment - supply feeds passes, re-entry needs OUTLEN (2026-09-11)

## Experiments (`r4_supply.py`, persistent `_preload` in vm_final.py)

| supply | steps | nrand | maxpc | result |
|---|---|---|---|---|
| none (force=742 only) | 1372 | 2 | 0x12a8cc | header attempt, dies 5th pop |
| zeros at loop POPs | 7717 | 2 | 0x12a8cc | longer looping, same death |
| zeros loop+entry | 12549 | 2 | 0x12a8cc | more passes, header never re-entered |

## Findings

1. Preload/refill sustains PASSES (steps 1372 -> 12549, qops scale) but the
   header region (0x12a1f8+) is entered exactly ONCE (the forced pass);
   later passes route seeder-direct. Re-entry needs the gateway path
   (0x101300 -> 0x128eec, OUTLEN >= 742), not more queue depth.
2. Gateway w0 = OUTLEN(selected stream) = acc - TOP with idx = popped
   value selecting the stream: for #0-selected, OUTLEN = acc - TOP#0.
   With acc starting 0, ANY nonzero TOP#0 gives u32-huge OUTLEN >= 742 on
   paper — but the gateway is only reached via cases our runs never take
   twice. The lever is precise: #0's tail (TOP#0) + acc growth set OUTLEN;
   OUTLEN routes at gateway; gateway opens header.
3. Persistent refill identified as pass-sustainer, one-shot preload as
   entry-assist. Both kept in vm_final (`_preload` persistent,
   `_force_val` once). No regressions (default runs unchanged: 1253).

## Next (single sharpest experiment)

#0-tail variants x acc-growth tracking: measure OUTLEN(stream0) +
gateway-pc hits per hypothesis (not blob overlap). First hypothesis to
produce a NATURAL gateway hit (0x128eec pc > 0 without forcing) wins and
becomes the header-loop driver; everything downstream is already walked.

## Addendum - tail battery (same session)

#0-tail variants (kv, tail725/742/big, all725) under shared queue: tail
content steers (1410 vs 1375 baseline; tailbig acts like zeros) but
gateway pcs (0x101300/0x128eec/0x12a1f8) stay DARK in all natural runs.
The gateway path (dispatch -> ... -> 0x100bd8 -> 0x101300 -> gateway) was
never taken naturally; its dispatch-side entry is the next read (which
value routes into 0x100bd8?).
