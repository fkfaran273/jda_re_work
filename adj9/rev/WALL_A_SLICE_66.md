# Wall A - slice 66: endpoint-matched resim + pad-masks-top (2026-09-11)

`pair_match.py` (kept? no - one-off; `pairs_tail.json` kept): 4 blobs paired
(H/map/fetch/blob, Hdt -23..820ms). Endpoint runs (own H + own fetched
hashes + cert + level + own second): flat (1375, disp 0).

## Pad zero masks TOP#0

`fq-hc` filled 35 hashes + 4 zero pad bytes: last dword = 0 => TOP#0 = 0
=> OUTLEN = 0 => dispatch 0. The pad HIDES content. Full-36 (values
repeated, no pad): dispatch **0x783acd00**, 1410 steps. Same lesson as
slice-37 tail law, now with real content: last dword rules dispatch#1.

## Standing

Endpoint-matched content moves dispatch (0x0 -> 0x783acd00 -> deeper
case) but pass-2+ still starve (workspace). Every content improvement
moves routing monotonically deeper; none yet sustains. Remaining:
workspace-live passes (real LENQ hits), gateway, header sustainment,
workhorse, assembly, parse.
