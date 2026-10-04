# Wall A - slice 48: chained walk, overlap metric corrected (2026-09-11)

## Chained walk (dispatch [742,400] + staged gates + counter supply)

41,573 steps, nrand 8, workhorse 44, 633 emits, writer clean. Streams at
ret: MAIN 787 dwords (handshake + per-pass EMITs), fields intact (real H +
SHA1 rev'd), offs accumulated. Passes: forced header + forced workhorse +
natural seeder tails.

## Overlap metric (body-44 only - header excluded!)

The 4 "hits" vs B1 are B1's OWN header dwords (same second => same
Random3 stream => same draws - trivially matching, not convergence).
Body-44 overlap: **0** across all runs so far. Any future overlap claim
must exclude the 4 header words.

## Counter-supply fragility (important correction)

Slice-40's X-placement (4/4 with zeros body) does NOT survive kv body:
with kv content the header X's vanish from EMITs (buried by shifted queue
dynamics). Placement is content-sensitive - there is no universal supply
pattern; each content needs its own queue-state analysis. The recipe
(CAP-pad + X-as-arg + counter) holds structurally; the supply VALUES must
match the content's flow.

## Standing

Walk harness reaches every stage with any content; structure fully mapped;
values flow per content; body overlap 0 (header-excluded). The remaining
unknown is exactly R4 content correctness (then natural routing +
placement + assembly + parse follow mechanically).
