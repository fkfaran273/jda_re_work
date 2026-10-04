# Wall A - slice 51: natural header + full walk + content verdict (2026-09-11)

## Natural header (NO injection): kv-interior + steered tail + prelude supply

- 18,735 steps, nrand 8, gateway naturally hit, header loop 4 iters.
- 4 EMITs = B1's header `654cf950/6f5b664b/46977544/1fd8fcf7` EXACT
  (`r4_nat.py`, kept). First fully-natural header reproduction.

## Full walk (chained [742,400] + staged gates + supply)

- 37,189 steps, nrand 16 (header TWICE), workhorse 44, writer clean.
- Streams at ret: fields intact (real H/SHA1), MAIN accumulated.
- Body-44 overlap vs B1: **0**. Header overlap in this run: 0 (kv content
  buries X differently than zeros - supply fragility per slice 48).

## Verdict

Control: fully walkable naturally (header) and staged (workhorse).
Values: header bytes emerge given seed (proven twice); body bytes need
true #0 encoding (all ~100 variants flat on overlap). The walk is
STRUCTURALLY complete end-to-end; content correctness is the entire
remainder (then assembly offsets + parse, both mechanical given content).
