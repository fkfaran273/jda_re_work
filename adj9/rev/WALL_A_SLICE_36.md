# Wall A - slice 36: staged walk to header loop + sustainment limit (2026-09-11)

`_forcereg` in vm_final.py (set register BEFORE insn at pc; persistent).

## Staged route (all INJECTED): 500 -> 700 -> 800 -> 700 -> 742

| stage | pc | forced | effect |
|---|---|---|---|
| dispatch | 0x100570 | w0=500 ([415,894)) | routes toward 0x100bd8 region |
| gate 1 | 0x100830 (cmp) | w0=700 (in [639,894)) | takes b.hs toward 0x100bd8 |
| gate 2 | 0x100BD8 (cmp) | w0=800 (>=725) | takes b.hs toward 0x101300 |
| gate 3 | 0x101300 (cmp) | w0=700 (<809) | takes b.lo into gateway |
| gateway | 0x128EEC (cmp) | w0=742 EXACT | b.hs taken AND b.ne fallen (both doors verified: 742 and 725 pass; all else loops back) |

Result: 0x12a1f8=1, 0x12a200=1, 0x12a2ec=1, 0x12a2f8=1, nrand=2 (dies 5th
pop as established). Earlier placement bug documented: forcing AT the
branch (0x100834) is too late (flags set at the cmp) — force at CMP pcs.

## Sustainment (persistent zeros at header POPs): 1372 -> 11341 steps

64 seeder passes consumed, nrand stuck at 2, header entered exactly once.
Later passes route seeder-direct (their dispatches differ; staged values
apply only along the forced pass's path). Conclusion: one-shot forcing
cannot sustain; every pass must route on live values. The harness reaches
all stages on demand; supply (R4) remains the only sustainable driver.

## Net

Full staged path proven executable end-to-start-of-header with exact gate
values (500/700/800/700/742). Remaining: natural routing per pass (real
workspace) + queue supply in-loop (real LENQ hits). Monitor: gateway hits
without forcing; nrand > 2.
