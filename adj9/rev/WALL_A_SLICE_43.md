# Wall A - slice 43: refill sweep - 153-case walks 188, counts are POP-fed (2026-09-11)

Dispatch sweep (14 values, `_mkiter` instrumented in vm_final.py):

## Only two dispatches reach list walks

- 153 (==0x99 case): **36,871 steps, MKITER(188) at 0x102058**, writer
  clean, stream total 63 dwords, loop-back exit. Regions 0x100/0x101/0x102.
- 742: MKITER(4) header loop (known).
- Other 12: no walks (short cases, seeder loop-back).

## MKITER counts are POP-fed (data-driven trip counts)

`0x102058` sequence: `CAP; POP; [sp]-load; mov w2,w0; MKITER` - count =
queue POP value (188 from placeholder state here). Likewise header
MKITER(4) (POP-fed, verified 4). So trip counts - and hence queue refill
volume per pass - derive from workspace values. Real workspace -> real
counts -> real refills -> sustained passes. Same R4 root, sharpened from
"values" to "trip counts".

## Scheduler model at scale

36k-step run still exits clean via isEmpty (walk balances push/pop to
zero net with placeholder content). The walk's per-iteration body (EMITs?
stores?) wasn't needed for this conclusion; its NET effect with real
content is the open question (does a real 188-walk leave the queue
nonempty?). Monitor: `_mkiter` counts + post-walk queue depth per pass.
