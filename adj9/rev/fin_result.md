# fin_result.md — from-inputs 44/44(+4) body recompute: SOLVED (2026-09-13)

## FINAL RESULT

Running the corrected executor (`rev/fin_vm2.py FinEx`) over the REAL 11
descriptors (`rev/fin_descs.json`, 147 dwords from the live field capture)
with seed = second = 1789240512:

```
status=exit-clean  steps=9,871,985  nrand=8  emit events=22,272
output sink (slot-0 stream, F0) window [0..48): 48/48 dwords
header 4/4: True      body 44/44: True
emu  blob == target blob 5595c3c431567e63…ab596  (hex-identical, 192 B)
```

The full-signing event stream also matches the native capture:
22,272 emulator events == 22,272 native capture events (signing A of
`device/whcap_hits7.json`); 22,038 have exact (sink,pos,value) twins, the
remaining 234 are intermediate values of byte-assembly chains tainted by
uninitialized native heap memory (see below); the last-write-wins final
state differs in exactly 1 key — output pos 112 (OUTSIDE the 48-dword blob,
same garbage-taint class, byte 3 = 0x61 vs 0x00).

## THE TWO BUGS FIXED (both in the emulator's op model)

### 1. va_order — empty descriptor at va position 8 (fin_extract.py)

The old `VA_ORDER = [0,9,8,4,2,7,10,5,6,1,3]` put #6 (1 dword) at va
position 8 and #1 (empty) at 9. The field capture proves the opposite:

- records 145→146: the va_list overflow pointer x28 jumps `…d748 → …d758`
  (+16) between the slot-7 and slot-8 field runs — an empty descriptor's
  slot is consumed with no EMIT;
- native merge block `0x129220` (from block 0x1cd) computes the 14th section
  length as `OUTLEN(ctx[8])` (constant index 8) — native gets 0 (empty sink),
  the old emulator got 1 (#6's sink) → the "+1 at merge event 194"
  (0xb1 vs 0xb0) and every later position drifted;
- the mid-merge interlude writes 1 dword (0x10) to `2fbcf0` (= the 9th field
  run = slot 9) and 4 dwords to `2fbed0` (= slot 10) — matching only with the
  corrected order.

Fix: `VA_ORDER = [0,9,8,4,2,7,10,5,1,6,3]` (swapped #6 ↔ #1); fin_descs.json
regenerated (lens `[36,5,4,8,1,1,90,1,0,1,0]`). #5/#6 (1-dw zero) and #1/#3
(empty) are mutually indistinguishable pairs, so the choice within each pair
is canonical.

### 2. MKITER / ITERNEXT — the iterator ops were modeled wrong (fin_vm2.py)

Disassembly of the real ops (0x146558 / 0x146650):

```
MKITER(x0=writer, x1=head_cell, w2=n):
    node = calloc(1,16); node[0]=n; node[8]=[x1]; [x1]=node   # push on LIFO
    (calloc failure -> [x0(writer)]=2)
ITERNEXT(x0=head_cell):
    node = [x0]; w21 = node[0] - 1; node[0] = w21
    if w21 == 0: [x0] = node[8]; free(node)                   # pop
    return w21                         # caller: `cbnz w0` loops while != 0
```

The old emulator invented fake iterator VAs with a fallback lookup that broke
as soon as two iterators were live (native keeps them in a LIFO list through a
shared head cell — the program passes the SAME cell to both ops, e.g. the
cell at ctx[0x10]). Consequences of the old model: whitening/copy loops died
after one iteration, later passes read garbage positions, and the run never
terminated (the 8M-step hang). With the correct semantics the run goes
**exit-clean** at 9.87M steps and produces exactly the native event count.

### Also discovered: the "205 merge events" ground truth was truncated

`fin_extract.py seg_merge()` stopped at the first different-sink event. The
real merge phase of signing A is 22,272 EMITs (multi-pass value-routed merge
ending exit-clean); the blob appears on the merge sink at pos 337.. and the
final output is assembled on the slot-0 stream (F0 = 2fd970 = #0's field
sink) whose [0..48) last-write window IS the 192-byte blob.

### Native-only nondeterminism (not a bug, cannot be reproduced from inputs)

The native LENQ readback chain (`write b0<<24; LENQ(pos); |b1<<16; …`) reads
the merge sink's offs array through the realloc capacity bound; cells never
written contain **uninitialized heap tail** which the native ORs into its
INTERMEDIATE events (e.g. event 1595: nat 0x63616b63 vs emu 0x63000000).
Every 4-byte chain completes, so finals are pure — 234 intermediate events
differ this way; the blob is unaffected.

## FILES CHANGED / ADDED

- `rev/fin_vm2.py` — FinStream ops; corrected MKITER/ITERNEXT (LIFO through a
  head cell in `mem`, ITERNEXT returns count-1); added `_step_hook`
- `rev/fin_extract.py` — VA_ORDER fix; regenerated `rev/fin_descs.json`
- `rev/fin_dbg1.py / fin_dbg2.py / fin_dbg3.py` — instrumented runners
- `rev/fin_cmp.py` — full-signing 1:1 event diff (nat_full.json)
- `rev/fin_mapcmp.py` — last-write final-state diff + blob window check
  (fin_mapcmp_out.json: 949 keys both, 1 diff outside blob, F0 48/48)

## VERIFICATION COMMAND

```
python fin_mapcmp.py 20000000 22272
# status=exit-clean steps=9871985 nrand=8 emu events=22272 (native=22272)
# final-state map: native keys=949 emu keys=949 DIFFS=1 (F0 pos=112, non-blob)
# blob window: F0 48/48
```
