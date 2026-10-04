# Wall A - slice 79: Option C — pure-Python trace replay, 44/44 + 4/4 (2026-09-13)

## What was done

`rev/trace_replay.py` (new): loads `device/whcap_hits7.json` (39,673 EMIT
records with sink/pos/val), applies them last-write-wins per (sink, pos)
into plain dicts — no emulator, no descriptor inputs, no #0 needed —
then reads the output sink `…f52fd970` window [0..48) against the paired
live blob (ts 1789240514238, `device/blob_whcap.json`, extracted from
`device/adj9_wh4.log`).

## Result

- header [0..4): **4/4**
- body [4..48): **44/44**

## What this proves and what it doesn't

- Proves: the EMIT trace is complete and sufficient — every body dword is
  present verbatim in the captured (sink, pos, val) events, and the output
  window mapping [0..4)/[4..48) is exact. Independent re-confirmation of
  slice 78's envelope map on a second artifact pair.
- Doesn't: replace from-inputs recompute — the trace *contains* the merged
  values rather than deriving them from claims + #0. The #0 gap (Option A)
  stands as the remaining item for claims-to-blob verification.
