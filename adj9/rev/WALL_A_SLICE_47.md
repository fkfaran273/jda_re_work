# Wall A - slice 47: depth sweep - transient buffers, no lasting residue (2026-09-11)

## Method

Static: every straight-line block's PUSH/POP net (477 targets; dozens of
+1-net blocks). Dynamic: max queue depth per forced dispatch (16 values).

## Results

- All dispatches: maxdepth 3, EXCEPT 153: maxdepth **188** (the MKITER walk
  buffers transiently, then drains to the same clean exit; 37k steps).
- +1-net blocks exist but every reachable path balances (pushes get popped
  within the same pass/case in placeholder runs).
- Depth ≠ progress: transient peaks don't leave residue; residue needs
  unbalanced-bytes... rather, residue needs trip-counts and case paths
  that only real LENQ/OUTLEN values open (R4 workspace again).

## Standing

The machine's depth dynamics are fully mapped (per-block nets, per-dispatch
maxima, transient vs residue). Nothing in the control or depth domain can
move further on placeholders. The SOLE undecided input class remains R4
content (real #0 encoding -> real TOPs -> real LENQ hits -> real trip
counts/values -> sustained passes -> 48 dwords -> assembly -> parse).
