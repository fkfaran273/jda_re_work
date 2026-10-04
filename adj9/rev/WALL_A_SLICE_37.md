# Wall A - slice 37: dispatch control law + sustainment (2026-09-11)

## 1. Dispatch control law (proven, no injection)

`dispatch#1 = (-rev32(#0-tail)) mod 2^32` in the kv-body configuration
(rev = byte-reverse from the field-loop `rev w3,w8`; negation from OUTLEN
`acc-TOP`). rev is bijective, so ANY first decision is reachable with one
dword: tail `0x9CFFFFFF` -> dispatch exactly `0x64` (100), observed
naturally (`_force_val` unused). Verified: tail sweep 0/1/4/.../192 gives
`0x0/0xFF000000/0xFC000000/...` exactly as the law predicts.

## 2. Preload fix (`vm_final.py`)

`_preload` keyed the wrong queue (`R[x1]` stale at loop-top). Now keys
`mem[CTX]` (the shared queue) — 1539 -> 31588 steps with 200 preloaded.
`_force_val` (once, dispatch POP) + `_forcereg` (set-reg-before-insn) +
`_preload` (persistent per-pc queue insert) = full fault harness, all
labeled INJECTED where used.

## 3. Sustainment ceiling

Even 31k-step runs never pass maxpc `0x12a8cc` naturally, nrand stays 0:
depth sustains looping, but every pass still routes on placeholder-derived
values (seeder cases), never into the gateway path (needs OUTLEN >= 742
from a warmed stream) nor back into the header. Steering controls pass 1;
passes 2+ need live workspace values (real merge EMITs from real #0).

## 4. Remaining (unchanged in kind, narrower in scope)

Real #0 encoding (fetch-ordered content + correct tail per target pass) so
that passes 2+ route live; then header sustainment (len/arg/counter from
live LENQ), workhorse, assembly, parse. Every stage has a working harness
and a falsifiable monitor (dispatch values, gateway pcs, nrand, overlap).
