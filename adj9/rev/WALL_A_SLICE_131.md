---
title: WALL_A_SLICE_131
---

# SLICE 131 — the builder walks Java objects (Path B mechanism found)

## 0. What the 9 self-call sites show (`rev/recargs_probe.py`)

Every `bl #0x9afa4` is preceded by the same 4-instruction prologue:

```
ldr  x8, [xObj]        ; vtable of a heap object (x22/x21/x23/x28)
mov  x0, xObj           ; arg0 = the object
ldr  x(1..4), [sp,..]   ; other args from the frame
ldr  x8, [x8, #off]     ; vtable slot: 0x548, 0x558, 0x30, 0x390,
blr  x8                 ;   0x388, 0x110, 0x108, 0xf8, 0x640
... use return value ...
mov  x0, xObj           ; arg0 = SAME object again
mov  x1, xzr            ; arg1 = 0 (NULL / index 0)
bl   #0x9afa4           ; recurse
```

So `sub_9afa4(obj, 0)` recurses over **live Java heap objects** (vtable
dispatch at 9 distinct slots), and its return value selects the
`mov/movk`-built 64-bit key that follows each site. The descriptor words
are therefore `heap_object_field ^ per-site key` — the "plaintext" is
object memory (vtable pointers, lock words, field values), which is why:

* rows 7/9 share identical claims yet differ everywhere (different heap),
* R never appears in H/claims/blob/second (it is heap-derived),
* every output-side battery fails (the source is not in the request at all),
* the tile repeats with R folded in (same object read at two offsets).

## 1. Consequence for the goal (stated plainly)

The 56-byte region is **uncomputable offline**: its inputs are ASLR-shifted
heap addresses and per-process object headers that exist only inside the
signing process at signing time. No formula over (claims, H, second) can
produce them — not because we haven't found it, but because the builder
reads memory the request never contains. Path B (static reduction) is
therefore closed as a derivation route; what remains of it is only the
confirmation role (the key-table shape already matches: R||R keys at the
block-write sites).

## 2. What stays open (and what does not)

* CLOSED: pure-Python derivation of #0/#2/#4 (mechanism proof above +
  exhaustive 0-hit batteries slices 123-130).
* OPEN: device-minted non-organic (10/10, `farm_win.py`) — unaffected.
* OPEN: the R-bridge (slice 129: a[6] = (R<<16)|Xlo, R == Xhi^Xlo, 11/11)
  as a *validity filter* for minted blobs (structural check, not derivation).
* OPEN: Path A-ext (builder-memory capture) — the only route that could
  ever supply real region bytes for a fresh payload, still blocked on
  injection (attach refused / spawn killed).

## 3. Artifacts

* `rev/recargs_probe.py` (9-site prologue dump, quoted above)
* `rev/str_probe.py` (T0/T1/d4-membership + H-half batteries: all 0/11)
* `rev/fn_9afa4_full.log` (3072 insns), `rev/sub_95fc4.log`, `rev/fn_95fc4.log`
