# WORKHORSE DECODE — the body is a verbatim workspace copy (2026-09-13)

## The loop (0x12a860..0x12a8b0, fully read)

```
0x12a860: ldr  x0, [x28, #0x20]!     ; x28 walks ctx; select stream (ctx[0x20+8k])
0x12a864: bl   OUTLEN (0x1472e8)     ; w22 = acc − TOP  = trip count
0x12a86c: mov  w23, wzr              ; counter i = 0
0x12a870: cmp  w22, w23; b.eq exit   ; while i < trip:
0x12a878: ldr  x0, [x28]             ; selected stream
0x12a87c: mov  w1, w23               ; LENQ arg n = i
0x12a880: ldr  x24, [x26]            ; sink = [x26] = out-buffer
0x12a884: add  w25, w21, w23         ; out position = w21 (running base) + i
0x12a888: bl   LENQ (0x147304)       ; w0 = stream[TOP + i]        ← RAW READ
0x12a88c: mov  w3, w0                ; EMIT value = LENQ result UNCHANGED
0x12a89c: bl   EMIT (0x146ed8)       ; out[w21+i] = value
0x12a8a4: add  w23, w23, #1
```

**out[w21 + i] = workspace_stream[TOP + i]** — a pure COPY. No XOR/add/rotate.

## Consequences

1. The 176-B body = the workspace array's window [TOP, TOP+44) of the selected
   stream(s), copied verbatim (w21 = running position base across streams;
   x28-advance = per-stream sections).
2. The whitening happened in the MERGE phase (before the workhorse): merge
   EMITs wrote values at computed positions idx = TOP + n where TOP =
   data[count−1] — i.e. the claims are diffused through POSITION arithmetic.
   The body is the resulting sparse-array state, which is why:
   - zero raw containment of H/claims (slice 8/12),
   - total diffusion (slice 15),
   - positional-looking values (+109/pass seeders, slice 40),
   - no per-word transform fits (tested 2026-09-13: xor/add/feedback — all fail).
3. Therefore the ONLY path to byte-exact body = exact simulation of the merge
   phase with REAL inputs (11 descriptors), then read off the workspace window.
   The workhorse itself needs no modeling beyond the copy.

## vm_mem insufficiency (measured 2026-09-13)

- The 44 inbuf words ARE recoverable from vm_full.json workhorse x3 regs —
  they decode to plaintext claims: adj_verification ("KlcAG2cb…"),
  android_uuid, "31", app_token "jut9tib0eeps", app_version "3.13.9",
  created_at "2026-09-12T12:02:24.477Z+0200", "moto g42", "phone",
  "production", gps_adid. (These are the WORKHORSE INPUTS — but per the copy
  decode above they are NOT what the workhorse writes; they fed the merge.)
- The vm_mem 3 regions do NOT contain the workspace stream arrays (no live
  stream structs found by full scan; packed claims absent). The merge state
  lives in un-dumped heap regions — the "exact auxiliary entry state" gap of
  slice 77 is now precisely: **the merge workspace at workhorse entry**.

## Path to the body (unchanged, now sharper)

Merge simulation with real descriptors → workspace state → copy window.
OR: capture the workspace arrays synchronously at workhorse entry (one
Frida run hooking 0x12a860, dumping [x28] stream struct + offs/data).
Everything else (header, field loop, op semantics) is already byte-exact.
