# Wall A - slice 73-75: replay, contracts, tail capture (2026-09-12)

## Emulator fixes (all in vm_final.py, baseline 1253 intact)

- csel/cset/ccmp implemented (were silently no-ops; affected all
  redispatch values).
- movk spaceless-pattern fix (slice 69); blr _blrret override + x8 logging.
- SUBR true call/ret via shadow stack: {0xBA4A8,0x9AFA4,0x9C478,0x9AD54};
  INS extended down to 0x9900, up through 0xBCA30.
- Heap mode (opt-in `_heap`): bump malloc/calloc, free noop, memcpy,
  memset, strlen + ldbyte/stbyte. Legacy runs unaffected.
- `_substub` (skip call, apply live regs), `_framefill` (x29-rel fills),
  hub/maze/load/pc instrumentation (_hublog,_mazelog,_loads,_b8a0...).

## Replay status (session-2 inputs, session-5/7 truth): prefix 10/19

Passes 0-9 exact (522b,6685,e646,5f69,41dc,f004,525e,f004,525e,f004).
Diverge at 10 (want x21): phase-loop exit needs countdown state.
Live contracts used: maze (x8=x9=0x5bcc,x20=BUMP,x1-x4=e7f4-family),
0x9c478 (x0=0,x1-x4=a5e3-family,x8=x9=9d91,x19=6685,x20=x0entry),
framefill [x29-0x28]=0xa, level-cell[0]=0 (live zero, not 31!).

## Live route (session-7, 40 hub passes per two signings)

One signing = 19 passes, two fetch rounds (x3, x3+0x10), then
f88b -> 0xBBBC0 free-tail -> 2nd fn -> ret. Phase loop counts
0xa->0x6->0x2 (malloc sizes 0xb,0x7,0x3); x1=libc-ptr, x3=0x10.
mazeRet 9x, ret9ad54 212x (per-byte getter), ret9c478 7x.

## Captures

- memdump2 (sessions 4,9,10): L0+L1 sweeps, entry regs.
- memdump3 (tail session): T0/T1 post-chain outputs (90KB heap of
  fetch values/tokens around x3), tail regs.
- route5.json (session-7): entry + 40 hub + all contracts.
- Stall at 0xBBBC0 kills the app (no oracle blob); entry-stall is safe.

## Verify path (found)

- Oracle `nsign` envelope events stopped for new sessions (only
  nsign_in/H fires) -> no fresh blobs. Fix oracle or wire-capture.
- OFFLINE alternative: fetch values STABLE across sessions
  (os_version token identical s2/s4); entry tokens per-type stable
  (0x558c session / 0x176e event); headers for all 34 old pairs
  already recomputed (blobset 34/34). -> Reconstruct old inputs
  (sign_input fields + stable fetch + per-type tokens), replay chain,
  field+workhorse, compare body vs pair blob. No device needed.
