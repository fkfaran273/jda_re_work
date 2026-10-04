# The 32-B block [46:78) — final verdict (2026-09-29)

Both subagents complete. The block is CLEARED as a blocker.

## Subagent A — VM trace (block_trace.py / vm_inverse.py)

The block is **not a computation**. It is a byte-for-byte re-serialisation of
9 dwords the VM had already written into the main stream:

```
block = be(11)[2:] + b"".join(be(n) for n in range(12, 19)) + be(19)[:2]
```

(M = main-stream dwords.) It adds **zero new information** — any blob whose
earlier stream words are right carries a right block automatically.

## Subagent B — pattern analysis (block_pattern_analysis.py/.md)

- 6/6 genuine winning blobs decode cleanly; their 6 blocks are all distinct,
  full entropy, no pattern vs (S, claims, head) — because there is nothing to
  find: it is stream data, not a hash.
- ~40 compositions of (S, head, cert, d0, d4) → 0 hits. The block is NOT a
  digest of anything.
- **Genuine vs instrumented: INDISTINGUISHABLE by block** (0 shared windows,
  same entropy/bit profile). The block does not leak instrumentation.
- **Decisive: FinEx predicts the genuine block byte-exactly on 5/6 winning
  blobs** from the claims + (second, S, solved head phase) alone — the block
  never fed in as knowledge. The 6th differs ONLY in block bytes, localized to
  that record's claims content (a stale 3.13.9-era click profile), not the law.
- Solved phases confirmed independently: pre-flight signings `(0x2B,)`,
  the three REAL REQUEST signings `(0x2B, 0x48)` + CY@2.

## Consequence

Every byte of the 192-B blob is now accounted for and computable offline:

| component | status |
|---|---|
| 16-B header | make_header(second) — proven |
| region #0/#2/#4 | F.region(S, 0, 0, head=(0x2B,0x48)) — proven faithful |
| claims #10/#7 | desc10_law — byte-exact session (360 B) + click (388 B); attribution predicted |
| constants #8/#9, zeros #5/#6, empty #1/#3 | pinned |
| 32-B block [46:78) | automatic FinEx output — no extra input |

⇒ The remaining failure modes are all OUTSIDE the blob: per-request claim
binding (each request needs its OWN signing) and the Client-SDK header on
/attribution. win_funnel2.py fixes both.
