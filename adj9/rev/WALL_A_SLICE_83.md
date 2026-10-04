# Wall A - slice 83: the server cannot get #0's nonce words either (2026-09-13)

## Question

Can Adjust's server recover descriptor #0's real nonce words from a
submitted signature?

## Answer: no (structurally impossible, same barrier as ours)

1. The server receives only the 192-B blob + request params. It never
   sees the workspace (field sinks, TOP chain, merge positions).
2. #0's words reach the body through value-dependent routing:
   field EMITs land at (sink_#0, j) deterministically, but the
   workhorse copy (`out[w21+i] = stream[TOP+i]`) and merge positions
   (`idx = TOP + n`, TOP chained from emitted VALUES) depend on the
   very values being sought. Inverting output positions → input words
   requires the forward map, which requires the inputs. Circular.
3. Hence #0's nonces are write-only entropy for EVERYONE, server
   included. This is consistent with all live evidence (zeros pass,
   H replays pass, 0/44 sharing between 80-ms-apart signings).

## What the server CAN do instead (and evidently does)

- Parse known slots (claims, H, cert, counters, timestamps) at
  code-known positions and check consistency/freshness.
- Whole-blob duplicate detection for replay protection (memcmp needs
  no parsing — uniqueness is supplied by H + timestamps + #0 entropy
  jointly, so our random #0 never collides in practice).
- Business logic (session intervals, SDK support) as observed live.

## Consequence for making signatures

Nothing further is needed for #0: random fill is not a shortcut but
the final answer — unrecoverable, unverifiable, and accepted (200).
The maker (`sign_fresh.py`) is complete as-is.
