# Wall A - slice 80: #0 investigation — per-signing entropy (2026-09-13)

## Question

Can descriptor #0's 36 dwords (144 B @struct+0x50) be reconstructed
offline for from-inputs recompute?

## Evidence

- #0 dword35 (last emit): `0x3465d635` (session, 12:02:24.477) vs
  `0x0c5bc6be` (click, 12:02:24.557, same second, same device, 80 ms
  apart). Varies per signing with no time structure.
- Tested and excluded: MD5/SHA-1/SHA-256 of created_at (both sessions),
  time-seeded Random3 continuations, H-word/XOR/add-seeded Random3
  (45 seeds × 40 draws), raw/BE/LE/rev/rot/add containment in any live
  stream, H, or cert words.
- Heap scan (1013 regions, fresh session): dword35 absent (expected —
  per-session values can't match across sessions; confirms variability).
- vm_mem (aligned session): dword35 absent BE+LE (buffer freed/reused).
- Merge positions are value-dependent (TOP chains from emitted values),
  so placeholder runs can't localize #0's words for blob read-off.

## Conclusion

#0's varying words are per-signing entropy (or a keyed function of
unknown inputs), NOT device/request claims. From-inputs recompute of
the exact body is impossible without capturing them live — the same
reason the server parses rather than recomputes. This bounds Option A:
positional/semantic decode is achievable offline; exact byte recompute
needs one synchronous capture.

## Precise capture spec (Option B, if ever needed)

Hook inner EMITs at `0x10015C` during the field phase (not just the
`0x100114` head) for one signing, capturing #0's 36 (pos, value), or
dump the 144-B buffer at struct+0x50 synchronously (grabtail-style
stall timed at the fieldloop hook). Correlate via oracle nsign ts.
Expected yield: full #0 + immediate 44/44 via recompute_body.py.
