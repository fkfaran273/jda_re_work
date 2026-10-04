# KB_DERIVED.md — how KB (240 B round-key schedule) is generated in the FinEx VM (SOLVED 2026-10-01)

## Verdict (overturns the working premise)

**KB is not computed at runtime and there is no master-key expansion.**
The 240 round-key bytes are carried **verbatim inside the VM bytecode as
`mov w2, #imm16` immediates** of an unrolled queue-push block, then drained
through a queue and emitted into scratch RAM where the whitening cipher
reads them. The "KB appears nowhere in libsigner.so" observation is an
artifact of the search method: each byte sits in the low 16 bits of a MOVZ
encoding (`0x52800000 | (imm<<5) | 2`), so no 16 contiguous bytes of any KB
block exist anywhere in the file. The earlier refutation battery
(T-images, MINSTD, AES key-expansion, hash chains, header seeds) was
refuting the wrong class of hypotheses.

KB is a **static constant of the program image**, identical for every
signing (verified across three different `second` values: 240/240 each).

## The materializing code (bytecode pcs)

```
0x119bb8  mov w2, #0x43        ; KB[0]
0x119bbc  bl  0x147630         ; OP_PUSH  -> queue (LIFO)
0x119bd0  mov w2, #0x101       ; offset n = 257 (= 949 - emit base 692)
0x119bd4  bl  0x147630
...                         480 pushes: per byte, value then offset,
...                         ascending idx; each push site 0x18 apart,
...                         interleaved with the writer-status guard
...                         (ldr w8,[x19]; cbnz err; ldr x1,[x20]; mov x0,x19)
0x11c8a0  mov w2, #0x1f0       ; n(1188) = 496
0x11c8b8  mov w2, #0xf0        ; 240  <- pair count for MKITER
0x11c8bc  bl  0x147630
0x11c8d0  bl  0x147734         ; POP  -> w0 = 240 (count)
0x11c8ec  bl  0x146558         ; MKITER(x19, [x8], 240)   (iterator node)
0x11c8f8  loop:
0x11c900    bl  0x147734       ; POP -> w21 = n   (offset)
0x11c918    bl  0x147734       ; POP -> w3  = v   (key byte)
0x11c934    bl  0x146ed8       ; EMIT(stream x26, n, v)  -> scratch RAM
0x11c948    bl  0x146650       ; ITERNEXT -> w0
0x11c94c    cbnz w0, loop      ; 240 iterations
```

The queue is LIFO (`insert(0, v)` / `pop(0)`), pushes run ascending idx, so
the loop emits **KB[239]..KB[0]** (descending) into the scratch stream
`0x5450001000` at absolute slots **949..1188** (emit base = stream top = 692
during this run; the offsets n = 257..496 are relative to the live top).
The same scratch arena also holds T at 693..948 and the 144-B cipher state
at 1206..1349.

## Consumption

The 14-round SPN reads the schedule byte-per-byte from slots 949..1188:

- `lenq` at **pc 0x111afc**: 2160 reads = 9 chunks x 240 key bytes
  (14 rounds + final whitening per chunk), all landing in 949..1188.
- `lenq` at **pc 0x111ea4**: 2016 reads = 9 x 14 x 16 T-lookups from the
  T region 693..948.
- pcs 0x1119f4 (2160) / 0x111e40 (2016): state reads/writes over the
  144-B state window (15 x 144 and 14 x 144).

After signing completes the arena is reused, which is why KB is not in the
final memory image — it exists only during the interval emit-event
9267..19989 (one contiguous interval; writer pc 0x11c934, 240 single-byte
writes, descending idx).

## Evidence chain (all mechanical, rerunnable)

1. `hunt_kb.py trace` — LogMem over `mem`: whole 10.5 M-step signing does
   only **1284** `mem` stores; 0 hits for KB/T 4-grams (any packing,
   endianness, XOR-0x55). Blob reproduced byte-exact.
2. `hunt_kb.py trace2` — instrumented queues (PUSH/POP/CAP), stream emits
   (resolved absolute idx) and lenq reads: still **zero** KB/T 4-grams as
   32-bit values — key material never travels as words.
3. Byte-granular scan of the scratch stream (`scan_s2.py`): KB 4-grams
   224/237 present at idx 949..1188; interval analysis shows exactly one
   full-KB interval; completing writer = **pc 0x11c934**, 240 byte writes,
   every value == KB byte-for-byte.
4. LIFO stack replay of the queue log pairs every generator pop with its
   push: 240 value-pops == KB 240/240, offsets 257..496 ascending, count
   pop == 240. **480/480 push sites are `mov w2, #imm` literals** (KB[13]
   = 0x00 uses the `mov w2, wzr` zero-encoding).
5. Static re-extraction from the embedded program image reproduces KB
   **240/240** with no VM execution and no hardcoded key bytes
   (`derive_kb.py`).
6. Input-independence: same 240 pops for seconds 1789239390, 1789239391,
   1234567890 — 240/240 each.

## T cross-check (validates the method)

T (256 B, AES S-box XOR 0x55) lives at scratch slots 693..948 during the
cipher and **is computed at runtime**: its build phase writes T in the
multiplicative-group order 3, 5, 15, 17, 51, 85, 255, 26, ... (powers of
the GF(2^8) generator 3 — the AES inverse table walk), completing at
T[0]=0x36 (writer pc 0x10c3b4/0x10c4d8). All 256 writes match
`pure_sign.T`. So: T computed (as T_LAW.md concluded), KB literal — two
different mechanisms, and the write-provenance method distinguishes them
cleanly.

## derive_kb() (stdlib only)

`derive_kb.py:derive_kb() -> bytes` regenerates KB byte-exact from the
program image (`signer_simple.py`'s `_LIB_SPANS`, which mirror
libsigner.so's code; override path via env `SIGNER_SIMPLE`):

- decode every `mov w2, #imm ; bl 0x147630` (OP_PUSH) site from the
  embedded spans (MOVZ w2 mask `0x7F800000 == 0x52800000`, hw=0, Rd=2, or
  the `mov w2, wzr` word `0x2A1F03E2`);
- take the contiguous 481-site run at stride 0x18 whose last immediate is
  240 (the MKITER count) and whose offset immediates are 240 consecutive
  ascending integers (self-validating gates);
- the value immediates in program order are KB[0..239].

Verification: `python derive_kb.py` -> **MATCH 240/240** vs
`pure_sign.KB` (`43fc368804c8ed1b17e5c8f603002f46...01aa5ca3cc74cc`).
No master key exists (<= 32 B or otherwise): the schedule itself is the
stored constant.

## Files (this directory)

- `hunt_kb.py` — trace / find / trace2 / find2 / window phases (LogMem,
  queue+stream instrumentation, bytecode dumper).
- `derive_kb.py` — the standalone extractor above.
- `scan_q.py`, `scan_s.py`, `scan_s2.py` — 4-gram scans, pc/qva histograms,
  byte-run reconstruction, interval analyses.
- `trace_pc.pkl` (mem-store log), `trace_q.pkl` (queue/stream op logs) —
  raw provenance data, ~390 KB + ~60 MB.
- `corpus_pc.py`, `probe_time.py` — gold vector + timing harness.
