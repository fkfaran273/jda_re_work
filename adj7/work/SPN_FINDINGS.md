# SPN_FINDINGS.md — the adj7 (3.62.0) whitening SPN

Date: 2026-10-05.  Work dir: `adj7/work/` (all artifacts below live here;
read-only inputs were used from `adj7_work/` and `adj9_ios/`).

---

## 1. Verdict (one paragraph)

The 304-B blob is `header(16) || body(256) || tag(32)`.  The **header and
tag laws are re-verified closed-form in `spn_law.py` on both known mints**
(bionic-rand pair-XOR header seeded with the signing second;
`tag = HMAC-SHA256(DK37, blob[16:272])`).  The **body's SPN was not reduced
to a closed formula in this session**, but the session produced the first
exact picture of *how* the body is computed and a working experimental
harness:

* the SPN runs inside a **bytecode VM** (word-stack machine, list-node
  heap) whose program is generated at run time from the claims;
* the per-chunk VM program is now **known opcode-by-opcode** (see §4):
  a 255-iteration key/table phase followed by **14 rounds** (13 full + 1
  final) of {setup, 4 × (4 word-ops incl. a multiply), mix-pair}, then a
  copy-out;
* a **snapshot/resume oracle** (`spn_resume2.py`) reproduces a genuine mint
  bit-exactly after full state restore, and proves **full diffusion**
  (every IV byte flip changes all 16 output bytes of the chunk);
* the **CBC structure is confirmed functionally**: patching the header IV
  after chunk 0's SPN has run leaves the whole body unchanged — only chunk
  0 consumes the header IV, chunks 1..15 chain from the previous chunk's
  output.

Everything below is measured, with the harness and raw data files named.

---

## 2. Established facts (all measured this session)

### 2.1 Deterministic baseline
* Mint (sid `0015`, sec `1771238644`) reproduces blob
  `66e7ca6832cb9e22...` (`v3_blob.hex`) byte-exactly in every probe run
  (`spn_probe1.py`, `spn_probe3.py`, `spn_probe4.py`, `spn_probe6.py`,
  `spn_resume.py`, `spn_resume2.py`).
* Second known mint (sid `0001`, sec `1789382946`) blob `67a33064...`
  (`adj7_work/adj7s4_out7.json`).
* The whitening phase (armed at the 8th `rand()` PLT call) spans
  **29,314,679 stores / 4,534,255 loads** (`v6_writes.txt` has
  `(pc addr size value)` per store; `v6_reads.txt` has `(pc addr size)`).

### 2.2 Key material
* **KB362** = 64 dwords from `adj7_work/adj7s4_immruns.json` key `d20a0`
  (duplicated at `d6c18`), consumed as `struct.pack('<64I', ...)` — the
  **LE dword view, unmasked** (verified: the contiguous 256-B copy appears
  at heap `0x900a6a8` in every pass-boundary snapshot of the 0015 mint;
  the 0xCC mask hypothesis is **not** what is used — the heap copy equals
  the unmasked LE bytes exactly).
* The KB is *not* read from the contiguous copy: it is **pushed through
  the VM stack** early (events ~6511-7771: 64 dword pushes, descending
  d63→d0, values also spilling to native stack slot `0x71ef67c`) and
  re-materialized into VM nodes; a fresh per-chunk re-copy of all 64 KB
  dwords into nodes happens right before each chunk's SPN (for chunk 0:
  events 4.2M-4.87M, one dword per ~6052 stores, pc `0x510a28`).
  Total KB-valued dword stores per signing: 1856.
* DK37 (tag key) confirmed materialized from `movz/movk` immediates at
  file `0xcc43c` (`w2 = 0x2a4cc079`, then pushed with VM op `0x110978`).

### 2.3 Chunk cadence
* The body is 16 chunks; each chunk's **output bytes are stored one byte
  at a time into a stride-4 dword-cell buffer**, 16 stores ~498 events
  apart (~8000 events per chunk loop); chunk k's loop ends at
  `wc ≈ 6,614,677 + k·1,220,968` (chunk 0: 6.61M, chunk 15: 24.94M).
* The 16 chunk buffers sit at `0x900f09c + 0x40·k` (found by
  `spn_bufscan.py`, which located all 16 stride-4 fills and matched every
  chunk byte-exactly; e.g. chunk 15's buffer `0x900f45c` receives exactly
  `89 08 f6 de b6 46 36 bd e3 e3 61 3b 73 40 bc 3a` = wire chunk 15).
* After each chunk's buffer fill, the same 16 bytes are re-copied to a
  second buffer (e.g. `0x900f058`), and the final direct-form body is
  pushed dword-by-dword (descending d63→d00) for the tag HMAC — that push
  is visible as 64 dword stores with the `0x36363636` ipad dword
  immediately after (stores7 cluster at ~85 % of the trace).

### 2.4 Diffusion / CBC (the oracle experiments, `spn_resume2.py`)
* Full-heap + full-register **snapshot/resume** works: restore at
  `wc=5,300,000` and resuming with no patch reproduces the genuine blob
  bit-exactly ("identity" test).
* **Full diffusion**: patching any single IV byte (`j = 0..15`, XOR 0xFF,
  30 IV-material spots patched: 16-B direct, 16-B swap4, 4-B words in
  both byte orders) changes **all 16 output bytes** of chunk 0
  (16/16 for every j).  No byte-lane or word-local structure.
* **CBC functional proof**: patching the IV *after* chunk 0's SPN has run
  (snapshot at `wc=6.6M`) leaves the whole body unchanged (only the
  header follows the patch).  Together with §2.3 this means: only chunk 0
  consumes the header IV; chunks 1..15 chain from the previous chunk
  output — the classic `E(R_k ^ C_{k-1})` CBC shape with the header as
  `C_{-1}` — consistent with the family shape of `adj9_ios_pure.py`.

### 2.5 The VM / interpreter (all offsets = emu addresses, base 0x400000;
file offset = emu − 0x400000)
* Flattened-control-flow interpreter.  Dispatch head `0x5112c0` cycles a
  64-bit state token through compare chains (tokens observed on the
  native stack: `0x34ee749c3dc3cf5c`, `0x418b7d3c908df894`,
  `0x49b9b00eeff4c15a`, ...).
* The **VM opcode dispatch** is at `0x4b8324-0x4b8350`: call `0x10eae4`
  returns the opcode in `w0`, then a binary compare tree (opcodes up to
  ~0x2c00+) routes to handlers.  Hooking the dispatch point
  (`0x4b833c`, right after the fetch) captures the **entire VM opcode
  stream**: only **25,204 opcodes per signing** (`v9_ops.txt`,
  `spn_probe6.py`).
* The heap is a **list-node pool**: nodes hold `{value dword (4 B),
  pointers (8 B)}`, reused constantly; VM primitives include
  `0x110978` push-constant, `0x110a94` pop, `0x110bc8(k)` load var k,
  `0x110504` node-element fetch (returns `w0`), `0x10fe08` node-element
  store, `0x1111c0`, `0x1102f0`, `0x110408`, `0x10eae0/4` opcode fetch,
  `0x512d40` calloc(1,16) node alloc / `0x512d1c` free.
* The store instruction `str w8,[x24,w19,uxtw #2]` at `0x5102b4` is the
  generic "store dword at node-buffer[idx]" site — it writes the chunk
  output bytes, the record/claims scratch, everything data-like.
* ~1,000 native instructions execute per VM opcode (the interpreter is
  heavily CFF-obfuscated with `mov/movk` constant storms).

### 2.6 What the SPN is *not*
* Not adj9's core: no AES S-box, no adj9 S-box (or their inverses) exist
  anywhere in the lib image (byte-exact and first-16 searches), and no
  adrp reference to the KB pages 0xd2000/0xd6000 — the KB is built from
  immediates, and the S-box is **generated at run time inside the VM**
  (see §4), which is why `crack_grid.py`'s decrypt-side grid search with
  fixed S-boxes could not hit.
* No S-box table survives in the final heap snapshots as a contiguous
  256-B permutation; no GF log/alog exp-table chain (xtime, g=3) exists
  contiguously either — the tables live in scattered VM nodes and are
  rebuilt **per chunk**.

---

## 3. The per-chunk output pipeline (ground truth from the traces)

For each chunk (chunk 0 numbers):

1. **Key/table phase** — a 255-iteration × 4-opcode loop
   (`0x1495, 0x14a3, 0x14b1, 0x14bf`; 1020 opcodes ≈ 730 k stores,
   wc 5.00M-5.74M for chunk 0).  Each iteration ≈ 2869 stores.
   The KB nodes are consumed *during* this phase (data-node read
   clusters 5.4-6.1M).  Byte-value streams of this phase differ between
   chunks (only 490/14174 positions match chunk 0 vs chunk 1), i.e. the
   phase is data/key-dependent, not a fixed constant table.
2. **Round phase** — opcode `0x1161`, then **13 × {0x1168, 0x116d,
   4 × [0x1312, 0x1341, 0x1372, 0x13a5], 0x1172, 0x1177}** followed by
   **1 final round {0x1168, 0x116d, 4 × [0x1312, 0x1341, 0x1372, 0x13a5],
   0x117e, 0x1183, 0x1188}** (no mix-pair — the AES-style "mix skipped on
   the last round" shape; 14 rounds total; wc 5.74M-6.21M for chunk 0).  Per-round costs: the 4 quads ≈ 1000
   stores each, `0x13a5` ≈ 2050, `0x1172`/`0x1177` ≈ 4000-8100 each.
   * `0x13a5` handler (site `0x4bb710`) performs **`mul w2, w0, w21`**
     (and its siblings the same shape) — a multiply primitive.
   * `0x1172` tail-calls the `0x1177` dispatch (`b 0xbf33c` with
     `w2=0x1177`) — the pair is one macro-op.
   * `0x1157` pushes the constant **13** (`mov w2, #0xd`).
3. **Copy-out** — opcodes `0x10b4, 0x10af, 0x1157`; the `0x10af` handler
   contains the internal loop `0x110504` (element fetch) → `0x10fe08`
   (element store) that copies the output bytes node→buffer; the visible
   result is the 16 stride-4 byte stores of the chunk output
   (§2.3), then the re-copy, then the body push for the HMAC.

The SPN **state between rounds lives in VM nodes** (registers alone
cannot hold it across opcode dispatches), but the state cells are
recycled list nodes, which is why naive "find the 16-B state in the
snapshot" scans fail; the round-by-round state *is* recoverable by
diffing the round-boundary heap captures (`spn_caps/cap_*.bin`,
`spn_probe7.py`) once the state-node addresses are pinned per round.

---

## 4. Open items — exact remaining work for the closed form

1. **Pin the state nodes.**  Diff `spn_caps/cap_5739035.bin` (before
   round 1) against `cap_5770336.bin` (after round 1) etc., filtering out
   pointer/counter churn (values that look like `0x009xxxxx` or < 0x40);
   the 16 state bytes per round are among the ~350 differing byte cells
   in the `0x900a/0x900b/0x900f` regions.  Repeat across rounds → the
   14 round states of chunk 0.
2. **Extract the generated table.**  The 255-iteration phase writes its
   output bytes via `0x510a28`; correlate the per-iteration byte writes
   (first iteration of chunk 0 pushes `01 0a 03 08 02 00 04 ...` at nodes
   `0x900aa20, 0x900b5a0, 0x900a960, 0x900aa00, 0x900a900, ...`) with the
   final node contents in `cap_5735024.bin`.  The table is per-chunk
   data-dependent (§3.1), so it must be reconstructed together with the
   key schedule.
3. **Decode the six round handlers** (`0x1168/0x116d` setup,
   `0x1312/0x1341/0x1372/0x13a5` word ops, `0x1172+0x1177` mix, and the
   final-round tail `0x117e/0x1183/0x1188`).  Their handler bodies are
   CFF-obfuscated but small; the semantics needed are: which operand is
   the table lookup, where the key byte enters, the multiply modulus
   (integer vs GF-via-tables), and the mix wiring across the four words.
   Handler entry points are listed in §3; the compare-tree sites for
   every opcode are findable by scanning for
   `movz w8, #imm; cmp w0, w8` (see `spn_consthunt.py`).
4. **Fit and verify** against the two known mints and a fresh mint at a
   new second (`spn_law.py` already verifies header+tag; the body check
   drops into it once the SPN is closed).

Estimated remaining effort: 1-2 focused sessions (the handler decoding
is the long pole; everything around it — oracle, traces, captures,
opcode stream — is done and saved here).

---

## 5. Artifacts in this directory

| file | content |
|---|---|
| `spn_law.py` | closed-form verifier: header + tag on both known mints (passes) |
| `spn_probe1.py` | fresh mint, heap read+write logs with values (`v4_*`) |
| `spn_probe2.py` | native instruction+register trace of the dword phase (`v5_codetrace.txt`, 1.17 M lines) |
| `spn_probe3.py` | fresh mint, **pc-attributed** store/load logs (`v6_writes.txt` 706 MB, `v6_reads.txt`) |
| `spn_probe4.py` | unified interleaved event log with read values (`v7_events.txt`, through wc 6.65 M) |
| `spn_probe5.py` | snapshot/resume + pc histogram (`v8_pchist.txt`) / selective code trace |
| `spn_probe6.py` | snapshot/resume + **full VM opcode stream** (`v9_ops.txt`, 25,204 ops) |
| `spn_probe7.py` | snapshot/resume + heap captures at all 14 round boundaries (`spn_caps/`) |
| `spn_resume.py` / `spn_resume2.py` | snapshot/restore oracle; IV-patch differential + fingerprint |
| `spn_bufscan.py` | locates all 16 stride-4 chunk-output buffer fills |
| `spn_kbwrites.py`, `spn_kbnodes.py`, `spn_reads1.py`, `spn_reads2.py`, `spn_kbreads.py` | KB/IV materialization + read-pattern analyses |
| `spn_consthunt.py`, `spn_tracedis.py`, `spn_scan.py`, `spn_scan2.py` | static constant hunt, trace disassembly, stores7 mining |
| `spn_caps/cap_*.bin` | 20 full 8-MB heap captures at round boundaries (chunk 0) |
| `lane0_iter.txt`, `spn_footprint.txt`, `chunk0_writes.txt` | focused event windows |

Raw-trace provenance: all `v4`-`v9` files come from mints run this
session with `sec=1771238644, sid=0015`, each verified against
`v3_blob.hex` before use.  (Note: `v4_reads.txt` read-value column is
always 0 — this Unicorn does not deliver values to `UC_HOOK_MEM_READ`;
`v7_events.txt` re-reads memory inside the hook instead.)
