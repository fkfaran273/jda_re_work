# decoder2 — TAINT-TRACKED body-decoder analysis (2026-09-26)

Task: recover the per-signing region seeds `(W0, X, T0, T1, F4 = d4[4],
S = d2)` from a captured 192-B adj9 blob by taint-tracking the wire-builder
VM, then test whether the winners' seeds are **generative**
(`S = V ^ (pid16 << 16)`, `V = (sec' ± 2) ^ us'`).

Files (all NEW; nothing existing was modified):
`vm_taint.py` (the provenance tracker), `decoder2.py` (harness),
`vm_taint_row7.log` + `taint_row7_dags.json` (row-7 run),
`_tdbg*.py` (the debugging trail this doc summarises).

---

## 1. The taint tool and what it proved

`vm_taint.py` runs the REAL `fin_vm2.FinEx` (the 48/48 forward encoder) with a
step-hook side band that mirrors every instruction's dataflow onto DAG nodes
(`('k',v)` constants, `('s',name)` descriptor-word seeds, `('rnd',i,v)`
Random3 draws, `('op',pc,m,v,kids)`, `('sel',...)`).  Values are ONLY ever
read from the live execution, so a node can never disagree with its value —
the v1 in-tracker "self-healing to K(v)" that silently produced
value-matched-but-wrong constant nodes (the reason the first draft of this
task emitted 48 constant leaves) is structurally impossible here.

Self-check on corpus row 7 (second 1789240512):
`status=exit-clean steps=9871985 nrand=8 blob_match=True seeds=57`.

### 1.1 Where the seeds flow (measured, row 7)

* Field loop (steps < 1 000): every descriptor word is loaded
  (`ldr w8,[x8,x22,lsl #2]` → `rev w3,w8`) as a seed node and EMITted to its
  sink stream, e.g. `('op',0x100180,'rev',0x13271271,(('s','W0'),))` — the
  whole 57-word descriptor plane is taint-seeded.
* Merge/whitening phase (0.33 M … 9.9 M): ~40 300 ALU ops, 22 500 queue
  pushes and 1 796 stream emits carry seed provenance in their first 4.3 M
  steps.  The `d2` seed enters the chain machinery as
  `eor/and/lsl/lsr/orr` reconstructions of `0xfb1a8296`
  (the `and w2,w0,w21`-family at 0x1068xxx, byte-extraction
  `and 0xFF / and 0xFF0000 / and 0xFF000000`, reassembly `lsl #k`,
  masked recombination `and ~0xFF00` …).
* The whitening-chain BYTES that reach the wire, however, prune to
  **constant** leaves: e.g. the body byte `0x55` emitted at step 4 046 694
  has the derivation
  `eor(0xF6, 0xA3)` with `0xF6` built only from
  `('s','d9[4]')/('s','d9[3]')` bytes and constants — i.e. the chain state
  travelling along the wire is **known plaintext material** (d9 = the pinned
  APK-cert SHA-1, d10 = the claims, d8 = the 16-B constants).  Every one of
  the 48 emitted words ends as `('k', v)` once its known-plaintext lineage is
  collapsed.

### 1.2 The structural finding (this is the headline)

The seed words (W0/X/T0/T1/F4/S) reach the wire **through position arithmetic
and data-dependent control flow, not through the whitening bytes' values**:

* the program's index math runs through `udiv`/`msub`/`mul`/`add` on the
  descriptor lengths and the running offsets (the `msub w2,w8,w0,w21` family
  at 0x10319c/0x11ebcc… and the CAP/ITERNEXT trip counts);
* the whitening loop (0x109ee4…, 0x10c1xx–0x10c3xx) consumes the queue
  machine with CAP-swaps whose indices and the `lsr w2,w21,w0` shift amounts
  are data-dependent — flipping `S` re-orders *which known plaintext byte*
  whitens which wire position (and re-points the feedback taps);
* consequently a per-word **value** DAG of a body word contains no seed
  leaves to invert, while the word VALUE is still seed-dependent — exactly
  the shape that defeats (a) the GF(2) linear model (measured: 0/48 words
  XOR-linear, `decoder.py` → `GF(2) system inconsistent`, model rank 256 but
  the system is inconsistent) and (b) any per-word algebraic `f^{-1}`
  composition.

`dep_probe.py` (ground truth, full-word flips): d2 flips words 8..47,
d0[0..3] and d4[4] flip 4..47, d4[0..3,5..7] flip NOTHING — consistent with
the step-1 model (`body[i] = plain[i] ^ K_i`, K seeded by W0/X/T0/T1/F4, S
entering at word 8), and consistent with the taint view: the seed acts
through the *selection* of the self-keyed (plaintext-fed) feedback chain, so
the K chain is real but its state bytes are known-material.

### 1.3 Invertibility inventory (for the record)

| op | f^{-1} | loss |
|---|---|---|
| add const c | sub c | none |
| eor const c | eor c | none |
| rot/rev/rev16, lsl/lsr by k | mirror ops | none |
| and/orr const | per-bit solve | 0-bits of AND-const are lost |
| mul ODD c | `pow(c, -1, 2**32)` | none |
| mul EVEN c | no modular inverse | loses low bits (2^{-tz(c)}) — **any even mul on the recovery path is a hard information wall** |
| udiv / msub (index math) | not value-invertible | the recovery blocker |

Measured on row 7: the recovery path never presents a clean per-word
`f` to invert — the seeds sit behind the udiv/msub/CAP index machinery, so
`f^{-1}` composition is not just lossy, it is undefined.  **No even-mul
losses were hit in the value plane because the value plane has no seed
leaves to invert; the loss is structural (index plane).**

---

## 2. Why the decoder is blocked (and what would unblock it)

* Backward walk 47→4 requires per-word `K_i = g_i(K_{i-1}, seeds)` with
  algebraic `g_i`.  The taint run shows `g_i`'s value inputs are
  known-plaintext bytes; the seeds enter `g_i` through the position/branch
  machinery.  Inverting means solving for the *schedule*, not the values.
* A 2^32 per-row brute force over FinEx is measurably out of reach
  (~16 s/mint ⇒ 2 200 CPU-years/row).
* `bodymodel.py`'s 256-sample GF(2) map (9 h measurement) is inconsistent on
  the real region ⇒ the map is genuinely non-linear, not under-measured.

Unblock options, in cost order:
1. **Capture S on-device** (the win_rows.json hook already does exactly this:
   `S`, `ctx_arg`, descriptors per signing) — 6 winners ⇒ 6 seeds, then remint
   anything with `F.py(region(S))`.
2. Symbolic execution of the wire-builder with the seed words as symbols and
   the INDEX plane as the symbolic domain (SMT over the udiv/msub/CAP
   schedule) — heavy but bounded (~10 M steps).
3. Skip the body entirely: the server does not re-mint it (slice 82: 0/44
   server-verifiable dwords; slice 81: replayed-body bookings accepted) —
   mint-by-replay or the device-mint path.

---

## 3. Generativity of the seeds — REFUTED on genuine data

`win_capture/win_rows.json` holds 4 GENUINE device signings with the actual
seed `S` captured (device oracle, `ctx_match=true`), gps 7759b5ed
(the same hook that produced the 11/11 device-mint wins).  Testing
`S = V ^ (pid16 << 16)`, `V = sec' ^ us'`, `sec' ∈ sec ± 2`, `us' < 1e6`,
`pid16 < 0x8000`:

| row | sign_id | second | S | pid16 candidates | verdict |
|---|---|---|---|---|---|
| 1 | 1 | 1790341263 | 0x61bf23c6 | 2825 (us'≈21321) | decomposes alone |
| 2 | 2 | 1790341263 | 0x48b5ad6f | 8707 (us'≈56800) | decomposes alone |
| 3 | 3 | 1790341264 | 0xd5c257c4 | 49012 (0xbf74) | **no valid decomposition** |
| 4 | 4 | 1790341264 | 0xb168a7ad | 56286 (0xdbde) | **no valid decomposition** |

* Rows 1+2 are the SAME process at the SAME second; a shared pid16 would
  force `u_hi2 ^ u_hi1 = 0x61bf ^ 0x48b5 = 0x290a > 15` — impossible since
  `us' < 1e6` bounds `us' >> 16 ≤ 15`.  **No consistent pid16 exists.**
* Rows 3+4 have no decomposition at all under the formula at any `sec' ± 2`.

⇒ `S = V ^ (pid16<<16)` is an **emulator artefact**: it is the
`get8random` FALLBACK (`tv_sec ^ (pid<<16) ^ tv_usec`, fired only when
`/dev/urandom` is unreachable — full_replay.md §4).  On the real device the
seed is the low 32 bits of a fresh 8-byte `/dev/urandom` read: per-call
kernel entropy, **not derivable from any captured input and not recoverable
from the blob** (full_replay §4; slice 82: the server cannot re-mint the
body either).

### The 6 genuine winners (win_capture/module_win_capture.log, gps 7cc81be0)

Extracted via header inversion (decoder2.py `--winners`):

| # | kind | second | blob |
|---|---|---|---|
| 0 | session | 1790341508 | 192 B |
| 1 | click | 1790341509 | 192 B |
| 2 | session | 1790341510 | 192 B |
| 3 | click | 1790341511 | 192 B |
| 4 | attribution | 1790341512 | 192 B |
| 5 | attribution | 1790341513 | 192 B |

Their S values cannot be produced by the blocked body decoder (§2), and the
capture log carries no seed leakage (checked: no `S=`, `ctx_arg`, `pid`,
`urandom` records).  The same device hook that filled win_rows.json is the
one-line unblock.

---

## 4. Verdict

* **Pure-Python synthesis of a winning plane: BLOCKED on exactly one
  component — the per-call 32-bit seed S (descriptor #2).**
  Everything else is law-proven and byte-exact (header `Random3(second)`
  4/4; desc10/desc7/desc8/desc9 laws; `F.py` region-given-S; `fin_vm2`
  remint 48/48 on the 6-row corpus).
* The proposed generative formula for S is **refuted on genuine device
  seeds** (§3): it is the emulator's `/dev/urandom`-failure fallback, not a
  device law.  A consistent pid16 across genuine signings does not exist.
* The taint route explains WHY the body decoder is hard: the seed acts
  through index/branch structure over a known-plaintext self-keyed feedback
  chain, so neither GF(2) algebra (0/48 linear) nor per-word value inversion
  applies.
* Working recipe for wins remains the device-mint path (farm_win 11/11) —
  and for pure Python, mint-by-replay of an accepted body (slice 81) with a
  freshly minted header/claims; a *generative* body requires a captured
  per-signing S (device hook, win_rows.json shape) or an SMT-grade model of
  the index plane.
