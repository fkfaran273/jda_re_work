# vm_inverse — the adj9 VM backward walk (blob → region), 2026-09-28

Task: build the INVERSE of the adj9 signature VM — given a 192-B blob + claims
+ signing second, recover the region `(d0[36], d2, d4[8])`.

Files (all NEW; nothing existing modified): `vm_inverse.py` (schedule capture +
per-event op fitting + backward walk + region reconstruction + remint oracle),
this document.  Companion probes: `_vin_*.json` (event captures).

---

## 1. What the blob actually contains (measured, all proven)

The whitened payload is a 144-byte RECORD the VM builds on its working stream
(`0x5450001000`, flat offs `[1134..1278)`, builder site `0x119538`, bytes
written in REVERSE order), plus a 32-B digest taken from another section
(body words 40..47 — not needed for the decode):

```
[0:3)     01 00 08
[3:19)    head = d0[0..3]  (each word rev16'd, LE-packed)
[19]      02
[20:24)   d2 little-endian = the native 32-bit seed S   ← the prize
[24]      03
[25:45)   d9 = APK cert SHA-1 (constant)
[45]      04
[46:78)   32-B block (region-derived hash material)
[78]      05
[79:111)  SHA256("")
[111:114) 06 01 07
[114:128) 00*14
[128:130) tail2 (d4[4]-dependent; 00 00 on all corpus rows)
[130:144) 0e*14
```

Dead-input map (flip probes, full-word, row 7 — extends dep_probe):

| input | body words moved | verdict |
|---|---|---|
| d0[0..3] (head) | 4..47 | alive (dep_probe) |
| d2 (S) | 8..47 | alive (dep_probe) |
| d4[4] bit16 | all 44 | alive, path-select bit |
| **d0[4], d0[10], d0[20], d0[35]** | **0/48** | **DEAD** (this session) |
| d4[0..3, 5..7] | 0/48 | DEAD (dep_probe) |

So the blob carries exactly **head(4 words) + S(1 word) + 1 path bit** of
region entropy; every other region word is reconstructed from S by the F.py
laws (`F._d4_words`, `F._d0_words(d4, phase)`, `d2 = BE(S)` — 10/10 on the
genuine corpus).  Recovering the record's `[3:24)` (head + S) IS the decode.

## 2. The whitening pipeline (the derivation machinery)

The record → body[0:144) transform is a FIXED PIPELINE of wire ops on MAIN
whose **schedule is region-independent**: two runs with completely different
regions at the same (claims, second) produce the IDENTICAL (kind, pc,
position) event sequence (21,965 events in the record window, verified
byte-for-byte on pcs+positions).  14,670 of those events are the record
pipeline (after trimming to the first record write).

Per-event op inventory (4-template differential fit, row 7):

| class | count | law (forward) | inverse |
|---|---|---|---|
| xct | 3,553 | `v = cur ^ xor(taps) ^ K` | algebra |
| xc | 2,794 | `v = cur ^ K` | algebra |
| **skt** | **2,013** | **`v = S[cur + D] ^ K`** — substitution; the byte's own value selects the tap position (site 0x111f70, D = 621, K = 0x55) | 256-candidate enumeration against the walk state |
| c | 1,333 | `v = taps[0]` — copies, incl. a 144-instance **memmove** (site 0x109f9c, window shift −17) | memmove runs unit-undone; stragglers destroy |
| xt | 1,283 | `v = xor(taps) ^ K` — **cur destroyed** | not locally invertible |
| act | 32 | `v = (cur + Σtaps + K) & 0xff` | algebra |
| ERR | **3,662** | unresolved | **the blocker** (§4) |

Key site laws proven:

* **Final sweep** (0x111c68, the last writer of every body byte):
  `body[p] = X[p] ^ 0x55 ^ KB[481 + (p mod 16)]` where `KB` = the
  region-independent 37-B chunk at `[1080..1117)` (verified 144/144 on row 7,
  `_bdbg8_row7.json`).  Fully invertible with constants.
* **Header XOR** (0x10a228): `v[1134+i] = v[1134+i] ^ rawheader[i mod 16]` —
  the raw 16-B Random3(second) header is the whitening key for this pass.
* **Self-keyed substitution** (0x111f70): `v = S[cur + 621] ^ 0x55` — read
  directly from the disassembly (`add w2, w0, #1` feeding the second LENQ at
  0x111ea4) and confirmed numerically on 4+8 templates (`tp − cur = 621`
  constant, `v ^ tapval = 0x55` constant).
* The disassembly idiom: every pass is `LENQ(cur) → PUSH → LENQ(tap) → PUSH →
  PUSH 0x55 → eor/eor → CAP juggling → EMIT`, with the tap INDEX computed by
  queue-carried `add` arithmetic.

## 3. The tool

`vm_inverse.py`:

* `capture(second, descs)` — one forward FinEx run → MAIN-stream event list +
  raw record + body + blob.
* `replay` / `fit_ops` / `_fit_one` — per-EMIT law fitting across N templates
  (self-read dropped as redundant; fixed-tap and self-keyed classes above).
* `trim_schedule`, `find_runs`, `D_ok` — pipeline trimming + memmove runs.
* `backward(blob, insts, known_init)` — the backward walk: state starts as the
  blob body bytes at the record positions, every EMIT undone in reverse event
  order (taps read from the maintained state, which equals the pre-event
  state), substitutions solved by 256-candidate scan, memmove runs undone as
  units, record bytes captured at the builder writes; fixpoint retry for
  deferred events.
* `region_from_record` — S → F.py region with head-phase match.
* `VmInverse.decode(blob)` — end-to-end + record/header self-checks + remint
  (FinEx re-run must reproduce the full 192-B blob).
* CLI: `row7` / `corpus [rows]` / `winners`.

## 4. Where the backward walk stands, and the two hard walls

Measured on a TEMPLATE blob (known ground truth): the walk recovers
**11/144** record bytes.  Two independent walls:

**(a) 3,662 unresolved events — the 32-bit word-hash stage.**  Four diagonal
sweep sites (`0x10d0ec / 0x110e30 / 0x10a5fc / 0x10fbf4`, 468 instances each,
covering every record position) plus the hash-state writers
(`0x113158 / 0x113818 / 0x112b60 / 0x109504`, writing the scratch region
`[832..1080)`) resist EVERY unary-transformed xor/add/sub tree fit over all
their visible inputs (cur + taps; 8 templates; rotations/neg/not/mul forms).
Their values vary while all tracked inputs are constant — the missing input is
a **32-bit word state carried through the value queues**: 20,306 32-bit
PUSH/POP pairs on queue `0x5450003000` (e.g. `POP 0x52B23A4A`,
`PUSH 0xF7E2F744` around site 0x113158).  This is the whitening's word-hash
stage (it produces the record's `[46:78)` block and feeds the substitution
table's `[832..877)` window).  Model = instruction tracing of the ALU between
queue ops (vm_taint-style, over the queue/word plane) — bounded work (~10 M
steps, one pass), not yet done.

**(b) Information-destroying writes.**  The xt/c classes (2,616 events) write
values that do not depend on the target's current byte — the forward run
destroys it.  A whitening that destroys intermediates is fine for the ENCODER;
whether the blob still determines the record depends on diffuse redundancy
(the same record byte feeding many taps downstream).  Sequential peeling
cannot resolve this — the decode needs a JOINT solver: encode every fitted
per-event law as a constraint (each is one byte equation over ≤4 stream
positions) plus the hash-stage model, and let SAT/SMT/Gaussian-style
propagation find the record consistent with the 144 known body bytes.
The self-checks (header law, record constants, F.py head match, remint 48/48)
then pick the solution.

Consequence: **corpus validation is 0/6** — the region is NOT yet recoverable
from the blob by this tool.  The 6 genuine winner blobs are NOT decoded yet;
`decoder2_winners.json` (blobs + claims + seconds) is ready for the moment
the two walls fall.

## 5. What would unblock it (cost order)

1. **Lift the word-hash stage** (the 0x10d0ec family + the 0x113158 writers):
   trace the ALU between queue ops for the ~3.7k events, recover the 32-bit
   chain law (it is a fixed function per (claims, second); the queue values
   are region-DEPENDENT inputs — likely the head/S words mixed wide).  Then
   refit those events into invertible/scan classes.
2. **Joint solve**: express the whole pipeline as 14,670 byte constraints over
   ~1,300 stream cells (all laws above are already in that form) and run an
   SMT solver (Z3) with the blob bytes as assertions.  The substitution and
   destroying events are exactly the non-linear constraints Z3 eats.  This
   route does NOT even need the hash stage lifted if its outputs are only
   READ by the record path through the fitted taps — measure first.
3. **Skip-the-body alternative** (unchanged from decoder2.md): the win path
   does not need the decoder — mint-by-replay of an accepted body, or capture
   S on-device (win_rows.json hook).  The decoder is the pure-Python route.

## 6. Verdict on the task's key insight

"The blob contains all the information to recover the region" is PLAUSIBLE but
NOT proven.  The map that matters is `(S, phase) → record → body`: 2^33
genuine inputs (F.py-consistent records) into a 2^1152 output space, and even
the lossy whitening (xt/c classes destroy 2,616 local bytes) will almost
certainly remain injective on that tiny subset — a d2 bit-flip alone moves
160/192 body bytes, so capacity is not the issue.  The blocker is
COMPUTATIONAL, not information-theoretic: (a) the word-hash stage's law is not
yet lifted, and (b) the destroyed intermediate bytes mean the decode cannot be
done by sequential peeling — it needs the joint solve (every fitted law is
already a byte equation over ≤4 stream cells; the blob bytes are 144
assertions).  The decisive experiment: run Z3 on the full constraint system —
SAT (with the header law + record constants + F.py head match) = the blob IS
decodable and the region falls out; UNSAT (on a complete model) = genuinely
one-way, consistent with slice 81/82 (replayed bodies accepted, 0/44
server-verifiable dwords — the server may verify structurally, not by
decoding).  Everything needed to build that experiment is now in
`vm_inverse.py`.
