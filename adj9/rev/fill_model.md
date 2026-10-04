# fill_model — the descriptor-fill model PINNED: region = F(gettimeofday tv), xor-mixed; nsec INERT

Date: 2026-09-23/24. Deliverables: `rev/fill_probe.py` (descriptor-dump driver),
`rev/fill_runs/*.json` (23 instrumented runs), `rev/fill_model.py`
(machine-checked analysis), `rev/fill_battery.py` / `fill_tsweep.py` /
`fill_bridge.py` (the batteries).  Harness: `rev/emu_8d6f4.py` (NOTE: the file
was extended by a sibling agent mid-session — see §7 — all conclusions below
were re-verified within a single harness era).

---

## 0. Headline

1. **The per-call region words (W0, X, tile U0..U3, d2, d4[0..7]) are a pure
   function of the GETTIMEOFDAY time-value at the fill instant — and of
   nothing else that is transmitted.**  The two tv fields mix as
   **V = tv_sec ^ tv_usec** (§3): `sec+1` and `usec+1` produce
   **byte-identical** #0/#2/#4 descriptors (proven in both harness eras),
   while `(sec+1, usec-1)` — equal **sum** tv_sec+tv_usec — produces a
   **different** region, killing the sum model and every linear model with it.
2. **The emu_findings §4 fine-clock hypothesis (CLOCK_MONOTONIC nsec) is
   REFUTED at the output level**: nsec ±1 ns, ±1000 ns, ±1 µs (usec-path), ±1 ms,
   ±2 ms leave ctx, the built descriptors and the 208-B blob **byte-identical**
   (5 runs).  The ±1 ns ctx+0x718/+0x788 sensitivity was real but those words
   never reach the output: the builder ctx is **0-word different** at the
   serializer even between runs whose regions differ (fill_ctxdiff.py).
3. **Input map (28 runs)**: LIVE = {gettimeofday tv_sec, tv_usec (xor-mixed),
   pid/tid (per-process constants)}; INERT = {nsec, width, height, all 13
   property strings, hmac/H, claims content, cert, cert-SHA1, package,
   tls_base, stack_guard, srand_seed/rand stream}.  `environment` is a GATE:
   a non-production value zeroes the whole fill (W0=X=tile=0, heap junk in the
   buffer tail) while the wire blob stays identical — see §6.
4. **The wire blob body is NOT the merge of the built descriptors in the
   emulator** (FinEx on the emu descriptors: header 4/4, body 0/44 for every
   run) — and `env_val` proves it directly: descriptors fully changed (zeros +
   heap junk), blob byte-identical.  The blob = the whitened claims/H stream;
   the descriptors feed the REGION captures only (consistent with
   corpus_seed §1.2 "the wire body contains no descriptors").  The device-side
   FinEx 48/48 reproduction binds the *device's* field-run values, which the
   emulator's whiten phase consumed differently (scheduling-era artifact, §7).
5. **Verdict on offline minting** (§6): the region is forgeable in principle
   — pick any fill-instant µs, compute F(V) — but F is a hash-like VM program
   (avalanche; site: the wire-builder ALU chain 0x128xxx–0x12axxx + the 16-bit
   XOR whitener `ldrh/eor w4,w4,w2; strh` at 0x14418c–0x1441a4), NOT yet
   lifted.  A server cannot recompute the region from the request (the µs is
   not transmitted; ±1 µs avalanches all 45 words), so the booking-gate
   "recomputation" must be law-based — and every F(V) output satisfies the
   laws (§4), while a random region fails them (chance 2^-16 per law).

## 1. Descriptors as a function of the inputs (the battery)

Driver: `fill_probe.py` hooks the serializer call `bl 0x100094` at **0x12d39c**
(w2=11), reads the 11 vararg nodes (x3..x7 + [sp..sp+0x28],
va_order=[0,9,8,4,2,7,10,5,1,6,3]), and dumps {nbytes, ptr, hex} per
descriptor + blob + rand/srand/clock logs.  Timeline (write-watchpoint +
EMIT-trace runs): builder fill done by icount ~24 M → field walk/serializer at
41.94 M → 8 rand draws at 42.2 M → merge (30,584 EMITs) → blob = **F0
last-write window [0..52)** (verified equal to the returned 208-B blob).

| run (cfg delta) | W0 | X | d2 | d4 | verdict |
|---|---|---|---|---|---|
| base, base2 (none) | 3a6ffb91 | 879d6e77 | 00149b5a | unchanged | deterministic within era |
| nsec ±1, ±1000, ±1 ms, ±2 ms | same | same | same | same | **nsec INERT** |
| width+1 / height+1 | same | same | same | same | ctx+0x60/64 change only; **INERT** |
| prop model change | same | same | same | same | **props INERT** |
| hmac_flip | same | same | same | same | **H INERT** |
| android_id → value | same | same | same | same | #7/#10 claims change; **region INERT** |
| cert / cert-SHA1 / package / tls / guard / srand_seed=2 | same | same | same | same | **INERT** (era-2) |
| **sec+1** | 0b984e85 | … | 01149b5a | changed | **LIVE** |
| **usec+1** | 0b984e85 | … | 01149b5a | changed | **LIVE — identical to sec+1** |
| **sec+1 & usec−1 (Tsame)** | 48d9cb85 | … | 7e149b5a | changed | **LIVE — ≠ base despite equal tv sum** |
| pid+1 & tid+1 | 912bce9f | … | 0014985a | changed | **LIVE (per-process)** |
| environment=production→sandbox | 00000000 | 00000000 | 06664b43 | 2929…29 | **fill GATED** (§6) |
| T sweep (usec +2..+10000) | avalanche | avalanche | linear-ish hi | avalanche | §3 |

## 2. The ts mystery RESOLVED (task 2's parenthetical)

* `pair_h3.json` rows 0..7 carry real `nsign_ts` values; rows 8/9 of
  `all_signings.json` have **no ts at all** — `l48_pairs.py` synthesises
  `TS[8]=TS[7]+22272`, `TS[9]=TS[7]+28663` (the whcap event offsets).  The
  "consecutive ts 1789240514238/536510/542901, ~22 s and ~6 s apart" are
  **artifacts**, not capture times.
* Real timeline (`device/adj9_wh4.log`): `nsign_in` ts=1789240511766 (signing A
  entered) → `nsign` ts=1789240514238 (A returned, 2.47 s later, blob
  5595c3c4…) → `nsign_in` ts=1789240514276 (signing B entered 38 ms after A
  returned; log ends during B).  Claims created_at: S0/S2 = 21:15:11.678,
  S1 = 21:15:11.762 (+0200) — the map was built once and re-signed.
* Consequences: row 7's header law (seed 1789240512) is untouched; rows 8/9's
  "second = 1789240512" (created_at+1 inference) is **not** header-proven
  (no blob) and is likely wrong by ~2 s for S1 — harmless, because the region
  does not consume the second except through the tv.

## 3. The transform: V = tv_sec ^ tv_usec (linear? NO — hash-like, xor-mixed)

Four-point algebra over the gettimeofday tv (the fill's read returns
(cfg.sec, cfg.usec + 4 ms of virtual clock)):

```
F(513, 504000) == F(512, 504001)   sec+1 ≡ usec+1, byte-identical, BOTH eras
F(513, 503999) != F(512, 504000)   Tsame  ≠ base   (equal SUM 1789744512!)
F(511, 504000) != F(512, 504000)   T-1sec ≠ base
```

No function of tv_sec+tv_usec (nor any a·sec+b·usec linear form) fits the
first and third lines simultaneously; **V = tv_sec ^ tv_usec** fits all 20+
runs (the equal-xor pairs collide, all distinct-xor runs differ).  Beyond the
input identity, F is **hash-like**: the T sweep (V+2, +3, +4, +5, +10, +100,
+1000, +10000) avalanches W0/X/tile/d4 (consecutive per-unit slopes −1741554806,
+1254325299, +2135953236, … — no constant slope); d2's high 16 bits move
non-monotonically (0x0014 → 0x0114 → … → 0xe415 → 0x6810 → 0x1073) while its
low 16 bits (0x9b5a) are V-invariant in the emulator.  The construction site
is the wire-builder VM: ALU opcodes (add/mul/eor w2,w0,w21 families at
0x128xxx–0x12axxx, append via 0x147630) plus the **16-bit XOR whitener**
`ldrh w4,[x19]; eor w4,w4,w2; strh w4,[x11]` at 0x14418c–0x1441a4 — the
region is assembled and whitened in 16-BIT UNITS (write watchpoints show
2-byte stores at 0x143f68/0x1441a4).  Lifting that program is the remaining
work for a closed formula.

## 4. The structural laws hold for every V (they are properties of F, not of the entropy)

| law | corpus | emulator |
|---|---|---|
| U[2]^U[0] == R‖R (16-bit replication) | 13/13 | 11/11 runs (phase-aligned; 2 runs have the tile cycle phase-shifted by 1 word — law still holds at the shifted phase) |
| d4[6]>>16 == R | 10/10 | 9/11 direct, 11/11 at the cycle phase |
| X == U[3] | 12/13 | **fails in-emulator** (emu word 1 is not the tile's 4th word) |
| #0 = W0 ‖ X ‖ tile×8 ‖ T0T1 (device) | ✓ | emu shape: W0 ‖ X ‖ 5 words ‖ tile×7.25 — the emulator's synthetic inputs (14-B claims) shift the layout; see §7 for the era-dependent one-unit effect |

## 5. The S0/S2 differentiator (task 3)

S0 (row 7) and S2 (row 9): identical 360-B claims (byte-equal d10, hence
identical canonical → identical H), identical second, same process — yet W0, X,
tile, d2, d4[1..7] all differ (d4[0] only by flag-like 0x0480).  With the input
map above there is exactly one surviving per-call quantity: **the fill-instant
gettimeofday tv (µs field) — V**.  The three signings of whcap_hits7 ran at
≈1789240511.77–.9, ≈1789240514.28+, ≈1789240517+ (entry times 2.5 s apart);
the fill's µs differs per call; ±1 µs avalanches the region.  pid/tid are the
only other live inputs and are per-process constants — they cannot
differentiate S0/S2.  (The B1~B2 oracle pair: same story — same second, same
inputs, different µs.)

## 6. The wire blob vs the region — and the verdict on offline minting (task 4)

* `env_val`: region fill gated to zeros/junk while the returned 208-B blob is
  byte-identical to base ⇒ **the blob body does not consume #0/#2/#4**;
  FinEx(emu descs) reproduces only the header (4/4), body 0/44 for every emu
  run.  The blob = the whitened claims/H stream; the region lives only in the
  descriptor buffers (what the whcap field-runs capture on device).
* **Is the region offline-computable given (second, nsec, props)?  NO — and
  the question's premise dissolves**: the region consumes neither the nsec nor
  the props.  It is F(gettimeofday tv at the fill instant, pid/tid).  The tv's
  µs field is untransmitted and unrecoverable from the request (created_at
  gives ms at best, and the fill happens later); ±1 µs changes all 45 words.
* **Is the region mintable offline?  YES, in two steps**:
  1. the entropy is now fully identified (tv, xor-mixed + pid/tid) — no
     unknown input remains;
  2. the transform F is a bounded VM program in the wire builder (§3) — a
     lift-and-run job (FinEx-style), not a search.  After lifting: pick any µs
     in the target second, compute V, run F → a region that satisfies every
     structural law automatically (§4).  A random region fails R‖R with
     probability 1−2⁻¹⁶ — which finally explains slice 144's booking gate
     (random regions rejected, app regions accepted) WITHOUT requiring the
     server to know the device's µs.
* Header: already solved (Random3(second), 8 draws, pair-XOR, BE).

## 7. Caveats

* **The harness changed mid-session** (`emu_8d6f4.py` 1342 → 1567 lines at
  00:25: a sibling agent added mono_sec/mono_nsec/urandom8 knobs and made
  every clock PLT call a coroutine yield point).  Era-1 (old scheduler) and
  era-2 (new scheduler) outputs differ by exactly ONE 16-bit unit in #0
  (0x879d present in era-1 base, absent in era 2) — i.e. **one unit of the
  region is coroutine-interleaving-dependent**.  Within an era everything is
  byte-reproducible (base_recheck1 == base_recheck2; both no-op controls ==
  base).  On the real device the two threads interleave nondeterministically —
  this is a second, hardware-real per-call entropy channel besides V.
* Because of the era split, cross-era W0 values must not be compared; every
  conclusion above was checked within one era (era-1: battery + T sweep;
  era-2: bridge + collision re-verification e2_sec1/e2_usec1).
* The emu's 14-B synthetic claims shift the #0 layout vs the device's 360-B
  claims (emu 5-word prefix + tile×7.25 vs device tile×8.5); the tile laws are
  layout-invariant.

## 8. Reproduction

```
python adj9/rev/fill_probe.py --runs '[{"tag":"base"},{"tag":"e2_sec1","cfg":{"sec":1789240513,"time_sec":1789240513}},{"tag":"e2_usec1","cfg":{"usec":500001}}]'
python adj9/rev/fill_battery.py      # inert-input battery (era-1)
python adj9/rev/fill_tsweep.py       # V sweep +2..+10000 (era-1)
python adj9/rev/fill_bridge.py       # cert/pkg/tls/guard/srand/pidtid/Tsame (era-2)
python adj9/rev/fill_model.py        # laws + collision + input map + ts mystery
python adj9/rev/fill_ctxdiff.py      # builder ctx identical even when region differs
```
