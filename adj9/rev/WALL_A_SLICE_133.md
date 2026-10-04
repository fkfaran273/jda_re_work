---
title: WALL_A_SLICE_133
---

# SLICE 133 — libsigner seeds libc rand() with time() ; VM draws TWO rands

## 0. Imports + call sites (measured, `rngsites_probe.py` + `imports_probe.py`)

libsigner.so imports 72 symbols; RNG/time-relevant: `rand`, `srand`,
`time`, `gettimeofday`, `clock_gettime`, `getpid`, `getauxval`, `syscall`.

Raw `bl imm26 -> plt` scan over all of .text:

```
clock_gettime: 2 sites (0x18aa0, 0x13dec0)
syscall:      13 sites
rand:          2 sites (0x12a2fc, 0x12a31c)
time:          1 site  (0x12cbbc)
srand:         1 site  (0x12cbc0)
gettimeofday:  1 site  (0x13e5fc)
getpid:        1 site  (0x13e600)
getauxval:     3 sites
```

## 1. Seeding: `srand(time(NULL))` once per process

`0x12cbbc: bl time@plt ; 0x12cbc0: bl srand@plt` — adjacent instructions in
the function at `0x12cb80` (stack-cookie prologue `mrs tpidr_el0` /
`ldr x8,[x8,#0x28]`). So the process RNG is seeded ONCE with
`time(NULL)` (seconds). This is the init path, not per-signing.

## 2. Consumption: the VM draws exactly TWO rands per pass

At `0x12a2fc` / `0x12a31c` (20 bytes apart, same basic block):

```
ldr  x21, [x20]     ; x20 = stream/queue pointer
bl   rand@plt       ; w0 = rand()
mov  w2, w0         ; value -> arg
mov  x0, x19        ; writer
mov  x1, x21        ; queue
bl   #0x147630      ; PUSH (verified opcode)
... repeated once, then eor w2,w0,w21 / PUSH, POPs, iterator ...
```

So one VM pass = `PUSH(rand) ; PUSH(rand)` into a queue, later combined
with `eor`. `rand()` returns 31-bit values (bionic: `next()>>1`), but the
region words have bit31 set ~half the time (ent_probe) — so they are NOT
raw rand() outputs; they are rand-derived (shifted/ORed/combined with heap
material — consistent with the `eor w2,w0,w21` right after).

## 3. Fit result: time-seeded bionic stream does NOT contain region words

`rev/bionic_randfit.py` (TYPE_3 additive feedback, same recurrence as
`header_gen.Random3`): seeds S, S-1, S&7fffffff, (S-1)&7fffffff for the 6
clean rows + app row, 4000 draws each, 8 targets (W0,T0..T3,d2,a7,a6):

```
[0] [1] [4] [5] [6] [7] [app]: none (0/7 rows, 0/56 targets)
```

So region words are not time-seeded bionic draws. Combined with §2 (only 2
rand calls per VM pass vs 14 random words needed), the region's entropy is
NOT libc rand() output — the rand draws feed VM control flow (queue
lengths/indices), while the WORDS come from elsewhere (heap/object memory
per slice 131, whose mechanism stands).

## 4. What this closes / leaves

* CLOSES: "region = rand()/srand(time) stream" as a derivation route
  (call sites found, model tested, 0/56 hits).
* LEAVES: the heap-object mechanism (slice 131) as the only standing
  source; Path A-ext (builder-memory capture) as the only fresh-byte route.
* NOTE: `gettimeofday` (0x13e5fc) + `getpid` (0x13e600) adjacent pair and 2
  `clock_gettime` sites are unexamined — possible finer-grained seeds, but
  they sit outside the signing/VM path found here.

## 5. Artifacts

* `rev/rngsites_probe.py` + `rngsites.log` (all call sites)
* `rev/imports_probe.py` (72 imports, 26 keyword hits)
* `rev/bionic_randfit.py` + `bionic_randfit.log` (0/56 fit)
* `rev/nested_probe.py` (R == Xhi^Xlo 11/11; overlap means 0.9..7.4;
  a[0] hot bits {1,20}; full histograms per slot)
