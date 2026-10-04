# rand_path — the wire builder is a stack-VM interpreter; the rand pair-XOR unit fully decoded

Date: 2026-09-23. Static pass over `extracted/arm64/lib/arm64-v8a/libsigner.so`.
Tools: `rev/scan_rand.py` (instruction index), `rev/vm_sim.py` (NEW symbolic VM executor,
`python vm_sim.py`), one-off censuses inlined below. This supersedes the O-LLVM tag-hub
model for this region: **`unflat_da97c.py` does NOT apply here** — the machine is different.

## 0. Headline

The "flattened wire builder" 0x100094..0x12aa44 is ONE function (prologue 0x100094,
`sub sp,#0x160`) implementing a **custom stack-VM interpreter**:

* **opcode FIFO queue** = arg1[3] (dispatch head pops one token; handlers push successors)
* **data stack** = arg1[0] (linked list, push/pop/swap/dup primitives)
* **word memory** = arg1[1] (growable u32 array = THE WIRE; frame-relative addressing)
* **loop nodes** = arg1[2] (linked list of trip counters)
* **11 descriptor objects** = arg1[4..14] (preloaded by the head loop with their data)

The two `bl rand` sites (0x12a2fc/0x12a31c) sit inside ONE interpreter handler — the
**pair-XOR fill loop** — whose trip count is the CONSTANT 4. **8 draws per activation,
4 wire words per activation, guaranteed.** The number of activations per build is
data-dependent (see §4): the corpus-consistent count is 3 activations = 24 draws
(4 units → #0's tile, 8 units → #4), to be confirmed by the logged-rand emulation.

## 1. Dispatch topology (task 1) — there is NO 64-bit tag hub

* External branches into 0x128000..0x12b000: 24 distinct targets, all from inside the
  same giant function (93× `b.ne 0x12a8b4` error/skip path, 64× `b.hi 0x12aa34`
  bounds-bail, 20× `b.hs 0x128810` subtree roots, plus per-opcode handler entries).
* The "hub" = the dispatch head at **0x100554**: `bl 0x146474` (queue empty? → exit
  0x100318), `bl 0x146478` (POP token → w0), then a **binary-search cmp w0,#imm /
  b.hs|b.lo|b.eq|b.ne tree** (0x100580..0x12a200, interleaved with handler code).
* Trampoline **0x12a8c0**: `bl 0x146470` pushes w2 (= next token) into the queue, then
  `cbz err → 0x100354` (the glue) — so each handler hardcodes its successor token(s).
  **0x12a8b4 is NOT an error**: it is the trampoline with w2=0x6d (a skip/continue
  token reached both from the tree's `b.ne` arms and from success paths like 0x129134).
* Glue **0x100354..0x100550** (runs between tokens): `mem[0] += stack-top residue`
  (running wire-cursor accumulator), `mem[mem[0]-1] = 0` (reserve a zeroed slot — the
  LENQ length-field mechanism), leaves the OLD mem[0] on the stack (the next handler's
  dst operand). Fast variant **0x1049f8/0x104a04**: pop-discard + fetch, then dispatch
  at 0x100580 **without** the glue.
* Token→handler map resolved mechanically (resolver in `vm_sim.py`); 117 distinct
  tokens enqueued at 28 `bl 0x146470` sites + 22 `b 0x12a8c0` trampolines. Seed token
  0x11 pushed at 0x10030c.

### Primitives (all decoded; push/pop/swap/dup emu-confirmed)

| VA | semantics |
|---|---|
| 0x147630 / 0x146470 | PUSH(v) — prepend node {v}, size++ (0x146470 = queue/s reg variant) |
| 0x147734 / 0x146478 | POP → w0 (empty → ctx err 3) |
| 0x147a18 | DUP (= DUPOVER 0) |
| 0x14784c | DUPOVER(n): copy depth-n element to top. Emu: [A,B] --n=1--> [B,A,B] |
| 0x147a20 | SWAP(n): swap top with depth-n. Emu: [1,2,3,4] --n=3--> [4,2,3,1] |
| 0x147304 | LOAD(off): mem[base[TOP-1]+off], 0 if OOB |
| 0x146ed8 | STORE(off,val): mem[base+off]=val, realloc-grow, cursor high-water |
| 0x1472e8 | OBJLEN(obj) = cursor - framebase (words written in current frame) |
| 0x147120 / 0x147220 | FRAMEPUSH / FRAMEPOP (base stack at obj+0x14/0x18, cursor obj+0x10) |
| 0x146558 / 0x146650 | LOOPNEW(cnt) / LOOPDEC → --node.cnt (unlink+free at 0); 59 sites |
| 0x148d10 | rand() — ONLY the two sites 0x12a2fc/0x12a31c, both in ONE handler |

## 2. The rand opcode — ordered flow through 0x129c00..0x12a380 (task 2)

Token **0x2e6** (the ONLY token in [0x2e6..0x318] with an enqueuer) → handler at
0x12a1f8, pseudo-code with VAs:

```
# entry: stack top = D (destination = current wire cursor, left by the glue)
0x12a200  PUSH 0x13; POP -> a ; POP -> v        ; pop D
0x12a248  STORE(0x13, D)                        ; save dst at frame word 0x13
0x12a260  PUSH 0x13; POP -> a ; LOAD(0x13) -> D ; reload
0x12a298  PUSH D
0x12a2b0  PUSH 4
0x12a2c8  POP -> cnt
0x12a2ec  LOOPNEW(cnt=4)                        ; *** CONSTANT 4 ***
0x12a2f8  LOOP: rand -> r1 ; PUSH r1            ; 0x12a2fc  bl rand
0x12a318  rand -> r2 ; PUSH r2                  ; 0x12a31c  bl rand
0x12a338  POP -> r2 ; POP -> r1
0x12a368  eor w2, r1, r2 ; PUSH(r1^r2)          ; THE pair-XOR
0x12a37c  DUPOVER(1)                            ; copy dst to top
0x12a394  POP -> idx ; POP -> val               ; idx=D, val=r1^r2
0x12a3d0  STORE(idx, val)                       ; mem[D] = r1^r2  (wire word!)
0x12a3dc  POP -> D ; PUSH(D+1)                  ; dst++
0x12a408  LOOPDEC -> n
0x12a414  cbnz n -> 0x12a2f8                    ; 4 iterations
          # net: mem[D..D+3] = 4 pair-XOR units; leaves D+4 on the stack
0x12a418  POP -> D4                             ; discard dst-end
0x12a42c  PUSH 0x14; POP -> a; LOAD(0x14) -> A  ; A = mem[frame+0x14] (src-ptr cell)
0x12a460  LOAD(A) -> B; PUSH B                  ; B = mem[A] (source region base)
0x12a4b4  PUSH 4; POP; POP; PUSH(B+4)           ; src+4
0x12a510  PUSH 8; POP; POP; PUSH(B+12)          ; src+12  (B+4, B+12 left for successors)
0x12a574  enqueue 0x319                         ; trampoline
```

**The whiten cycle** (each arrow = token enqueued at exactly ONE static site — proven by
the full enqueue census):

```
0x143  (enqueued by shared tail 0x12a984: PUSH 1 + tramp)
  → 0x2c3  handler 0x100bf0: P=mem[frame+0x14]; V=mem[P]; PUSH V; FRAMEPUSH;
           0x100cf4 enqueue 0x2d5
  → 0x2d5  handler 0x128ef4: P15=mem[frame+0x15]; POP V; STORE(P15, V)   ; 1 wire word
           PUSH 4 (alloc 4); 0x128fb8 enqueue 0x2e6                       ; → RAND
  → 0x2e6  THE PAIR-XOR LOOP (above): 4 fresh units at the wire end; enqueue 0x319
  → 0x319  handler 0x129888: STORE(0x16, cursor); PUSH 1; enqueue 0x329
  → 0x329  handler 0x101310: STORE(0x17, ·); src pointer +1 walk; …
  → … copy/bswap opcodes (0x19f "copy descriptor #N → wire at frame+0xc",
      0x211 "copy obj arg1[k+4] → computed dst", 0xbb/0xc0 "2-word BSWAP32 copy",
      0x99 "gather loop, data-dependent count") … → conditional shared tails
      (0x12a8d4 PUSH 4→0x99, 0x12a900 PUSH 1→0x15f, 0x12a958 PUSH 1→0x127,
       0x12a984 PUSH 1→0x143 = loop-back to the whiten cycle, 0x12a9dc PUSH 8→0x1fb)
```

The 4-word unit produced by one cycle activation is what the corpus sees as T0..T3; the
copy opcodes replicate it (tile ×8+3 in #0 — "only 4-6 distinct words" observed), and
B+4/B+12 arithmetic in the rand tail walks a source region in 4-word steps.

## 3. Answers (task 3)

**(a) Draws per signing.** 2 draws per pair-XOR unit; the unit count per activation is
the CONSTANT 4 (0x12a2b0 `PUSH 4` → 0x12a2ec LOOPNEW) — **8 draws per activation**.
Activations = trips of the whiten cycle, which are governed by runtime loop cells
(59 LOOPNEW/LOOPDEC sites, counts popped from memory built earlier — e.g. 0x99's
gather loop at 0x102058 takes its count from computed mem values). Static bound:
one cycle per 4-word per-call region. Corpus-consistent reading:
* 4 units → #0's T0..T3 (replicated ×11 by copy opcodes),
* 8 units → #4's 8 words (2 activations),
* #2's 1 word and W0/W1 = 0x2d5-style single stores / mixes (no fresh draws).
⇒ **leading hypothesis 3 activations = 24 draws = 12 units per signing** (range 8..~88
depending on trip count); the exact count is the single number the already-queued
logged-rand emulation must confirm.

**(b) The small pushes.** They are frame-slot addresses and allocation counts, NOT
descriptor ids: 0x13(19)=rand dst-pointer slot; 0x14(20)=source-pointer cell (read
twice: 0x2c3 and the rand tail); 0x15(21)=single-store dst slot; 0x16/0x17=cursor/
length cells; 4 = pair-XOR unit count AND the 4-word allocation increment; 8 = the
8-word region allocation (#4) at tail 0x12a9dc; 1 = one-word allocations/lengths;
0x19(25)=initial wire-cursor value (header length) stored at 0x100298.

**(c) Which wire words receive pair-XOR units.** The units are STORED at
mem[dst..dst+3] with dst = the running wire cursor at activation entry (frame+0x13
cell) — i.e. the units land at the CURRENT END of the region being built, never at
fixed addresses. The emit-at-index model of WALL 146 is corrected: `bl 0x146ed8` is a
memory STORE (frame-relative), not an append; the wire is later assembled per the
cursor table (mem[0] accumulator + the 0x16/0x17 length cells = the LENQ mechanism).
So the mapping is: #0's tile region = one unit quad replicated; #4's 8 words = two
unit quads; #2/W0/W1 = stored/mixed words.

**(d) Other constructions.** No single-draw sites and no rand+C at the rand sites
(both `bl rand` are inside the pair loop; the loop has no mix constant — confirmed by
l48_sweep). Everything else is value-derivation on already-drawn/store material:
* BSWAP32 chains (lsr/and/orr/lsl, e.g. 0x103490..0x1037cc) big-endian-ize each
  descriptor word before storing;
* copy loops (0x19f/0x211/0xbb/0xc0/0x99) move descriptor/object words into the wire
  (replication of the tile; claims/HMAC/static-table regions);
* ALU opcode handlers producing w2: add ×338, eor ×64, and ×48, mul ×27, orr ×25,
  sub ×44, lsl ×20, lsr ×17 — the mul/eor families are the mix() candidates between
  the rand units and the observed wire words (with the mov/movk constant pools);
* the glue's `mem[0] += residue; mem[mem[0]-1]=0` cursor/LENQ accounting.

## 4. Verdict

The "pair-XOR opcode" of WALL 146 §5b is CONFIRMED and now fully ordered:
`mem[dst+i] = rand() ^ rand()`, i = 0..3, per whiten-cycle activation, 8 draws per
activation, destinations = the running end of the wire region under construction.
The machine is a stack-VM interpreter (queue/stack/memory/loop-nodes), NOT an O-LLVM
tag machine — the da97c-style unflattener is inapplicable; `vm_sim.py` (new) is the
right instrument and already reproduces the program head (tokens 0x11→0x2d→0x50→…,
cursor accumulator 0x19→0x3d→0x45→…, descriptor #2 BSWAP32 path) before diverging on
calloc-derived pointer cells. Remaining unknown = the whiten-cycle trip count per
signing (data-dependent; leading hypothesis 3 ⇒ 24 draws) and the mul/add post-mix —
both are one logged-rand emulation away. The offline-reproduction consequence of
state_walk §4 stands: srand48(resume-second) → draw 24+ values → pair-XOR → per-region
mix → wire.

## 5. Reproduction

```
python adj9/rev/vm_sim.py            # symbolic executor; trace to stdout
# censuses used: enqueue sites (28 direct + 22 trampolines, 117 tokens),
# opcode→handler resolver, ALU census, prologue/epilogue scan — inlined in session log
```
