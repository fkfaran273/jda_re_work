# Wall A — slice 10: remaining, precisely specified (2026-09-11)

Question asked: what exactly blocks the claim loop. Answer below with
addresses, contracts, and the mining proof that forced the conclusion.
Scripts: `mine_body.py`, `verify_saz_like_server.py` (114/114 still PASS).

## 1. LENQ/OUTLEN exact contracts (lifted this session, small fns)

**LENQ `0x147304`** (100 insns, single `ret` at `0x1473d0`):
```
w8  = [x0+0x14] - 1          # top index (count-1)
x10 = [x0+0x18]              # data ptr
w12 = [x0+0x00]              # limit/base
w8  = [x10 + w8*4]           # TOP = data[count-1]
w10 = w8 + w1                # TOP + n  (!! n is added to the VALUE, not the index)
...opaque maze (junk 64-bit consts 0x6dbb/c058/f56d/7e88..., x15 vs
x9/x14/x12/x11 compare loop 0x147374<->0x1473ac, single live exit)...
0x1473a0: x8 = [x0+0x08]; w8 = [x8 + w10*4]   # offs[TOP+n]
0x1473d0: w0 = w8; ret
```
So `LENQ(stream x0, n w1) = offs[TOP_value + n]` — a section-aware,
value-indexed read. Our `vm_final.py` model (`data[base+n]`) is wrong in
both the table (offs vs data) and the index (TOP+n vs base+n).

**OUTLEN `0x1472e8`** (7 insns, no maze):
```
w8 = [x9=data, (w8=[x0+0x14]-1)]; w9 = [x0+0x10]; w0 = w9 - w8
```
i.e. `OUTLEN(x0) = [x0+0x10] - data[count-1]` — a VALUE difference, not a
length. Our model (`len(data)-base`) is wrong; worse, our `StreamObj` has
no `+0x00/+0x08/+0x10/+0x14/+0x18` struct fields at all (native stream =
`{?+0x0, ?+0x8, ?+0x10, count+0x14, data+0x18,...}`), so every LENQ/OUTLEN
result in the merge stage is garbage in our run — the precise reason the
dispatch POP drains at step 1253.

**EMIT `0x146ed8`**: 200+ insns, same opaque-maze style (junk 64-bit const
ladder `0x5cb8/1dac/1381/25ce...`, `stp w2,w3,[x29-0xc]` saves (n,v), single
store + `+0x80`-dword realloc grow). Maze needs the same live-exit proof as
LENQ (all const-compares resolve one way — identical construction to the
verified SM4-opaque case); the store itself is `data[base+n]=v` as modeled.

## 2. Why markers can't validate the merge (proven, not conjectured)

Dispatch at `0x100554..0x1005c4` after the isEmpty/POP:
```
tbnz w0,#0 -> die; POP -> w0; stp; cmp w0,#0x2d -> 0x128838 | == -> 0x128990
cmp #0x37e -> 0x100710; #0x19f -> 0x100830; #0xeb -> 0x100a2c
#0xbb -> 0x100db0; #0x7d -> 0x128fc0; #0x99 -> 0x1293c8; else 0x12a8b4
```
The route is a function of a *queue VALUE* (which derives from LENQ reads =
marker data in our run, real claims on device). Marker runs take edge paths
and drain (step-1253 exit, queues `[]/[]`); device runs take true paths.
Field stage (data-independent emit-per-len) is 62/62 exact; merge stage
needs REAL descriptor bytes. Of the 11 we hold 1 (H from `pairset.json`);
the 144-B core record, runtime strings, digests, ns stamps are unknown —
so forward match on the 38 is input-blocked as well as arithmetic-blocked.

## 3. Bodies are fully whitened (mining proof, 38 blobs)

`mine_body.py`: 0 dword positions < 256 anywhere; 0 XOR-triples shared by
>=30/38; 0 structural counts (44/48/62/36/11/8/5/4/176/192/144/32/20/16)
with >=5 hits. Combined with same-second 44/48 diffusion (slice 7) and
H-non-containment (slice 8): no lengths, counters, tags, or checksums are
visible. The server MUST un-whiten with the regenerated stream (shared
clock) before comparing — consistent with everything observed.

## 4. What remains, in order (all offline, no key, no device)

1. Model native stream struct (`+0x0/+0x8/+0x10/count+0x14/data+0x18`,
   who allocates: trace `0xbb548` + writer/ctx setup in orchestrator
   `0xda97c`) in `vm_final.py`.
2. Re-run marker mode → merge proceeds past step 1253 on struct grounds;
   prove EMIT/LENQ maze live-exits (same technique as SM4-opaque kill).
3. Recover real descriptor bytes for ONE oracle event (H known; core record
   = claim strings from the SAZ plaintext request + live `.data` table;
   digests = SHA-1(cert)/params computable) → forward 48-dword match on 1
   blob, then all 38.
4. Claim loop = parse fields → digests vs SAZ plaintext params, H vs
   history, stamps vs now. That is server-verification, complete.
