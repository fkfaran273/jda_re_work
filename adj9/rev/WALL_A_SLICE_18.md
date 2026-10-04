# Wall A — slice 18: probe inputs specified + assembly route is arg-dependent (2026-09-11)

## 1. Probe synthetic inputs, fully specified (`Hook.java:311–380`)

Base = the intercepted LIVE map/H/level (fresh clones every call —
the earlier A1∼A2 false-positive class is fixed in this revision):

| tag | construction |
|---|---|
| A1/A2 (+A3) | same live `(map, H, lvl)` — determinism baseline |
| B1/B2 | `z = new byte[h.length]` (H ≡ 0, len 32), same map/lvl |
| C1 | `hf = h.clone(); hf[0] ^= 0x01` (first-byte flip) |
| D1/D2 | live map + first-key value `+"X"` (`# map_key_modified=` + old value logged in `probe_result`) |
| E1/F1 | level 30 / 31, same map+H |
| log | `probe_start` (arg3_len, level, map_size, real blob hex), `probe_result` (10 rows + 9 diffs + 5 headers), `burst_*` |

`probe_blobs.json` = 4 runs × 10 blobs (all 192 B) consumed in slice 15.

## 2. Heap Rosetta: dead with evidence (not re-attempted blindly)

`heapProbe` reads `/proc/self/mem` in-process → `heapprobe_err` in every
hp log (`adj9_hp*.log`, slice-6 §5.1 predicted: app UID `dumpable=0` ⇒
EACCES). `live_probe.log` (345 KB) contains zero hits/sinks. External
dumps (`hp_0/1/2`) mistimed quarantine (slice 11: 0 hits). Closed three
ways; further heap work must be synchronous in-call (R2 pattern), and the
only synchronous prize left is real descriptor bytes (R4).

## 3. `0xbb548` hub walked as far as statics allow (`unflat_bb.py`, `walk_bb.py`)

Hub `0xbb668`, 18 work blocks, entry `x9=0x522b857231f0c047`, same
x9-state family as `0x24a40` — BUT prologue ends with
`cmp x3,#0; ccmp x2,#0; csel x19,x9,x8,ne` ⇒ **`x19 = {2 values}`}** on
function args `(x2, x3)`. First alias edge (`cmp x8,x10==entry → hub`)
materializes `x9 := x19` = ambiguous ⇒ static visit order forks on
runtime args (real stream pointers/counts from the caller). Third
independent confirmation of the same wall: merge dispatch (slice 10),
LENQ-outside (fine), assembly route (here) — all value/arg-dependent.

## 4. Strategy locked (no more alternatives left to test)

Forward match and static assembly order both bottom out at R4 concrete
inputs. The economical endgame is the INVERSE + known-plaintext search:
complete exact inverse arithmetic (LENQ ✓ slice 14, EMIT store ✓ slice 16,
`0xbb548` order via unflattener WITH concrete args from R4) → parse any
real blob → locate the 13 known dwords (H 8 + cert-SHA1 5, ±rev/endian) +
level/small-ints + sec-anchored timestamps directly in the parse. The 7
unknown payloads then never need independent recovery — they are READ OUT.
Cheapest supplier of R4 args remains one synchronous device run (R2
pattern: in-call logging, no timing race); the B-corpus (H≡0) is the
simplest first target.
