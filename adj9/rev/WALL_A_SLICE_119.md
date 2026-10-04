---
title: WALL_A_SLICE_119
---

# SLICE 119 — the captured plane IS the VM's stream plane, and descriptors are NOT in it

## 0. What was tested

Slice 118's plan was: *feed the captured streams into `fin_vm2.FinEx` as the
descriptor set and see if the VM reproduces our blob.* Two scripts ran:

| script | question | result |
|---|---|---|
| `rev/fin118.py` | do the captured values work as descriptors? | **0/4 arms byte-exact** — every arm hit the 20 M step cap (no termination) |
| `rev/fin_desc_probe.py` | control: does FinEx still reproduce the golden blob? + are descriptors emitted? | **control passes** (`header law OK: True`); **descriptors 0/36, 0/8, 0/5, 0/1 present in the trace** |
| `rev/plane_vs_finex.py` | does the captured plane's slot signature match FinEx's stream plane? | **9/11 exact pairing**, 2 predicted differences |

## 1. The decisive correspondence

FinEx's stream census for the **golden** signing (reproducible offline, `fin_descs` +
second 1789240512) vs the slice-118 capture:

```
captured slot counts : [658, 107,  84, 36, 36, 8, 4, 1, 1, 1, 1]
FinEx   slot counts  : [658, 113,  90, 36, 36, 8, 4, 1, 1, 1, 1]

  q=…2656 slots=658  <->  va=0x5450001000 658      exact
  q=…2992 slots= 36  <->  va=0x5500001000  36      exact
  q=…2896 slots= 36  <->  va=0x5500002000  36      exact
  q=…7168 slots=  8  <->  va=0x5500003000   8      exact
  q=…6784 slots=  4  <->  va=0x550000a000   4      exact
  q=…5776/7024/6448/7408 slots=1 <-> 0x5500004000/5000/7000/9000   exact
  5848 → 107 vs 113   and   5344 → 84 vs 90        ASCII-carrying buffers
```

The two non-exact pairs are the buffers that carry the claim **string**: our map is a
47-pair session map (336 B) and the golden's set is 360 B, so those two buffers *must*
differ by exactly the claim-length delta. That is a **predicted** difference, not a
failure — so the identification is confirmed: **the slice-118 EMIT capture is the VM's
stream plane.**

## 2. The consequence that matters

`fin_desc_probe.py` asked, for a signing FinEx reproduces byte-exactly, whether the
descriptor words appear in the emit trace:

```
build_idx 0  (#0, 36 dwords)   present_in_emit  0/36
build_idx 9  (#9,  5 dwords)   present_in_emit  0/5
build_idx 4  (#4,  8 dwords)   present_in_emit  0/8
build_idx 7  (#7,  1 dword)    present_in_emit  0/1
build_idx 10 (#10, 90 dwords)  present_in_emit  2/90   (coincidental)
build_idx 8  (#8,  4 dwords)   present_in_emit  4/4
build_idx 2 / 5 / 6 (1 dword)  present_in_emit  1/1
```

⇒ In FinEx the descriptor **data lives in memory** (`0x5700000000 + i*0x400`, written by
the builder) and is read with LDR — it is **not** written into streams by EMIT. The
streams are **outputs**.

That explains the `fin118` failure precisely: I fed the contents of *output* streams in as
descriptor *inputs*. Same reason for the earlier confusion in slice 118 §2 — the
"`#0` shape" (36 slots, `0x90` length word, repeated 16-byte tile) is an **output buffer**
of 144 B, not `#0`'s data. `0x90 = 144` is that buffer's byte length; `0xc0 = 192` is the
blob-sized output buffer, which is exactly why it contained `blob[5..39]` verbatim.

Also settled: `#0`/`#4`/`#9`/`#7` are **not** recoverable from EMIT, so the slice-118 hope
of reading the region off the wire is closed — the region must come from **memory**.

## 3. Corrected target for the region

The descriptor table is written by the builder identified in slice 117:

| site | function | role |
|---|---|---|
| nSign `0xdb24c` | **`sub_95fc4`** `(sdk, env, &ctx, &map, &H, &status)` | builds the descriptor table (`#0…/#10`) |
| nSign `0xdbb64` | **`sub_bb548`** `(ctx, env, &H, &blob, &out)` | consumes descriptors + H, assembles the 192-byte blob |

The golden signing's descriptors were obtained by exactly such a **memory** capture
(`device/whcap_hits7.json` → `rev/fin_descs.json`). So the missing experiment is: run that
same memory capture for **our** freshly-built signing (map 47 pairs, H = 1..32, known
second), i.e.

1. hook `sub_95fc4` at `base+0x95fc4`; on leave dump the descriptor table (`#0` 36 dwords,
   `#4` 8, `#8` 4, `#2/#7/#5/#6` 1 each, `#9` 5, `#10` len/4);
2. or, simpler and argument-free, call `nlh.a(ctx, map, H, 31)` and then **scan the heap
   for the descriptor structures** (the builder's buffers persist for the duration of the
   call; the table is reachable from the pointers passed to `sub_bb548`).

With that, the earlier fully-labelled sample becomes complete:
`(claims, H, second) → descriptors → blob`, and the regression for the region is real.

## 4. Status of the pure-Python question after this slice

| item | status |
|---|---|
| header law | done (byte-exact, inverts a genuine second uniquely) |
| claim laws (session/click/attribution/event) | done / predicted-verified |
| `#7`, `#8`-const, padding, `len` | done |
| VM reproduction of device blobs | done (48/48 byte-exact with descriptors) |
| VM stream plane identified against a live capture | **done here (9/11 exact)** |
| region from EMIT | **refuted here** — descriptors are not emitted |
| region from the builder's memory | **next step** (hook `sub_95fc4` / scan after `nlh.a`) |
| is the region a function of (claims, H, second)? | open — needs the memory capture to ask |

## 5. Artifacts

- `rev/fin118.py` + `fin118.log` — the 4 descriptor arms (all step-capped, 0/4)
- `rev/fin_desc_probe.py` + `fdp.log` — control PASS + descriptor-word absence (0/36 etc.)
- `rev/plane_vs_finex.py` + `plane_vs_finex.log` — the 9/11 stream pairing
- inputs: `rev/harvest_out.json` (slice-118 plane), `rev/fin_descs.json`, `rev/adj9_material.json`