---
title: WALL_A_SLICE_132
---

# SLICE 132 — the 4 block sites are STRING decryptors, not region inputs (correction)

## 0. The slice-132 hypothesis, tested and REFUTED

Slice 132 (first version) read the 4 `str q0` sites as "the builder's region
inputs are ciphertext decrypted in place". File bytes at the three page VAs:

```
0x153950 ^ 0x12 = "()Ljava/lang/String;\x00\x12\x12\x12..."
0x1537a0 ^ 0xc8 = "android/util/Base64\x00\xd1\xd0\xd6..."
0x1537c0 ^ 0x9d = "(Ljava/lang/String;I)[B\x00=..."
```

These are **obfuscated Java type/method descriptors** — the standard OLLVM
string-cryptor also documented in `rev/decryptors.py` (same
`ldr q / eor v / str q / strb latch` shape, same `movi v1.16b,#key` keys).
Decrypted blocks match NO tile word on any of the 11 rows (0 hits), and the
"R-tag = decryptor stream position" claim is withdrawn: R's mechanism is
still unexplained.

## 1. What the correction changes (and what it does not)

* The 4 sites supply JNI string constants to the builder's vtable calls
  (the `ldr x8,[x8,#off]; blr x8` prologue at all 9 self-call sites), not
  descriptor words. Path B's "dump pages + decrypt + match region" step is
  void — those pages hold strings.
* Unchanged: the builder walks live Java heap objects (`sub_9afa4(obj, 0)`
  recursion, slice 131 §0) — that reading stands on the call prologues
  alone and is independent of this correction.
* Unchanged: the region's inputs are heap/object memory (slice 131) and
  the output-side batteries remain 0-hit (slices 123-130 + R-aware reruns).

## 2. Where the work goes next (no device needed for the first two)

1. `sub_95fc4` (186 insns, `fn_95fc4.log`) — NOT recursive, calls
   `sub_9afa4` once (`0x96204`) plus pthread/thread + latch helpers. Read it
   as the argument marshaller: which Java objects/fields it loads before
   the `bl #0x9afa4` tells us exactly what memory the region words come
   from (vtable slots 0x548/0x558/0x30/0x390/0x388/0x110/0x108/0xf8/0x640
   are the next identifiers to resolve).
2. `sub_bb548` (`fn_bb548.log`) — the H-consuming assembler: how H enters
   the blob (H is not IN the blob per slice 103, so this fn's use of H is
   the remaining H question).
3. Path A-ext unchanged: builder-memory capture is still the only route to
   fresh region bytes (device up: `fs17` root, app pid 21973).

## 3. Artifacts

* `rev/strsites_probe.py` (4-site dump) — kept; interpretation corrected
* `rev/recargs_probe.py` (9 self-call prologues)
* `rev/bridge3_probe.py`, `rev/const_r_probe.py` (R-aware batteries: 0 hits)
* `rev/fn_9afa4_full.log`, `rev/sub_95fc4.log`, `rev/fn_95fc4.log`

