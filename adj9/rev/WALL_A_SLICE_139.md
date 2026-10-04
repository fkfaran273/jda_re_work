---
title: WALL_A_SLICE_139
---

# SLICE 139 — the descriptor table is laid bare in write-order (Path A-ext delivers)

Date: 2026-09-21. One capture (fresh boot, healthy-enough LSPosed) + offline analysis.
Scripts: `device/appcap_reg.py` (region+worker hooks), `rev/verify_reg4.py`.
Artifacts: `rev/app_reg.json` (2.8 MB, nemit 22288 / nlenq 65560 / nregion 3011),
`rev/app_signings4.json`, `rev/vreg4.log`.

## 0. Two independent wins

**A. A 14th verified signing.** Fresh session (`1c57dd0d`… wait, `79886b96-…`,
360 B claims, created_at 2026-09-21T10:51:51+0530 = sec 1789968111). FinEx at that
second: `exit-clean 9875063 steps` → `app_signings4.json`. The capture→verify pipeline
ran clean on the first attach after a reboot.

**B. The region write is captured and attributed.** The region hooks
(`sub_9afa4` + worker `0x962ac`/`0x96320`) confirmed again that **neither fires during
the signing** (3011 calls, 2 objects, all return 0 = init heartbeat; worker never
spawned). Instead, the EMIT plane itself shows the region being written **as the very
first events of the signing** (EMIT index 0–7), into a single 510-write stream
(`0xb2ad5480`) that IS the descriptor table, in write order.

## 1. The descriptor table, as the builder writes it (stream 0xb2ad5480, 510 words)

```
[0]      28ac9f6d                      <- #0 W0
[1..4]   4119191e cacb9568 46bd70ab aedff17c   <- #0 tile (T0..T3)
[5..35]  tile repeats (22a9191e = T1' variant)   -> #0 = 36 words, tile x8
[36..39] 1ffdffff ffffffbf 00000000 00000700   <- #8 (byte-reversed CONST8)
[40..79] 00202000 20022202 26002604 00140720 27072d02 87100da1 64148c76 d3d55a0d  x5
                                           <- #4, FIVE identical copies (8 words each)
[80..83] 28ac9f6d 4119191e cacb9568 46bd70ab   <- #0 head repeated (W0 + T0..T2)
[84..91] e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
                                           <- sha256("") (the empty-string digest)
[92..96] fad0f10d 60f93c17 937b2f1e b6c09691 ae7d74bd   <- #9 (CONST9, cert SHA-1)
[97..]   0008ac28 6d9f1941 1e19cbca ...        <- tile words, byte-shifted view
[101..]  ab70339d acc2e3b0 ...               <- #2 = 339dacc2, PACKED byte-shifted
                                            (spans two words against the sha256 block)
[114..]  4b6c6341 47326362 ...               <- #10 claims ("KlcA...", 90 words)
```

`#2` and `#7` never appear as standalone dwords — `#2` is **bit-packed** into the
stream (its bytes straddle `[101]/[102]`), and `#7` (=360) is a length the reader
derives, not a stored word. This is why every "find #2 as a dword" probe returned 0
hits (slices 123/130): it is not stored as one.

## 2. What this resolves

* **The region is in the capture.** `#0` (W0+tile), `#4` (×5), `#8`, `#9`, `#2`
  (packed) are all present in the EMIT plane in write order — the "descriptors are
  LENQ-read, not emitted" framing (slice 119/134) is superseded: the *builder* emits
  them (slice 122 was right), and the *VM* reads them back (LENQ). Both planes show
  the same buffer.
* **The region is computed before the VM walk.** It is the first thing written at
  signing start — so its inputs are whatever the builder read at process state before
  the VM (the two LENQ pre-reads `0x19`/`0x3d` are queue lengths, not the entropy).
* **`sha256("")` sits between #0 and #9** — a constant separator the maker already
  reproduces (it is in the golden `fin_descs` family).

## 3. What is still NOT answered

The EMIT hook records *values*, not *provenance*. The region words are written by the
builder at `0x146ed8`, but the **function that computes them from heap state** runs
before the burst and is not `sub_9afa4` / the `0x962ac` worker (both proven absent).
To attribute the *source* (which heap fields), the next capture must hook the EMIT
op's **caller** during the first 8 writes (return-address at `0x146ed8` entry) — one
hook, fires exactly at region-write time, no init-poll noise.

## 4. Standing state

* Verified corpus: **11 rows** (6 slice-136 + app 127/137/138/139 rows), all
  exit-clean/byte-exact through FinEx.
* Region: fully present in the capture, written first at signing time; `#2` is
  bit-packed (not a dword), `#4` is written ×5, `#0` tile ×8. The remaining unknown
  is only the *computing function*, addressable by hooking `0x146ed8`'s caller.

## 5. Artifacts

* `rev/app_reg.json` (2.8 MB) — EMIT+LENQ+region of the fresh signing
* `rev/app_signings4.json` — the verified row (sec 1789968111, steps 9875063)
* `rev/verify_reg4.py` + `vreg4.log`
* `device/appcap_reg.py` (patched: prefer exact `com.penti.app` process)
