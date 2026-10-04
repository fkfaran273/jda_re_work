---
title: WALL_A_SLICE_134
---

# SLICE 134 — fresh CLICK signing captured: #2-candidate refuted, blob is an output section

## 0. Capture (Path A, first fresh CLICK ground truth)

`device/appcap_fast.py` + agent auto-flush (threshold 300 emits) + state
wipe (`AdjustIoActivityState` deleted) → `app_dump.json` 2.16 MB, 86
segments. **Segment 27** is a complete CLICK signing:

```
n=1 : 000000c0 / cd9d3a91 / 00000183 / 00000000 / 00000000 / 00000019
n=4 : bfffffff fffffd1f 00070000 00000000   (#8 = CONST8)
n=5 : fad0f10d 60f93c17 ...                (#9 = CONST9)
n=8 : 00010201 00080801 ...                (#4, 8 words)
n=17: a6de2582 808c3d49 ... 000000c0       (17-word stream, NEW)
n=36: fdda97ce b559bc7d ...                (#0)
n=48: 78c5da5d 25356594 ...                (blob, second=1789914579 header law)
n=97: 4b6c6341 ...                         (claims 388 B; created_at 2026-09-20T19:59:38)
```

## 1. `cd9d3a91` is NOT #2 (decisive, `app_fin4.py` + `d2cands.py`)

FinEx with the seg27 roles (`#2=cd9d3a91`, `#7=387`, `#10`=claims):

```
roles: #0=fdda97ce #4=00010201 #9=CONST9 claims=388B
status=exit-clean steps=9885778 diff 44/48     (header 4/4, body 0/44)
```

Same signature as feeding zeros (`abl9`: 44/48). And content-wise,
`cd9d3a91` is in NO plane of its own signing (blob BE/LE, claims BE/LE:
all False). **The largest single word in the segment is not the
descriptor** — the slice-127 `#2` rule (max-popcount) was a heuristic that
happened to work once.

Additional controls from `d2cands.py`: #2-cand is not in the 17w stream,
and no 17w dword is in #4 or shares halves with a[6].

## 2. The 17-word stream IS the blob's body section, verbatim

```
17w = a6de2582 808c3d49 08734189 87339b88 51d6e846 646339ce 758710b9 a436119e
      (same 8 words) x2 + 000000c0
17w dwords in blob: ALL 16 non-trailing dwords (verbatim, in order)
```

So the 17w stream is the VM's OUTPUT section #2 (16 body dwords + the
`0xc0`=192 length trailer), not an input descriptor. The blob's body words
are assembled in-plane; feeding any wrong input still exits clean with a
wrong body (44/48), consistent with every ablation so far.

## 3. Consequence

* No new #2 candidate exists in seg27: the TRUE #2 (1 word) never crossed
  the EMIT plane in this capture — same as slice 119's finding that
  descriptors are LENQ-read (memory), not emitted.
* The corpus gains a verified CLICK row anyway (claims law + header law +
  role table all check out): `app_signings.json` row 2
  (`second=1789914579`, `#7=387`).
* The remaining target is unchanged and now sharper: capture the TRUE #2
  (LENQ plane, as in `wh_out.json`'s LENQ reads) for a known (claims, H,
  second) — or read it from builder memory (Path A-ext).

## 4. Artifacts

* `rev/app_dump.json` (2.16 MB, run7), `rev/app_fin3.py` (retired: brute
  window inverted the header too slowly), `rev/seg27_probe.py`+.log,
  `rev/app_fin4.py`+.log, `rev/seg27_multi.py`+.log, `rev/d2cands.py`+.log
* `rev/agent/appcap_src.js` (auto-flush + native fwrite dump) → `appcap.js`
* `device/appcap_run{2..7}.log` (guard-timing series: kill in 1-10 s)
