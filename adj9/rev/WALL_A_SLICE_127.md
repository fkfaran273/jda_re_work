---
title: WALL_A_SLICE_127
---

# SLICE 127 — the app's own fresh signing reproduces byte-exactly (Path A data)

## 0. Capture (2.65 MB, survived by flushing mid-run)

`device/appcap_fast.py` (fast-attach ~2 s after launch so the guard doesn't engage, arm on
resume, write `app_dump.json` the moment a signing burst appears instead of on stop).
The run survived the SIGKILL race: `nemit=19205 nlenq=51186` at poll 1, flushed, then the
kill arrived as usual. (`device/appcap_spawn.log`, `device/appcap_fast.log`)

Key capture facts: the SDK's own launch-time signing on a fresh process; planes
`nemit=22272 nlenq=65540`; Java blob hook produced `nblob=0` (the SDK's own send ran on a
path the Java hook misses), so the emitted blob is read from the plane instead.

## 1. Segmentation + role table: complete, fresh, genuine

`rev/app_seg.py` (pos-0 segmentation per slice 122): 97 segments; segment 0 has the full
signature `[1,1,1,1,1,4,5,8,36,90]`. `rev/app_pair.py` compares it against the golden
segment field by field:

```
golden seg0 : #0=13271271…  #2=fb1a8296  #4=00100400…  #9=fad0f10d…  #10='KlcA…'(90w)
app    seg0 : #0=ae2efc57…  #2=8333f07a  #4=80001000…  #9=fad0f10d…  #10='KlcA…'(90w)
app seg0 == golden seg0 : False
```

So: **fresh `#0/#2/#4` (a genuine new signing), same `#10/#9/#8` family** — exactly the
ground truth the campaign has been missing (our own mints lack `#9`; this one has it, and
the captured `#9` equals `CONST9` again — session-constant).

## 2. The decisive test passes 2/2

`rev/app_fin2.py`: feed seg0's descriptors (with `#9` in *both* the captured and the
golden-`CONST9` forms) into `FinEx`, with the segmented blob's own header as target
(`second=1789903463`, `Random3` verified):

```
#9=CONST9(golden)     exit-clean 9871985   BYTE-EXACT
#9=captured(fad0f10d) exit-clean 9871985   BYTE-EXACT
=== RESULT: 2/2 byte-exact ===
```

**Conclusion: the descriptor plane is sufficient.** The offline VM reproduces a *fresh*,
*witnessed-on-device* signing. Nothing schematic stands between the descriptors and the
blob; only their *derivation* remains.

## 3. New row in the corpus

`rev/app_row.py` → `rev/app_signings.json` (currently one row):

```
d0 W0=ae2efc57 tile=['fea674a4','b13ff75c','32c726dd','7d5e3b3d']
d2=8333f07a d7=00000168 claims=360B second=1789903463  (blob: seg96 of app_dump)
claims carry created_at 2026-09-20T16:50:45.956Z+0530 (fresh vs the 09-12 family)
```

This row is the first with a *device-second* far from the original 10-sample family and
with the descriptor/blob pairing established by construction (not by index or time guesses).

## 6. The region carries zero claims information

`rev/fold_probe.py` plus a deduplication over the corpus: **9 distinct claim strings across the
10 real signings**, and rows **7 and 9 share the identical 360-byte string**:

```
[7] d0=13271271db50f44cb63798ccdab7f51a  d2=fb1a8296  d4=00100400041440008000c440
[9] d0=f1a55b5b9949bda6011d4d1e13227bce  d2=4bce691e  d4=0010008000b000a82098003c
```

Folds (XOR/ADD over LE/BE dwords) and digest vectors (sha256/sha1/md5/blake2s, first-word and
windowed) give **0 hits on all 10 rows**.

So with the claims held *perfectly constant*, the entire 56-byte region still varies. The
region stores **no claims content**. Combined with slice 123 §8 (same `created_at` ≠ same
region) the region's only admissible inputs are per-signing: (`second`, `H`). The fit must
therefore regress the region **purely on (`H`, `second`)** — which makes the full 10-row
pairing (`pair_h3.json`, order-preserving assignment for the shared-`created_at` groups) the
gate for the whole derivation, not just bookkeeping.

`rev/abl9.py` — same winning arm, one descriptor swapped for its zero buffer:

```
baseline (#9=CONST9):  exit-clean 9871985   BYTE-EXACT
#9=zeros:              exit-clean 9871985   diff 40/48
#8=zeros:              exit-clean 9874921   diff 44/48
```

Both keep the VM terminating (steps change only for #8) but destroy ~44 body dwords. So
`#9` is a genuine merge *input* — it steers the output — even though its value is the same
constant across sessions. That also confirms the slice-119 trace reading was an artefact:
`0/5` presence in the *output* streams proves nothing, because descriptors are *read*
(`LENQ`), not emitted, and `#9` is read somewhere in the 9.87 M-step walk. The remaining
question for `#9` is only *where* inside the VM it is read (PC-level), not whether it matters.

- `rev/app_dump.json` (2.6 MB), `rev/app_seg.py`+`app_seg.log`, `rev/app_pair.py`+`app_pair.json`
- `rev/app_fin2.py`+`app_fin2.log` (2/2 BYTE-EXACT), `rev/app_fin.py`+`app_fin.log` (the
  superseeded attempt — its `cands[:4]` arm ordering put the blob in seg96, whose roles it
  then failed to fill; `app_fin2` fixes this by segmenting the *same* seg0)
- `rev/app_row.py`+`app_row.log`, `rev/app_signings.json`
- `rev/abl9.py`+`abl9.log` (#9/#8 ablation results above)
- `rev/fold_probe.py`+`fold_probe.log` (claims-fold negative + the 7/9 shared-claims control pair)
- `device/appcap_fast.py`, `device/appcap_run.py`, `rev/agent/appcap_src.js` (thread filter
  variant that crashed the target is reverted; the known-good build is `appcap.js`)