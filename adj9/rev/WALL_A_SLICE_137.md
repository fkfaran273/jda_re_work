---
title: WALL_A_SLICE_137
---

# SLICE 137 — fresh Path-A capture works end-to-end: a 12th verified row

Date: 2026-09-21 (early). One device capture, fully analyzed offline. Scripts:
`device/appcap_fast.py` (run9), `rev/find_sec5.py`, `rev/sec_sweep5.py`,
`rev/app_fin5.py`. Artifacts: `rev/app_dump.json` (2.4 MB), `rev/app_signings2.json`,
`rev/sec5_found.json`, `rev/sec5D.log`.

## 0. Result

A **fresh, genuine first-install signing** was captured live and verified offline:

```
seg0 streams = [1,1,1,1,1,4,5,8,36,90]   (full descriptor signature)
#0 W0=f0e972fe tile=[7fc85389 f33bca0d 6abfd19e e64cdf7a]   (R = 1577)
#2 = 17dd4d35   #7 = 0x168 (=360)   claims = 360 B   #9 = CONST9
second = 1789929323   (== claims created_at 2026-09-21T00:15:23.352Z+0530)
FinEx(sec, descs) -> status=exit-clean  steps=9871985  header-stream=0x5500000000
```

`steps=9871985` is the exact step count shared by every verified signing in the
campaign — the fresh row is VM-consistent by the strongest internal signature we have.

## 1. What was hard (all environment, recorded so it is not re-fought)

* **The SDK does not sign on demand.** `setSessionInterval`/`setMinTimeBetweenSessions`
  are absent from this SDK build; `Adjust.onResume()` alone is throttled and produced
  **zero emits** across five capture attempts. The ONLY reliable trigger is the
  **full wipe**: `AdjustIoActivityState` + `AdjustAttribution` + `AdjustIoPackageQueue`
  + `shared_prefs/adjust_preferences.xml` (run together, as root). Keeping
  `AdjustAttribution` (as `prep_fresh.py` does) = no signing. Full wipe → signing
  burst within ~1 s of launch.
* **The guard kill is real but beatable.** Failed runs died at 4–13 s with nemit=0.
  The winning run attached at 1.98 s and the burst landed at poll 1 (nemit 8 587),
  auto-flush (threshold 300) fired before the kill. Timing jitter matters; retry.
* **fs17 dies between runs** (phantom reaper). `TransportError` on enumerate ⇒
  respawn via `setsid /data/local/tmp/fs17 -l 127.0.0.1:27042 &` + re-forward.

## 2. The blob is NOT in the EMIT/LENQ plane — the second is found by exit-clean sweep

* The dump's value set (3 514 distinct words) contains **no 4-word header** from any
  second in ±1800 s — the blob is sectioned (slice 121) and this capture's Java blob
  hook returned `nblob=0` (the SDK's own send path again, as in slice 127).
* A naive "header words present" scan over ±1800 s gave a **false positive** at
  +600 s (4/4 by chance among 3 514 values). The robust second-recovery is
  **`sec_sweep5.py`**: sweep seconds, the true one is where FinEx **exits clean**
  (the VM only terminates when the second-dependent OP_RAND draws line up,
  slice 136). It found `sec=1789929323` = the claims' own `created_at`. Rule of
  thumb: trust the exit-clean sweep, not word-presence.

## 3. Corpus and the one exact relation, now 12/12

`app_signings2.json` adds a row with a second far from both prior families
(09-12 batch, 09-20 slice-127 row). The slice-129 tile bridge was re-checked on all
app rows:

```
row           R      K13=R||R  K02hi==R  a[6]=(R<<16)|Xlo with R==Xhi^Xlo
app (127)     cc61   True      True      True
app (135)     7345   True      True      True
app (137)     1577   True      True      True
```

→ 12/12 rows satisfy the only exact cross-descriptor relation known.

## 4. Standing state

* Verified corpus: 6 (slice 136) + 3 app rows = **9 verified signings**, all with
  descriptors + second, all reproducing exit-clean / byte-exact through FinEx.
* Region (`#0/#2/#4`) remains heap-object memory (slice 131) — not offline-derivable;
  but the **capture→segment→sweep-second→FinEx** pipeline is now a proven, repeatable
  way to mint a fully-labelled fresh row on demand.
* Next: with the pipeline working, Path A-ext can now capture a signing *while also
  reading builder memory* (`sub_9afa4`/`sub_95fc4` args) to tie region words to the
  heap objects they came from.

## 5. Artifacts

* `device/cap_run9.log` (the winning run), `rev/app_dump.json` (2.4 MB)
* `rev/app_fin5.py` (generalized segmenter; blob-stream search), `rev/find_sec5.py`
  (exit-clean + blob emit at the true second), `rev/sec_sweep5.py` + `sec5_found.json`
  (second recovery), `rev/app_signings2.json` (the new verified row)
