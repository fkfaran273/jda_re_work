---
title: WALL_A_SLICE_120
---

# SLICE 120 — memory capture of the builder: what it yielded, and the route it closes

## 0. What was attempted

Slice 119 concluded that the descriptor table is **memory**, not EMIT. So the agent was
extended to hook the builder `sub_95fc4` (`base+0x95fc4`) and dump a window at each of its
arguments on return, plus larger windows around the stream arena.

## 1. Results

**Captured (good):** `rev/dmp_out.json` — four 8 KB windows, the builder's surviving
pointers:

```
ndumps 4  bhook=already
  arg1 0xb400006d71881590  8192 B      (JNIEnv*)
  arg2 0x6beb88dbe0        8192 B
  arg3 0x6beb88dda0        8192 B
  arg4 0x6beb88dda4        8192 B      (arg3/arg4 4 B apart -> &H / &status)
```

**Analysis (`rev/mem_scan.py`, `mem_scan.log`)** — over all four windows:

| search | result |
|---|---|
| claim string (`KlcA…`) / any claim key (`android_uuid`, `gps_adid`, `activity_kind`) | **absent** |
| 16-byte repeating tile (`#0` shape) | only **zero** tiles (`00000000 ×3, 00000003`) — not the region |
| sparse ascending 8-dword blocks (`#4` shape) | only `ffffffff` runs and ASCII fragments |
| any **blob dword** appearing in the windows | **0 hits** |

So the builder's argument windows are small control structs; the descriptor table and the
blob live elsewhere on the heap. The wide arena dump was attempted and **failed**
(`readByteArray` across an unmapped hole), and the follow-up variant — page-aligned
per-stream window dumps — **destabilised the target** (script destroyed mid-call on every
attempt, 3 runs). That variant is reverted; the agent is back to the known-good
configuration and recompiles (`485 233 B`).

## 2. The route this closes

Combining this slice with slice 119:

1. descriptor words are **not** in the EMIT plane (`#0 0/36`, `#4 0/8`, `#9 0/5`, `#7 0/1`);
2. the captured EMIT plane **is** the VM's stream plane (9/11 exact slot pairing);
3. feeding stream contents in as descriptors **fails** (0/4 arms, all step-capped).

⇒ The descriptor table is neither emitted nor reconstructible from the emitted plane, so
**the region cannot be obtained by inversion from a device's output**. It must be read from
the input side — the builder's writes — which is exactly what the golden `fin_descs.json`
came from (`device/whcap_hits7.json`).

## 3. Device-path lessons (worth recording, they cost hours)

| symptom | cause | rule |
|---|---|---|
| `fs17` dies seconds after start | Android's **phantom-process killer** reaps children of `adb shell` | `settings put global settings_enable_monitor_phantom_procs false` (root) **and** start fs17 via the parked-shell `Start-Process` trick |
| `NotSupportedError` on every attach, persistent | app latched an anti-instrumentation state across many attach attempts | **reboot the device** — attach then works first try (`round 0 pid=9410 ok`) |
| script destroyed right after `spawn`+resume | app's own guard, reached before our hooks settle | prefer **attach-to-running** after a reboot; keep spawn as fallback |
| harvest returns empty detail | ~500 KB RPC payload silently dropped | agent writes to the device; pull the file |

## 4. Remaining plan (unchanged in substance, now unblocked in method)

1. **Capture the descriptor table from memory using the golden mechanism** — i.e. the
   `whcap`-style hook that produced `fin_descs.json` (it captured descriptors as memory
   reads, not EMIT), run against **our** freshly built signing (map 47 pairs, H = 1..32,
   known second) ⇒ first fully-labelled `(claims, H, second) → #0/#2/#4` sample.
2. Alternatively hook the **assembler** `sub_bb548` (slice 117), whose arguments reference
   the descriptor table just before the blob is assembled — a single, well-defined dump.
3. Sweep: same map / different second, and one-claim-changed / same second ⇒ fit the region.
4. Final proof: device-free mint + send on a fresh clicked GAID.

## 5. Artifacts

- `rev/dmp_out.json` (43 918 B) — builder argument windows (new)
- `rev/mem_scan.py` + `mem_scan.log` — the search above
- `rev/harvest_out.json` (519 288 B) — stream plane of the same signing
- `rev/agent/harvest_src.js` — agent v3 (builder hook + arg dumps); window-dump variant reverted
- `device/fs_up.py`, `device/harvest_run.py` (3-round attach), `device/harvest_spawn.py` (spawn variant)