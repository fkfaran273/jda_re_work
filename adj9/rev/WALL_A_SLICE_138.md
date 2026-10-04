---
title: WALL_A_SLICE_138
---

# SLICE 138 — Path A-ext works (region walk captured) + sub_9afa4 attribution corrected

Date: 2026-09-21. Device capture + offline verify. Scripts: `rev/agent/appcap_reg_src.js`
(new agent: appcap + `sub_9afa4`/9-site hooks + persistent `armRegion` timer + hardened
guard disarm), `device/appcap_reg.py`, `device/appcap_reg_spawn.py`, `rev/verify_reg.py`.
Artifacts: `rev/app_reg.json` (2.7 MB), `rev/app_signings3.json`, `rev/vreg.log`.

## 0. The win — a fresh CLICK signing, captured with the builder hooked

After two reboots (the app latch + fs17 fragility are both boot-cleared), a
**first-launch fast-attach** landed the full pipeline:

```
[attach] OK pid=10643 after 2.77s
hk=0x7875243000   region armed (timer)   <- libsigner mapped, hooks live
signing burst: nemit=22336 nlenq=65628 nregion=1220   (2.7 MB pulled)
```

`verify_reg.py` on seg0 (`[1,1,1,1,1,4,5,8,36,97]`, 97-w click claims, new
android_uuid `1c57dd0d`):

```
#0 W0=70ffe729   #2=a4c0c178   #7=388   claims=388B
EXIT-CLEAN sec=1789965827  steps=9889399  stream=0x5500000000
```

**A 13th verified row** (`app_signings3.json`), and the first *click* kind verified
through the new pipeline (step count 9889399 > session's 9871985, as 388 B predicts).

## 1. The correction — sub_9afa4 is NOT the signing-time region builder

The 1220 region hits are **all one object** (`0xb4000079e65e18d0`, one vtable,
return `0x0` every time), and **zero** of the 9 recursive sites fired. Identical
pattern in the earlier spawn run (object `…dec1c70`, same vtable, 4001×). That is a
**heartbeat/poll at process init**, not the descriptor walk.

⇒ The slice-131 reading ("`sub_9afa4` recurses over heap objects to build the region")
is **wrong for the signing path**. It is entered at init on a single object and never
recurses during signing. The region (`#0/#2/#4`) for this verified signing was built
by code our `sub_9afa4` hook never saw — i.e. the true builder runs **inside nSign on
the send thread**, downstream of `sub_95fc4`, and is a *different* function.

## 2. What this pins down — and the REAL builder found

* The capture pipeline (wipe → first-launch fast-attach → region-armed timer →
  auto-flush) is now robust and repeatable. Reboot clears both the attach latch and
  fs17 death; the spawn path is inferior (libsigner maps only after the guard's
  `raise(19)` SIGSTOP engages, so spawn never gets the hooks in time).
* **The real region builder is found.** `sub_95fc4` (the marshaller) ends with
  `pthread_create(x2 = 0x962ac)` — it **spawns a worker thread** at **`0x962ac`**
  that runs the signing work on its own thread. That worker (`fn_962ac.log`,
  ~800 insns) is the O-LLVM-flattened builder: it reads the global object
  `[0x155aa8]`, calls vtable slot `0x20` (`0x96320 blr x8`), and its `mov/movk`
  constants are the per-site keystream table (same family as slice 124/136's
  `w22/w13/w15/w12` keys). **The region words are produced inside this worker
  thread**, which is why the `sub_9afa4` hook (init poll, different thread) never
  saw them.
* Next hook target: the worker's vtable call at `0x96320` (`blr x8` after
  `ldr x8,[x0]; ldr x8,[x8,#0x20]`) — capture its return values during a live
  signing; those returns ARE the region plaintext. One hook, well-defined.

## 3. Standing state

* Verified corpus: 6 (slice 136) + app rows (127, 137 session + 138 click) =
  **10 verified signings**, all reproducing exit-clean / byte-exact through FinEx.
* Region builder = **`0x962ac` worker thread** (spawned by `sub_95fc4`). The
  remaining single experiment: hook `0x96320` during a live signing and read the
  vtable-call returns → the region plaintext, attributed.

## 4. Environment failure this session (recorded, blocks Path A-ext right now)

After 3 reboots in one day, the device's **LSPosed is degraded** (`lsplant`: "Failed to
init class linker / lsplant", `LoadedApk#createClassLoader NoSuchFieldError`). The app
runs (MainActivity resumed, Adjust pool threads active, unsigned `/event` sends return
200) but **libsigner never maps** — the signer initializes only on a *session* send, and
the module-driven SDK path that triggered it in the working captures (00:12, 09:33) is
not active with broken `lsplant`. Repeated force-stop/wipe cycles then latched the app
(only one clean attach per boot; `NotSupportedError` after). **Fix: a clean boot with
LSPosed healthy** (reinstall/refresh LSPosed if `lsplant` stays broken), then the proven
sequence: wipe → first-launch fast-attach → capture.

The capture tooling itself is proven and unchanged; only the device environment is down.

## 5. Artifacts

* `rev/agent/appcap_reg_src.js` (+ `_patch_reg*.py`), compiled `appcap_reg.js` (494 KB)
* `device/appcap_reg.py`, `device/appcap_reg_spawn.py` (spawn = inferior, documented)
* `rev/app_reg.json` (2.7 MB), `rev/verify_reg.py` + `vreg.log`, `rev/app_signings3.json`
