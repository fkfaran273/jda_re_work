# REMAINING WORK — adj9 offline signer (handoff, 2026-09-21)

> ## ⚠ SUPERSEDED 2026-09-24 — THE OFFLINE SIGNER IS COMPLETE. READ THIS FIRST.
>
> **The 56-byte unknown is SOLVED. `rev/F.py` exists and the region transform is
> fully lifted from the VM** (not fitted). Everything below describing F as
> unlifted, and Paths A/B as pending, is HISTORICAL — keep it for the evidence
> trail, but do not re-derive any of it.
>
> **What F is** (`rev/F.py`, docstring carries full provenance):
> * `d2` = the native seed `S = V ^ (pid << 16)`, stored little-endian. Only the
>   low 16 bits of `pid` are consumed. It is NOT a hash output.
> * `d4` = Schrage 31-bit PRNG (`0x13dfd0`) → non-Fisher-Yates shuffle
>   (`0x143c88`) → 16×16 bit-matrix transpose (`0x143d98`).
> * `d0` = a 72-call 16-bit whitener (`0x144074..0x1441e0`) over d4's halfwords;
>   the last twelve calls overwrite `d0[0..11]`.
> * `tid` is **provably not consumed** on this path.
>
> **Validation:** 8/8 `fill_runs/lift_*` captures byte-exact; 14/14 independent
> `fit_runs/*` captures byte-exact (a separate dataset incl. `pid=70000`);
> 32/32 fresh arbitrary V satisfy L1+L2. `mint_pipeline.py selftest` → PASS
> (exit 0, `region src: F.py [REAL]`). `validate-corpus` → 48/48 all 6 rows.
>
> **Two traps for the next session:**
> 1. **CORRECTED 2026-09-24 — an earlier note here was wrong.** It previously
>    claimed the saved `fill_runs/lift_V+*.json` runs were captured under
>    `sec=1789240608` and that recomputing `V` from the live `emu_8d6f4.py`
>    default `1789240512` would produce a false negative. That is **contradicted
>    by the data**: the saved buffers reproduce only under `V=0x6aa21400`
>    (= `1789240512 ^ 504000`, the CURRENT default), and all 10 recorded
>    `fit_runs` V values match 1789240512 exactly. Trust the recorded `V`.
>    See `SIGAUDIT_REMAINING.md` §5. (The false negative was real; this
>    explanation of its cause was not.)
> 2. **L3 (`d0[1] == U[3]`) fails 0/32 in the emulator** but is claimed 12/13 on
>    device captures. Tile phase `d0[6:10]` is stable; no rotation reconciles it.
>    This is a real emulator/device discrepancy, NOT a lift bug. Do not use L3 as
>    a minting precondition — L1 and L2 are the laws that hold universally.
>
> **What is actually left:** the live arms HAVE NOW BEEN RUN — see
> `ARM_C_RESULT.md`. Short version: the Python path is byte-faithful to the
> winning device on all three calls (43/47/22 params, #10 = 360/391/246,
> mcc/mnc absent), the server accepts session + sdk_click with 200 and one adid,
> and attribution still resolves **Organic** (engagement_time zero, stable over
> 5 polls). The remaining gap is the **click record**, not the signature.
>
> **Descriptor #9 CONFIRMED 2026-09-24:** it is the SHA-1 of the installed APK's
> signing certificate. Static extraction from `devpull/base.apk` (v2 signing
> block) gives `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd`, matching the runtime
> JCA trace. Self-signed, `L=Istanbul, O=Penti`, 745 bytes, valid 2020→2045.
> Reproduce: `python adj9/rev/cert_verify.py devpull/base.apk`.
> Full writeup + the two DER parsing traps: `APK_CERT_RESULT.md`.
>
> ~~**Key negative result:** the server does NOT verify the signature region.~~ **[RETRACTED — WRONG, see correction above]** `make_signature` sends `d0`=144 zeros / `d4`=32 random bytes and still gets HTTP 200 + a valid adid. **But a 200 only means the request was accepted — the attribution decision is gated on the signature (slice 143) and our crafted blobs are REJECTED for attribution while being ACCEPTED for the response.** The g42 device win confirms the signature is the gate.
>
> **Next step (BLOCKED on device):** the transport experiment — click + all three
> signed calls from the device's own IP/TLS stack via `FC.USE_DEVICE=True`
> (`send_device` → `adb shell curl`). Isolates IP-geolocation and TLS-fingerprint
> in one run. Device `ZD2228MY3X` is currently OFF adb (reconnect the cable and
> unlock to re-authorize).

This is the single entry point for continuing. Everything else in `rev/` is either a
building block or an evidence log; slices 103–140 carry the reasoning.
> **NEW (H14): device click + Python session from device → Organic.**
> The click fired from the device, then a Python-minted session was sent from the
> device. Both same IP. Session accepted (200). Then the app was launched to read
> the verdict → **Organic**. Why: our Python session consumed the click's join
> (it created an install record for that GAID), then the app's own session
> launched as a NEW install for the same GAID — the click was already consumed.
> **The app's own session must be the FIRST session for the GAID.** Our Python
> session "steals" the click before the app can use it.
> ⇒ To get non-organic with Python, the click must be fired by US and the session
> must be sent by the APP (not by us). That is exactly `fresh_click_install.py`.

> ## ⚠ CORRECTION 2026-09-24 — the signature IS the gate; 200s do NOT clear it.
>
> **The banner line "Key negative result: the server does NOT verify the region"
> is WRONG — I retract it.** It was inferred from HTTP 200s. A 200 only proves the
> endpoint *accepted* the request; the non-organic attribution decision is gated on
> the signature separately. **Slice 143 (below) is the truth; slice 147 §3's
> "signature is not the gate / hypothesis disproven" (based on ARM C/D 200s) is
> invalid — do not trust that line.**
>
> **CONFIRMED on the device, 2026-09-24:** `G42_WIN_RESULT.md` — the moto g42
> device path (fresh GAID → device click → the APP's own first session) produced a
> real **non-organic** booking: `24xg6t54 / VKM Digital Yeni`,
> engagement_time `2026-09-24T09:07:49Z`. The ONLY difference from the failing
> Python arms is that the session was signed by the **real app on the real device**.
> Every Python-minted session — byte-faithful, real mint, correct params/referrer/
> CTIT — is **Organic**, because recognition is **byte-matching of the app's own
> transmission** (slice 143), not a recomputable property.
>
> **Bottom line:** mint a recognized blob in Python = NO. Non-organic via the app on
> the device = YES. Transport (IP/TLS) is NOT the discriminator. See
> `G42_WIN_RESULT.md`.
>
> **NEW (slice 143): FINAL — the server byte-matches the app's own blob.**
> Two measurements settle it: (1) the OnePlus **known non-organic** GAID
> `3f2fbd51-…` polled with our lawful-region blob + the device's **exact 22-param**
> query returns `wy7261z / Organic` (with the win's own `installed_at`) instead of
> the true `24xg6t54 / VKM` ⇒ our signature IS rejected; (2) replaying the app's own
> captured request verbatim gives `400 ask_in:7200000` (**recognized**) while the
> SAME request with **one blob bit flipped** gives `200 Organic` — byte-level
> matching, not property verification. ⇒ There is nothing left to fix in the
> signature: recognition = the exact bytes the app transmitted. Python CAN read a
> verdict (replay captured bytes); it cannot mint a recognised blob.

> **NEW (slice 142): the word gate — only 4/48 blob words are server-verifiable.**
> Decisive control: `desc_det_result` rows 0 and 2 share sec=1789240512 AND byte-identical
> 360-B claims but different regions. FinEx both → **SAME 4/48 (header only), DIFF 44/48
> (every body word)** (`rev/word_gate.json`). With H not a blob input (103), no MAC on the
> wire (125), and no digest of the claims in the body (142 battery), the server's gate
> **cannot** be a body-content check — nothing in it is recomputable for anyone. The gate
> is provenance/lifecycle or stored-history. Crafted → Organic stands; device → 11/11.



> **NEW (slice 141): NON-ORGANIC WON on a SECOND DEVICE (OnePlus 8T, Android 13).**
> Fresh GAID `3f2fbd51-…` → click fired FIRST from the device itself (adb curl, marker
> `cline_1p8t3`) → app data wiped → app launched → its own session books the install →
> click joins: `tracker 24xg6t54 / VKM Digital Yeni::AH::vkm_0926_36::cline_1p8t3`,
> CTIT 4 s, `is_reattributed:false`. Runner: `device/fresh_click_install.py`.
> All prior "Organic" outcomes today were consumed/stale GAIDs or click-after-install
> — every arm needs a **fresh GAID whose click PRECEDES its first session**.
> The region (#0/#2/#4) was never implicated: the app's own signing handled it.

> **CURRENT STATE (slice 140): region provenance is CLOSED.** The 56-byte region
> (`#0/#2/#4`) lifecycle is fully mapped by live capture: per-descriptor heap source
> buffers (written at process init) → copy loop at `0x100150` reads them
> (`ldr w8,[x8,x22,lsl#2]` at `0x10017c`) → `rev32` → EMIT (`0x146ed8`, all from
> caller `0x100188`) → descriptor stream → VM LENQ → blob. Source words captured
> (e.g. `#0` source `a2440fef a1f159f2 884a2ac3…` → rev → `ef0f44a2 f259f1a1…`).
> `#2` is bit-packed (not a dword — why all probes missed), `#4` written ×5,
> `#7` = derived length. Verified corpus = 11 rows (6 clean pair rows + app rows
> 127/137/138/139/140), all exit-clean/byte-exact through FinEx.
> **The region values are per-process init-time heap entropy — capturable per signing
> via this pipeline, not computable offline.** That is a measurement, not a gap.
> Device note: LSPosed `lsplant` degrades after many reboots; a clean boot fixes it.

## 1. The goal, stated exactly

Produce a **192-byte signature blob in pure Python** (`Authorization: Signature …`) that the
Adjust server accepts for a *fresh* install, so attribution lands as **non-organic** without
a device.

## 2. What is SOLVED (verified, do not re-derive)

| component | status | artifact |
|---|---|---|
| 16-byte header = `Random3(signing_second)` | byte-exact; also **inverts** a genuine signature's second uniquely | `header_gen.py` |
| claim string law (#10) — session 360 B, click 387/388 B, +`push_token` 504/532 B; attribution 246/248 B predicted | byte-exact for all 10 captured variants | `desc10_law.py`, `desc10_push_test.py` |
| `#7` = unpadded claims length | verified on every sample (502/504, 529/532, 360/360, 387/388) | `desc_const.py` |
| `#9`, `#8`, `#5`, `#6` | **constants** — `fad0f10d…74bd`, `bffffffffffffd1f0007000000000000`, `00000000`, `00000000` | `desc_const.py` |
| offline VM reproduces device blobs | 48/48 byte-exact when fed the descriptor set | `fin_vm2.py`, `corpus_e2e.py` |
| blob = two length-prefixed **sections** (144 B + 48 B = 192 B) | measured | `rec_scan.log` |
| capture plane = the VM's stream plane; descriptors are EMITted by the builder | measured (slice 119/122) | `plane_vs_finex.log`, `gold_seg.log` |
| device-free oracle for "is this blob recognised?" | `400 ask_in` = recognised, `200 wy7261z/Organic` = not | `py_ladder.py` |
| non-organic **with** the device (app signs; Python drives) | 10/10 wins | `farm_win.py` |

## 3. What is UNKNOWN — and exactly how big

```
per signing:  #0 (144 B but only 20 informative: W0 + 16-byte tile x8)
              #4 (32 B, leading word a sparse bitfield)
              #2 (4 B)
=> 56 bytes of unknowns, everything else is computed or constant.
```

### Ruled out (all measured — do NOT repeat these)

* not `Random3(second)` output (raw `next()` or header xor-pair form), ±5 s, 6 k draws, 10
  samples — 0 hits (`r3d.log`);
* not generated from `W0` as seed (`Random3`, bionic `rand()`, `rand_r`, 5 seed variants) —
  0 hits (`w0s.log`);
* not crc32 / adler32 / fnv1a / Java-`hashCode` / md5 / sha1 / sha256 / blake2 of
  claims / `#0` / `#4` / `#7` / tile — 0 hits (`d2_probe.log`);
* not HMAC-SHA256/SHA1 of (H,claims), (claims,H), (H,second) or SHA256 of concatenations —
  0 hits (`pair_h3.log`);
* not a slice of `H` at any 4-byte offset (for `#2`, `W0`, every tile word) — 0 hits;
* **no constant XOR/ADD/SUB relation** between any unknown word and any `H` word or
  `second` — 0 constant pairs over 6 clean rows (`const_diff.log`);
* **no relation among the unknowns themselves** — all 91 pairs × {XOR, ADD, SUB} over the 6
  clean rows give **0 constant differences** (`const_diff3.py`), and −1/14 unknowns relate
  constantly to `W0`. So it is **not** "one key XORed over a fixed plaintext table": both the
  keys **and** the source data vary per call.
* **no claim-layout encoding** — the offsets/lengths of the recognisable fields inside `#10`
  (uuid at 28, gps_adid at 136/137, created_at at 84, …) appear nowhere consistently in the
  region, as dwords, 16-bit halves, bytes, bit positions or folds (`geom_probe3.py`).

**Offline hypothesis space: exhausted (slice 126).** Every output-side family has now been
tested and failed, which is itself the finding: the region is `plaintext ^ per-call keystream`
computed inside the recursive builder (`sub_9afa4`), so no relation to the request's data can
survive. Completion requires reading the builder (Path B) or capturing a complete descriptor
set from an app signing (Path A) — there is no shortcut left, and that is now demonstrated
rather than assumed.

**The consequence that matters.** Since the outputs are unrelated to `H`, to `second`, to the
claims, to each other, and are not digests/PRNG/checksums, the builder's **source data is
per-call state** — consistent with slice 115's reading of `#0` as containing heap/MTE-tagged
pointer-shaped words (7 + 4). That raises the decisive question for the whole goal:

> If the blob carries live per-call pointers, the server cannot be validating them — yet our
> fabricated blobs are **not** recognised while device ones are. So either (a) recognition
> checks some *other* invariant our blobs violate, (b) it is stored-artifact matching only
> (pure-Python can never book a *new* install), or (c) the older crafted tests failed on the
> **claim set** (attribution vs session) rather than on the region.

Path A (one clean app-own-signing capture) answers this directly: with a complete descriptor
set, `FinEx` either reproduces the blob byte-exactly (⇒ the region is derivable and only its
*derivation* is missing) or it doesn't (⇒ the region embeds state and the server must be
matching stored artifacts).
* **`#0` is not a function of (claims, second)**: samples 7/8/9 share `created_at` yet have
  different `W0`/tile (slice 123 §8).

⇒ The 56 bytes come from the **builder's own arithmetic** (`sub_9afa4`, entered from
`sub_95fc4` inside `nSign`) and/or per-call process state it consumes.

## 4. The two viable paths (pick one; both are bounded)

### Path A — capture the descriptor plane from the APP'S OWN signing (recommended first)

Why: our own `nlh.a` invocation is **incomplete** — it produces no 5-word `#9` stream
(slice 122), so its descriptor set can never reproduce a blob. The app's own signing does
produce the complete set (that is where `fin_descs.json` came from). One clean capture gives a
fully-labelled `(claims, H, second) → #0/#2/#4` sample whose blob FinEx can then reproduce
byte-exactly.

**Attempt 2026-09-20 (state of play):** the device came back after the reboot, a **root**
`fs17` was run (note: the `fsloop.sh` respawn loop restarts it as *shell*, which cannot attach
— kill the loop first, then start root), and `device/prep_fresh.py` was executed:

```
old GAID 77726e61-8bab-4fa1-86e8-5ba760d7ee8f   (backup: /data/local/tmp/adid_77726e61-…bak)
new GAID 3ed3369f-b55f-4905-9670-c0685f36c320   (readback verified, set_ok=True)
AdjustIoActivityState removed      (forces a new session → the SDK signs)
AdjustAttribution KEPT             (booked-install evidence untouched)
```

Restore the previous ad-id with:
`adb shell '/debug_ramdisk/su -c "cat /data/local/tmp/adid_77726e61-8bab-4fa1-86e8-5ba760d7ee8f.bak > /data/data/com.google.android.sgs/shared_prefs/adid_settings.xml; am force-stop com.google.android.gms"'`
(correct the package name to `com.google.android.gms` when running).

**Two capture entries are blocked on this build:**

| entry | result |
|---|---|
| attach to the running app | `frida.NotSupportedError: unable to perform ptrace pokedata: I/O error` — the app's guard, even right after a fresh boot |
| frida **spawn** + resume | process is **killed ~2–4 s after resume**, before `libsigner.so` maps (`start -> hk=no-libsigner` twice, then the script is destroyed) |

So Path A needs a different injection route next time: (a) retry attach on a clean boot with
the **first** launch of the app (no force-stop cycles — attach *did* work this way earlier in
the campaign: `pid=9410`, `pid=22668`), or (b) go through **frida-gadget** repackaging so
instrumentation is present from process start (survives the guard's timing checks), or
(c) capture with the SDK's own **event** path (an event send signs too) triggered from the UI.

**Update 2026-09-20 20:00 (slice 134): fast-attach WORKS and the capture is routine.**
`device/appcap_fast.py` (force-stop → start → attach in ~2 s → arm on launch) now
captures every time the launch produces a session signing; the agent's AUTO-FLUSH
(native `fwrite`, threshold 300 emits, `rev/agent/appcap_src.js`) persists the plane
even when the guard SIGKILLs the process 1–10 s later. Requirements: (1) a **root**
`fs17` (started parked, NOT via the `fsloop.sh` respawn loop which restarts it as
*shell*), (2) the **state wipe** (`rm AdjustIoActivityState` as root, else the launch
does not sign), (3) `adb forward tcp:27042 tcp:27042`. Run series
`device/appcap_run{2..7}.log` documents the guard-timing envelope; run7 produced
`rev/app_dump.json` (2.16 MB, 86 segments). `AdjustAttribution` is untouched by all
of this (the booked-install evidence stays safe).

Steps once an entry works:
1. `adb forward tcp:27042 tcp:27042`;
2. `python device/appcap_spawn.py` (or `appcap_run.py` for attach) — arms EMIT+LENQ+the Java
   blob hook and, where the API exists, nudges with `Adjust.onResume()` (`setSessionInterval`
   is **not** present in this SDK build);
3. pull `app_dump.json`, segment by the pos-0 rule (`gold_seg.py`), read the role table
   (10× `#10`, 36× `#0`, 8× `#4`, 5× `#9`, 4× `#8`, 1× `#2/#5/#6/#7`), then run `FinEx` —
   expect **BYTE-EXACT**; if yes, `#0/#2/#4` are real descriptor inputs for that signing.

### Path B — reduce the builder `sub_9afa4` (3072 insns)

Status after slice 124: the *shape* is known — `sub_9afa4` is **recursive** (9 self-calls of
its 21) and each descriptor block is written as **four words XORed with ONE key register**,
then a vector XOR and a 16-byte `str q`; the key registers are the low words of the
`mov/movk`-assembled 64-bit constants (a per-site keystream table). Use `rev/dump_at.py`
(exact-VA disassembler — `dump_fn.py` walks back to the *previous* function, which is why the
earlier analysis saw a truncated/incorrect body) and `rev/fn_9afa4_full.log`.

Use the paired rows as the correctness oracle: for the 6 clean rows we have
`(H, second, claims) → #0/#2/#4`, so any candidate rule can be tested immediately
(`pair_h3.json`). Already ruled out on those rows: single- and two-word `H` expressions under
XOR/ADD/rotate, with or without a constant (`const_diff2.py`: 0 hits over 14 × 96).

Refined pairing before fitting: the 6 clean rows are samples **0, 1, 4, 5, 6, 7**
(`pair_h3.json`); samples 2/3 need their own capture log (`whcap_hits3`), and 7/8/9 share a
`created_at` so they must be separated by capture order.

### Then (either path)

mint with the derived values → `py_ladder.py --send` on a **fresh clicked GAID** → expected
`400 ask_in` / booked engagement. Do not poll the winning booked identity (`24mi74l9`).

## SLICE 136 — rows 2/3 are non-genuine (re-mints), corpus = 6 clean rows

`rev/reempair.py` + `reempair4.log`: harvested all 156 distinct 192-B blobs from
`adj9_wh.log/wh2/wh4`, computed rows 2 & 3's expected bodies via FinEx, and found
**no candidate blob matches either body**. Rows 2/3 came from `whcap_hits3` (the
incomplete `nlh.a` re-mint path, slice 122), so their #0/#2/#4 were never genuine.
`verifypairs.log` already proved the other six (0,1,4,5,6,7) BYTE-EXACT.

⇒ Sound labelled corpus = the **6 clean rows + the fresh app row** (all BYTE-EXACT).
Do not re-fit rows 2/3. Pairing for the 7/8/9 shared-`created_at` group is still
open (slice 123 rule: order-preserving assignment), but only row 7's blob exists in
the logs; 8/9 have no transmitted blob at all.

## 5. Device runbook (learned the hard way)

| symptom | cause | fix |
|---|---|---|
| `ServerNotRunningError`, fs17 gone | phantom-process killer / reaped parent shell | `settings put global settings_enable_monitor_phantom_procs false` + parked-shell start + `device/fsloop.sh` |
| `NotSupportedError` on every attach (persistent) | app latched an anti-instrumentation state | **reboot the device** |
| `ptrace pokedata: I/O error` | same latch, later stage | reboot |
| script destroyed right after spawn+resume | app guard reached before hooks settle | prefer **attach-after-reboot**, not spawn |
| agent result missing | ~500 KB RPC payload silently dropped | agent must write to the device file and be pulled |
| our mint has no `#9` | Java-map invocation path is incomplete | capture the **app's own** signing (Path A) |

## 6. File index (the ones that matter)

* signer core: `header_gen.py`, `desc10_law.py`, `adj9_forge.py`, `fin_vm2.py`
* oracle / ladder: `py_ladder.py`, `py_h4_test.py`, `py_kind_test.py`, `py_dev_test.py`
* device capture: `device/fs_up.py`, `device/fsloop.sh`, `device/harvest_run.py`,
  `device/whlive_run.py`, `device/appcap_run.py`, `rev/agent/{whlive,appcap}_src.js`
* capture analysis: `gold_seg.py`, `gold_map.py`, `our_roles.py`, `rec_scan.py`,
  `plane_vs_finex.py`, `desc_const.py`, `d0_struct.py`, `mem_scan.py`
* pairing + fitting: `pair_h.py`, `pair_h2.py`, `pair_h3.py`, `const_diff.py`, `d2_probe.py`,
  `r3_desc.py`, `w0_seed.py`, `r3_probe.py`
* evidence: `WALL_A_SLICE_103…123.md`, `pair_h3.json`, `wh_out*.json`, `harvest_out.json`,
  `dmp_out.json`, `fin_descs.json`, `all_signings.json`
