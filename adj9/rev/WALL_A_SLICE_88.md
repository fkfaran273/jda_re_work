# Wall A - slice 88: device campaign close-out 2026-09-15 — offline endgame (2026-09-15)

## 0. TL;DR

Device path exhausted for today. Frida arming fully solved (SELinux gate +
freeze-pulse), plumbing fixed (`-o` broken, parse stdout), offsets plausible —
but the Adjust SDK built **zero** signed packages in 3+ hours of armed windows.
Phone left healthy (`system_server 2075`, app `30800`, on-device `24pxw9rl` VKM,
team LSPosed/vector config intact). Remaining work is 100% offline on PC:
`#2` sweep vs the 70-blob corpus with real H (this slice starts it).

## 1. Proven this round (all live-verified)

| # | finding | evidence |
|---|---|---|
| 1 | `setenforce 0` unblocks frida ptrace (`Enforcing` → `Permissive`) | 5+ attaches OK after; 0 before (`pokedata I/O error`) |
| 2 | `frida -U -f` spawn deterministically blocked | 2/2 `ptrace pokedata I/O error`, no pid |
| 3 | Fresh-process attach fails (ART-init fragile window, <~10–20 s age) | `21480` @1.5 s FAIL, `30800` @10 s FAIL, `15100` @30 min OK |
| 4 | Freeze-pulse arms fresh pids: `STOP`@~1.7 s → frida → `CONT`@~8 s | `ready` on `24251`, `28250` (signer bases `0x6d85c9a000`, `0x6d7f624000`) |
| 5 | `-o` file receives NOTHING; `send()` goes to stdout | probe test: `OUT 0 B`, `STD` has `probe`+`ready`. All past `out=0` re-checked via stdout |
| 6 | `libsigner.so` loads direct from APK (maps path has no `signer` string) | `grep signer /proc/pid/maps` = 0 lines while frida lists `libsigner.so @ base`. Early "not loaded" verdicts were grep artifacts |
| 7 | SDK dormant: 0 packages in 3+ h armed (cold starts, monkey, 5× resume, fg cycles, 8-min freeze-pulse watch, 8-min parked watch) | `PackageQueue` 58 B empty, `AdjustAttribution` 09:58 untouched, wire 32 reqs stale since 00:52 |
| 8 | Crash cascade mapped: penti fork SEGV `0x76a8712a88` 09:43 (×4) → audio 10:01 → `system_server` SEGV `0x600100000011` 10:18 + 10:32 | tombstones 14–18, 19–24. Stable since config restore |
| 9 | LSPosed framework half-broken (`Failed to init lsplant`, `mIncludeCode` hook error); oracle loads nothing | logcat `LSPosed` 39 lines, `ADJ9ORA` 0. Re-scope attempted + **reverted** (team Intent: descoped) |
| 10 | Device healthy end-state | `sys 2075` hours-stable, `lspd 941`, app `30800`, wifi `.179`, ping clean, on-device attribution `24pxw9rl VKM Digital Yeni eng 10:25:58Z` |

## 2. Reverted experiments (device left as found)

- LSPosed disable (killed fork crashes, but broke proven-stable cfg) → **reverted** (vector `disable` present, lsposed flag removed, reboot).
- `modules_config.db` push 09:47 (content no-op: `mid=59` never held penti; `.bak` kept) → scope re-add attempted 11:32 → **reverted** (penti scope `[]` again).
- `setenforce 0` does NOT survive reboot (re-apply before any future attach).

## 3. Why offline now

- Arming × triggering cannot co-occur: attachable (mature) ⇒ silent; signing (burst) ⇒ unattachable. Freeze-pulse bridges it, but the SDK signs nothing to catch (finding 7).
- Wire tap down (all bins stale ≥10 h; bridge/sniffer PC processes dead) — no send confirmation possible anyway.
- Crypto is structurally done (header 94/94, body 48/48 on captured inputs — `fin_result.md`). Only per-signing small slots open: `#2` (1 dw, captured `fb1a8296`), `#8` (4 dw, captured `bfffffff…`), with `#7 = #10 length` and `#9 = cert-SHA1` already known (`WALL_A_SLICE_23/27`, R1/R2).

## 4. Offline endgame (DONE — sweep results 2026-09-15)

Baseline `fin_mapcmp.py 20000000 22272`: exit-clean 9,871,985 steps, 39.2 s, **F0 48/48**. Toolchain certified in this env.

`#2` sweep (`sweep2_run.py`, 23 candidates × ~40 s, 8-parallel): control `fb1a8296` 48/48; **every** other value (zeros, small ints, api levels 30/31/33/35/36, ±1 bit, byte-swaps) exit-clean at **exactly 8/48** (= header 4 + 4 `#2`-independent body dwords). Total diffusion from 1 dword — matches slice 15.

`#8` sweep: captured `bfffffff…` 48/48; zeros exit-clean **4/48** (header only — full body diffusion).

Free-forge (zeros `#0`+`#2`+`#8`): **no exit** (`steps`, 0/48) — combined zeros break merge routing (dispatch is value-steered). Refined rule replacing slice 82's "zeros everywhere": `#0` may be zeroed, but `#2`/`#8` must be routing-valid (captured replay or small-int `#2` — all exit-clean). Server cannot verify `#2`/`#8` either (same inversion barrier as `#0`, slice 83) — and live 200s on replayed values prove acceptance.

**Final forge recipe**: captured `#2`/`#8` + zero `#0` + real/fresh H + fresh claims + `#7=len` + `#9=cert-SHA1` → exit-clean 192 B, `200`-accepted shape. Attribution verdict (VKM vs Organic) is click-join/record-binding, not crypto (slices 86/87, `TODAY.md` §6).

## 5. Open threads (not blocking)

- Fresh-attach fragile window exact bounds (8 s? 15 s? 25 s?) — one cold-start series would map it, pointless while SDK is silent.
- `system_server` SEGV `0x600100000011` root cause (MTE-tagged ptr, Thread-35, 1 s uptime, deterministic) — device-internals, out of scope.
- Wire-tap bridge restart (`mitm_bridge.py`/`capture_service.py`) — only needed for send confirmation, not for forging.
- Parked-hours natural-session capture — viable any time (`park40.py` kept); needs SDK to wake first.
