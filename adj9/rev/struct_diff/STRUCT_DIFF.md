# libsigner.so signing struct — on-device forensics (com.penti.app, moto g42)

**Date:** 2026-09-22 (session 18:52–23:30 IST). **Device:** moto g42, serial `ZD2228MY3X`,
Android 12 (S2SE32.28-28-4), root `/debug_ramdisk/su -c`, SELinux **Permissive** (verified).
**No frida, no attach, no force-stop.** All reads = plain root block-skip `dd` of `/proc/PID/mem`.

---

## 1. Verdict (TL;DR)

1. **The struct WAS found live in `[anon:scudo:*]` memory** — but **only during/shortly after a
   signing**, and **never at rest**. Anchor = the #9 SHA-1
   `fad0f10d 60f93c17 937b2f1e b6c09691 ae7d74bd` (raw cert-digest bytes, 20 B).
2. **The brief's at-rest snapshot model does not hold on this build.** The struct is transient:
   nSign materializes it per signing; after free it survives only seconds before scudo reuses the
   chunk. Every at-rest scudo sweep (≥ 20 snapshots across 5 processes) returned **zero** hits.
3. **The live #8 quad is NOT the brief's quad.** Live: `1ffdffff ffffffbe 00000000 00000700`
   (LE) — three of four words match the brief (`0xfffffd1f`, `0x00070000`, `0x00000000`), but the
   first word is `0xffffffbe`, not `0xbfffffff`. That mismatch (plus byte-order ambiguity in the
   brief) is why exact `#8`-pattern searches fail even when the struct is present.
4. **A complete struct capture exists for ONE signing** (pid 26530). A second full capture is
   pending (net running); everything else was lost to the detection→save race (fixed mid-session
   by piping `dd | tee | grep` so the scanned bytes are captured atomically).

## 2. PIDs and stability

| role | pid | lifetime | notes |
|------|-----|----------|-------|
| first P1 | 25451 | ~21:15–21:18 | died silently ~3 min after launch |
| earlier | 24818 | ~21:07–21:15 | SIGBUS BUS_ADRALN `0x720065`, thread `ExoPlayer:Playb` |
| mid | 27269, 27615, 28703, 582, 2887, … | 9 s – 5 min | app self-destructs with **pc=0x1** (corrupted callback in `libmedia.so` playback path) |
| **t1 capture** | **26530** | ≥ 4 min | struct captured at 22:41 (hunt3) |
| hunt4 catch | 12133 | ≥ 2 min | 3 range hits at 22:31, images later lost |
| hunt5c catch | 3919 | ≥ 2 min | 2 range hits + persist probes at 22:32 |
| hunt6 catch | 12782 | ≥ 2 min | 3 range hits + persist probes at 22:41 |

PID stability across two signings **in one process was not achievable**: the signing flush lags
its trigger by ~35–100 s (queued package → WorkManager flush), while the app dies in 9 s–9 min;
every process that stayed alive long enough to catch a signing died before the next flush.
Four single-signing captures across four processes + same-process +2 s persistence probes were
used instead.

## 3. Anchor history (what was searched, what was scanned)

Byte patterns tried (locally, on every pulled byte): `#8` as LE `bfffffff fffffd1f 00070000 0`
(raw `bf ff ff bf 1f fd ff ff 00 00 07 00 …`), raw `bf ff ff ff ff ff fd 1f 00 07 …`, BE, 16-bit
half-swapped; `#9` as raw SHA-1 bytes, LE dword, BE, ASCII hex (`fad0f10d`, uppercase), 8-byte
prefixes and the full 20 bytes; plus structural signatures (`KlcAG2cb…` adj_verification, header
`00460111`, id-table prefix `09 0e 20 21`).

Surfaces scanned (all device-side dd, sizes verified against maps):

| surface | size | result |
|---|---|---|
| `[anon:scudo:*]` rw, PIDs 25328, 3408, 25451 (prior run today) + 28703×8 snapshots, 582×2, 2887×5 | 21 MB each | **no hit at rest** (pre- and post-signing) |
| ALL anonymous rw ≤ 256 MB (400 ranges: stacks, .bss, dalvik aux, unnamed) of pid 2887 post-signing | 219 MB | no hit |
| ALL file-backed rw ≤ 16 MB (library `.data` incl. libsigner.so, pid 11818) | 32 MB | no hit |
| dalvik-main space (1 GB) + LOS (512 MB) | — | **not scanned** (excluded by the ≤256 MB rule; ART-owned, implausible for a native lib struct; device had 759 MB free) |
| 256 KB-class scudo streaming hunt during signings (hunt3–hunt11) | ~6 s/sweep × 4 workers | **4 signing-window hits** (pids 26530, 12133, 3919, 12782) |

## 4. The complete capture (pid 26530, signing `created_at 2026-09-22T21:57:26.146Z`)

Range `7bd564f000-7bd568f000` (256 KB scudo primary), SHA-1 at **0x7bd5676e60**;
allocation base (16-aligned, content start after zero fill + scudo header)
**B = 0x7bd5676d50**. Files: `t1_struct.bin` (B..B+0x160), `t1_ctx.bin` (B−0x40..B+0x200),
`t1_words.json`.

Live layout (LE dwords; strings stored as 4-byte-reversed groups):

| B+off | content | per-signing? |
|---|---|---|
| +0x00 / +0x04 | `00460111 6aaf0000` header | unknown (single capture) |
| +0x10..+0xf4 | field-id table, 52 ascending ids (9, e, 20, 21, 41, 47, …, fb07, 110000) | probably constant |
| +0xf4..+0x104 | 16-byte HMAC/key tag `cd39a024 a250c597 c7e3aafe a88a9b5e` | unknown |
| +0x104 | `00000090 00000024 00000000` (lens) | per-signing |
| **+0x110** | **#9 SHA-1 `fad0f10d 60f93c17 937b2f1e b6c09691 ae7d74bd`** | **constant (cert digest)** |
| **+0x124** | **quad `1ffdffff ffffffbe 00000000 00000700`** | bitmask; word0 ≠ brief's `bfffffff` |
| +0x134..+0x154 | 9-dword descriptor blob `40006000 20800800 00010882 60901013 28091282 72335413 0ada6f69 0274e744 747367c6` | likely per-signing |
| +0x154 | `00000168 0000005a` = claims_len 360 + 90 (brief's example: 0x183=387) | **per-signing** |
| +0x15c | `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` (adj_verification — byte-reversed dwords in memory) | constant (matches adjust-sig-findings.md) |
| +0x17c.. | `…dc859dc-54-f9-3f7d6-6d76-2147382d3e2` install id, `jut9tib0eeps` app_token, **`2026-09-22T21:57:26.146Z` created_at (per-signing!)**, `2026-09-14T17:52:12.431Z` install ts (constant), `moto g42 phone production`, `S2SE32.28-28-4`, `com.android.vending`, `15000001`, `session android5.7.0`… | mixed |

**Answer to the brief's diff questions (single-capture + probes, second capture pending):**
- B+0x94..0x123 (#0, 36 dwords): on-device this region is the **id table + H + lens** — the
  per-signing members are the lens at +0x104 (and created_at deeper in the claims block);
  the SHA-1 inside this span is constant.
- B+0x74 (#4) / B+0x64 (#2): no separate descriptors at those offsets on-device — the emulator's
  descriptor table is compacted differently; the descriptor blob lives at +0x134.
- B+0x08 (claims_len): on-device the two lengths sit at **+0x154** (`0x168`, `0x5a`).
- Persistence: +2 s same-process re-reads (`*_p2_*.bin`) are byte-identical in the surviving
  parts — struct content is stable within a signing's lifetime, then freed.

## 5. Files

- `t1/hunt3/r26530_7bd564f000.bin` — **full 256 KB range image, complete struct** (the one valid capture).
- `images/hunt5/` — pid 3919 images (race-lost content, kept for provenance) + hits.txt.
- `images/hunt6/` — pid 12782 images: **partial second signing** (`r12782_7c0564c000_*.bin`
  retains the pair-table variant at 0xcf40, header `0023c114 257f0000` — same object family,
  different signing state; SHA-1 chunk reused before capture).
- `t1_struct.bin`, `t1_ctx.bin`, `t1_words.json` — extracted capture.
- `t1/sd1`, `t1/sdcap`, `t1/sdext`, `t1/sdfb`, `t1/big` — the at-rest scan surface (see §3).
- Device-side tools: `adj9/device/hunt3.sh, hunt4.sh, hunt5.sh, hunt7.sh (atomic tee), hunt9.sh`
  (fast 256 KB-class net), `caploop.sh, extdump.sh, fbdump.sh, bigdump.sh`.

## 6. Second full capture — attempts and outcome

After the 26530 capture, seven more net campaigns (hunt10/11/12, fc3 full sweep, hunt7/8 with
atomic `dd|tee|grep` capture) fished every subsequent trigger (T, U, R, Q, P, O, N…). Result:

- **23:07:36** — last successful signed POST (`app.adjust.com/sdk_click`, HTTP 200).
- **23:20** — `AdjustEventMetadata` created (event package enqueued) but never flushed.
- After ~23:07 the SDK/WorkManager pipeline went **dormant** (send backoff after ~15
  wipe-triggered signing cycles today); flush nudges tried: resume cycles every ~90 s,
  connectivity bounce, jobscheduler force-run (no pending job existed). All scans stayed clean.

Consequently the **two-signing dword diff could not be completed on-device today**. What the
data does establish per the brief's questions:

- **PID stability across two signings: impossible in practice** — the guard self-destructs the
  process (SIGBUS/pc=0x1 in `ExoPlayer:Playb`) in 9 s–9 min, while the signing flush lags its
  trigger by 35–100 s. Only one signing per process is catchable.
- **Per-signing changed words (from capture + structure):** `created_at` (B+0x1ac region,
  e.g. `2026-09-22T21:57:26.146Z`), the two claims lengths (B+0x154: `0x168`, `0x5a`; prior
  session's emulator capture had `0x183`), the descriptor blob (B+0x134..0x154), and the header
  words (B+0x00: `00460111` vs `0023c114` in the 12782 partial). **Constant:** #9 cert SHA-1,
  adj_verification, install timestamp `2026-09-14T17:52:12.431Z`, app_token, device fields, and
  (very likely) the field-id table.
- **+2 s persistence probes** (`*_p2_*.bin`): surviving parts byte-identical — the snapshot is
  stable within a signing's lifetime.

## 7. Why the at-rest search failed (conclusions)

1. The struct is **per-signing transient state**, not persistent config: nSign builds it, the
   send consumes it, scudo frees it; content survives only seconds post-free.
2. The brief's anchor `#8` contains a value (`bfffffff`) that does not occur in this build's live
   struct (`ffffffbe` at that slot) — it must have come from the emulator replay
   (`app_reg.json` addresses 0xf54e4xxx are not device addresses) or an older signing.
3. `#9` (cert SHA-1) is the only reliable raw anchor; it appears **only inside the live struct**,
   nowhere else in 250+ MB of scanned memory.
4. Signing cadence is server/WorkManager-gated (flush 35–100 s after a wipe+resume trigger;
   dormant for 30+ min once backoff kicks in), so captures must be net-fished across many
   triggers, not scheduled.

---

# SESSION 2 ADDendum (22:25–00:00 IST, same day) — guard defeated, app stabilized, dormancy confirmed

## 8. What this session changed in the environment (USER-APPROVED)

**Root cause of the 9 s–5 min self-destructs identified: the LSPosed module
`mobi.acpm.sslunpinning` scoped to `com.penti.app`.** With that hook present every foreground
incarnation died in ~1–5 s (33 consecutive tombstones: `ExoPlayer:Playb` thread, SIGSEGV
pc=0x0 / pc=libEGL+0x30b70 / SIGBUS BUS_ADRALN with per-crash garbage fault addresses —
deterministic sabotage, not a rendering bug). With the user's approval the scope row
`(mid=4, 'com.penti.app')` was removed from `/data/adb/lspd/config/modules_config.db`
(db backed up in `/data/local/tmp/lsp_bak/` and `adj9/rev/struct_diff/tbak.db` +
`tmc.db[-wal]`), framework soft-rebooted (`stop; start`).

Result: **the app now runs indefinitely in foreground** — pid 925 lived >40 min through
login (burn account allcountrypurchase@gmail.com auto-restored), registration, product view
and add-to-cart, vs 9 s–5 min before. Note `setenforce 0` must be re-applied after the soft
reboot (it resets to Enforcing).

**Revert (when desired):**
```
adb shell "/debug_ramdisk/su -c 'cp /data/local/tmp/lsp_bak/modules_config.db /data/adb/lspd/config/modules_config.db'"
```
then `stop; start` (or re-add the scope row in the LSPosed manager UI).

## 9. Anchor search this session (all negative — consistent with §7)

| surface | pid(s) | size | patterns |
|---|---|---|---|
| scudo+libc_malloc full | 12008, 21471 | 21–35 MB | #8 quad LE/BE/dword-swapped, #9 LE/BE |
| ALL anon rw ≤ 256 MB | 12591, 31710, 9660, 12349, 925 | 192–337 MB each (≈1.1 GB total) | same + #8/#9 individual dwords |
| dalvik-main 0x02000000–0x28000000 + LOS 0x28000000–0x62000000 | 12349, 925 | ≈1.3 GB | same |
| state: crash-looping, HOME-stable, post-unhook stable, post-login, post-cart-event, post-state-wipe | 15+ incarnations | — | zero hits anywhere |

Single-dword `0xfffffd1f` hits inside the dalvik heap (0x42xxxxxx/0x43xxxxxx) are ART-internal
`(-737)` high words of 64-bit pairs, not the struct. `1500000` (adj_signing_id) exists only in a
framework boot-image table. Scudo shells `sd5\r`, `sdA\r` etc. from earlier CRLF-corrupted
scripts were empty (mksh arithmetic is 32-bit — all address math must be done in awk doubles or
host-side, as done here).

## 10. Live-struct hunt with session-1's atomic tools, on the stabilized app

`adj9/device/hunt7.sh` (streaming `dd|tee|grep` for the raw `#9` SHA-1 bytes, 4 workers, all
scudo ranges ≤1 MB, ~6 s/sweep) was run for its full 400 s window against stable pid 925 while
firing the session-1 trigger (state-file wipe + HOME + resume) plus a cart event at t+45 s.
State files updated (ActivityState 23:49) but **no flush occurred and no hit was recorded** —
the SDK send pipeline was still in the post-backoff dormancy documented in §6 (last successful
signed POST 23:07:36). The wipe made in a live process is also overwritten in-memory by the
running SDK (file rewritten on next lifecycle save); it only takes effect on the next cold start.

## 11. Per-signing word snapshots of a stable process (new artifact)

With signing-active risk low, a different artifact was captured for future diffing: three
full scudo snapshots of the SAME stable, signed-in, event-firing process (pid 925), taken
seconds apart around two add-to-cart events (AdjustEventMetadata changed 276→281 bytes
between S2 and S3):

- `tSS1/`, `tSS2/`, `tSS3/` — 117 scudo-range files each, K = LO//4096, addresses = K·4096+off
  (maps: `adj9/device/maps_925.txt`).
- Intersection of changed words across S1→S2 and S2→S3 (same address changed twice): 547 words,
  35 small clusters (`struct_candidates.json`). Best structural candidate: counter at
  0x7136e60a90 incrementing 0x99→0x9a→0x9b per event — identified as an ART store-buffer
  cursor, **not** the signer struct. No candidate matched the session-1 live layout
  (id-table + HMAC tag + #9 SHA-1 + descriptor blob), as expected while no signing is live.

## 12. Updated conclusion

Session 1's §6 verdict stands and is now strengthened: the two-signing dword diff requires
catching the live signing window, which requires (a) the stabilized app (this session's
unscoping — now available for the first time) AND (b) an active send pipeline (currently in
post-backoff dormancy; last signed POST 23:07:36). The next run should wait out the backoff
(>30 min since last attempt), re-verify dormancy is lifted via one cart event + hunt7, and —
if WorkManager still refuses — clear the backoff by wiping
`/data/data/com.penti.app/databases/androidx.work*` (untested) or by full device reboot, then
fish with hunt7 per §5's procedure.
