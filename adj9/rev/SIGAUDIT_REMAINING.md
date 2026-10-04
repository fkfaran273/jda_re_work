# SIGAUDIT_REMAINING.md — verification audit of adj9 (offline, no network/device)

Scope: read-only audit of the reverse-engineered Adjust "adj9" signature scheme in
`C:\Users\Apps\Downloads\com.penti.app\adj9\rev`. No network, no adb, no device, no
live sender. Every number below was recomputed from saved artifacts in this
workspace. Findings are tagged:

- **PROVEN** — reproduced byte-for-byte from saved captures / deterministic offline replay.
- **CORROBORATED-BUT-NOT-BYTES** — consistent with independent evidence, but the
  specific claim/order/length was never captured from a real device signing.
- **UNVERIFIABLE-WITH-CURRENT-DATA** — cannot be decided with what is on disk; stated with the exact reason.

---

## 1. Attribution claim law — is the recorded 246 self-consistent with the recorded hex?

Source: `saz_blobs.json` → `units[2]` (session 3, `/attribution`, `activity_kind="attribution"`).

**PROVEN — the recorded numbers are self-consistent.**

- `claim_law_hex` = 496 hex chars = **248 bytes**; the last 2 bytes are `\x00\x00`
  (4-byte NUL padding), so the unpadded claim is **246 bytes**.
- `sha256(claim_law_hex[:-2])` = `1f1430b737c87f77c2b1aa48276458c5035859d5f27e9354a24327c5668e5138`
  — **exactly** the recorded `claim_sha256`. Match = True.
- `claim_unpadded_length` = 246, `claim_padded_length` = 248. Both agree with the hex.
- The unpadded 246 B decodes to a clean UTF-8 claim string (no embedded NUL), ending in
  `...com.penti.app15000001attributionandroid5.7.0105.0.0`.

**PROVEN — the current pipeline reproduces the recorded claim byte-for-byte.**

`mint_pipeline.claims_from_wire(params,"attribution")` → `claims_for_law` yields
**246 unpadded / 248 padded**, byte-identical to `claim_law_hex`, sha256 identical.
(Detail: the pipeline's `ADJ_SIGNING_ID` is the 7-char string `"1500000"`; concatenated
with the 1-char tail `tracking_enabled="1"` this produces the 8-char run `"15000001"`,
which is why the 21-key law lands on 246, not 247. A 247-B result only appears if
`adj_signing_id` is wrongly supplied as the full `"15000001"`.)

**The one caveat that matters (see §3): this proves internal consistency, not
device agreement.** The `claim_law_hex` field was itself produced by applying
`desc10_law.build_desc10` to the recorded wire params (`saz_body_analysis.py:99-150`),
so the SHA/length round-trip is a *self*-check of the law on its own output, not an
independent device capture.

---

## 2. Can the attribution BODY be re-derived (brute-force (V,pid))?

Seed law, read directly from `F.py:146-153`:

```
seed = ((V & 0xFFFFFFFF) ^ ((pid & 0xFFFF) << 16)) & 0xFFFFFFFF
tid  is deleted (F.py:147) — never consumed
V    = tv_sec ^ tv_usec   (mint_pipeline.make_V, usec masked to 20 bits)
```

**Search-space arithmetic (signing_second = 1789388591):**

- `tv_usec` effectively 20 bits → `2^20 = 1,048,576` distinct `V` values.
- only `pid & 0xFFFF` is consumed → `2^16 = 65,536` values.
- `(V, pid)` pairs = `2^20 * 2^16 = 2^36 = 68,719,476,736` (6.872e10).
- These collapse to `2^32 = 4,294,967,296` **distinct seeds** (each seed is hit by 16
  different `(usec,pid)` pairs, since `usec` bits 16-19 and `pid` bits 0-3 overlap).
  Brute force is over the 2^32 distinct seeds; the body depends only on the seed.

**Per-candidate cost — real numbers from this repo/machine (no invented figures):**

- `_corpus_final.log` (6 real remints): 27, 29, 41, 39, 42, 42 s → avg **36.7 s**, range 27–42 s.
- I measured one live **attribution**-sized FinEx offline: `steps=9,912,330`,
  `status=exit-clean`, **wall 42.4 s**.

**Is there a cheap shortcut? No — verified.** For a freshly minted attribution body I
checked whether the seed leaks: `d2` word (`6f05040d`) **not** in body; seed LE **not**
in body; **0/8** `d4` words appear verbatim; the signing second **not** in body. The
body is a full FinEx-VM avalanche of the descriptors (consistent with the corpus
result that changing the region changes all 44 body words). So every candidate needs a
full ~36–42 s FinEx; there is no sub-linear prefilter.

**Wall-clock estimate (exhaustive over 2^32 seeds):**

- 1 core: `6.872e10 * 42.4 s = 2.914e12 s ≈ 9.23e4 years` (~92,000 years).
- 1,024 cores: ~90 years. 100,000 cores: ~337 days.

**Verdict: NOT FEASIBLE.** Brute-force re-derivation of the attribution body is
astronomically out of reach (even a 100k-core farm needs ~a year, and the cost per
candidate is a full VM run). The historical `(V,pid)` are absent from the wire
(`saz_offline_repro.py` documents this), so the 176 body bytes are underdetermined by
the capture alone.

---

## 3. Audit: is there ANY other artifact that could byte-verify the attribution claim?

Searched the whole `rev/` tree (and the `device/` logs it references) for a real
captured attribution signing — an EMIT trace, gold JSON, or descriptor dump containing
a genuine attribution desc10 / body.

**Result: NO. There is no byte-level attribution claim artifact anywhere. Definitive.**

Evidence that attribution was searched and found absent:

- `d10scan3.log` — scanned 28 capture/JSON files for the desc10 anchor. The only
  distinct captured desc10 shapes are **click 387→388** and **session 360→360**
  (`desc10_runs.json`). It states verbatim: *"NO attribution desc10 in the logs ->
  prediction stays UNVERIFIED (session/click only)"*.
- `desc10_runs.json` (the store of REAL captured desc10) has keys `['session','click']`
  only — `attribution` is **absent**. This is the sharpest contrast: the session (360)
  and click (391→pad 392) laws are backed by a genuinely captured desc10 here; the
  attribution law is not.
- The two >120 MB logs that `d10scan3` skipped were checked directly (they live in
  `device/`, not `rev/`): `device/adj9_wh.log` (214 MB) and `device/adj9_wh2.log`
  (219 MB) — **0** hits for `initiated_by` and **0** hits for the attribution desc10
  block-2 junction `attributionandroid5.7.0`. Closing that gap changes nothing.

Files that mention attribution *alongside* a body/hex/EMIT context (all are
**predictions or maps, not captured signings**):

- `att_desc10.log` / `att_desc10b.log` / `att_kind_verify.log` — the predicted 246-B
  claim built from the device's 30-key attribution map. `att_kind_verify.log` is a
  useful cross-check: "law keys absent from the device map: NONE; map keys the law
  omits: NONE" — the 21-key selection is exactly the device map's claim-relevant keys.
- `WALL_A_SLICE_107.md` — records the same prediction.
- `gold6_audit.log` / `gold6_kinds.log` — gold6 records idx 2 and idx 5 are real
  `activity_kind="attribution"` **maps** (30/31 keys) with a captured 192-B blob
  (`gold6` idx 2), but a map + blob is NOT a captured desc10; there is no EMIT of the
  246-B claim for it.
- `whcap_params.json`, `wire_sets.json`, `wire_pairs.json`, `wh_out*.json`,
  `wh4_records.json` — mention "attribution" only as a wire/query parameter or map
  key; none contains a 246-B captured desc10.

**Conclusion for the attribution claim law:**

- **PROVEN:** 246/248 lengths, the recorded sha256, and byte-exact offline
  reproduction from the device's own 22 wire params via the current law.
- **CORROBORATED-BUT-NOT-BYTES:** the 21-key *set/selection* and the
  sorted-profile/pinned/tail/block-2 *ordering pattern* — corroborated by two real
  device attribution maps (gold6 idx 2/5; `att_kind_verify.log` "absent: NONE") and by
  the identical pattern being byte-verified for session/click. Also corroborated by the
  246-B length being unique (not any captured 360/387/391/504/532).
- **UNVERIFIABLE-WITH-CURRENT-DATA (byte level):** whether the device actually emits
  exactly these 246 bytes in exactly this order for `/attribution`. Reason: **no EMIT
  trace / desc10 capture of an attribution signing exists in the workspace.** The
  recorded `claim_law_hex` is the law's own output, so it cannot serve as independent
  byte evidence. One real attribution EMIT capture would confirm or refute it.

---

## 4. Independent re-verification of the pid claims (saved captures only, no Unicorn)

Method: read `F.py` and replay it against the saved `fit_runs/*.json` and
`fill_runs/lift_*.json` region buffers. The emulator was NOT run. All 14 fit_runs and
8 lift_runs reproduce byte-exactly (`F.region` → pack(d0,d2,d4) == saved hex).

**(a) pid enters only via `seed = V ^ ((pid & 0xffff) << 16)` — PROVEN.**
- Files: `fit_runs/validate_base.json` (V=0x6aa21400, pid=12345) vs
  `fit_runs/fit_pidonly.json` (V=0x6aa21400, pid=12346).
- Same V, pid 12345→12346: `d2` changes `00149b5a` → `0014985a` (pid consumed), and
  `d0`/`d4` avalanche. `F.region(V,12346)` reproduces `fit_pidonly` exactly. The code
  is `F.py:148`.

**(b) pid = 70000 (> 0xFFFF) reproduces exactly ⇒ low-16 truncation — PROVEN.**
- File/run: `fit_runs/fit_pidtid2.json` (V=0x6aa21400, **pid=70000**, tid=80000).
- `F.region(V,70000)` reproduces the saved region **exactly**, and
  `F.region(V, 70000 & 0xffff = 4464)` reproduces it **identically** — proving only the
  low 16 bits of pid reach the seed. (70000 ≠ 4464; the match under truncation is the
  proof.) Code: `F.py:148` `((pid & _MASK16) << 16)`.

**(c) tid is not consumed — PROVEN.**
- File/run: `fit_runs/fit_tidonly.json` (pid=12345, **tid=12347**) vs
  `fit_runs/validate_base.json` (pid=12345, tid=12346): byte-identical `d0`/`d2`/`d4`
  (`d2=00149b5a` both). Only tid differs; the region is unchanged ⇒ tid not consumed.
- Corroborating run: `fit_pidonly.json` (pid=12346, tid=12346) is byte-identical to
  `fill_runs/lift_pidtid.json` (pid=12346, tid=12347) — again only tid differs.
- Code: `F.py:147` `del tid`.

All three claims are decidable from the saved captures alone. (14/14 fit_runs and
8/8 lift_runs reproduce exactly, so nothing here required the emulator.)

---

## 5. The one documented FALSE NEGATIVE trap — the `sec` drift

**The documented claim (REMAINING_WORK.md "Two traps", item 1; F_LIFT_FINDINGS.md:147-149):**
the saved `fill_runs/lift_V+*.json` runs have `cfg: {}` and "were captured when the
harness default `sec` was **1789240608**, not today's **1789240512**"; recomputing `V`
from the live `emu_8d6f4.py` defaults gives the wrong seed and makes a correct lift look
broken.

**Confirmed — the mechanism and the current default value:**
- `emu_8d6f4.py:231` `"sec": 1789240512` (and `:233` `time_sec: 1789240512`, `:234`
  `usec: 500000`). The delta to the alleged capture value is `1789240608 - 1789240512 = 96 s`.
- The `lift_V+*.json` runs do carry `cfg: {}` (they were produced by `fill_lift.py:49`
  with an empty cfg for the `V+0` case, i.e. defaults), so the sec is not stored in the
  run file itself.

**AUDIT FINDING — the saved bytes pin these runs to the CURRENT default
(1789240512), not 1789240608.** The `effective-V` table in `F_LIFT_FINDINGS.md` lists
`lift_V+0` as `V = 0x6aa21400`, and:

- `F.region(0x6aa21400, pid=12345)` reproduces the saved `lift_V+0` buffers **exactly**.
- `0x6aa21400 = 1789240512 ^ 504000` (usec 500000 + 4 ms virtual offset) — i.e. the
  **current** default `sec=1789240512`.
- Under the alleged capture-time `sec=1789240608`, the same usec would give
  `V = 0x6aa215e0`, and `F.region(0x6aa215e0, …)` **fails** to reproduce `lift_V+0`.
- Corroboration: the `fit_runs/*.json` record `V` explicitly, and all 10 recompute
  exactly under `sec=1789240512` (e.g. `validate_base` V=0x6aa21400), and **none** under
  1789240608.

**Interpretation (careful, not overclaiming):** whatever historical default drift
occurred, the capture files that are on disk today are byte-consistent with the current
`emu_8d6f4.py` default `sec=1789240512`. As of the current file, recomputing `V` from the
live defaults **does** reproduce the lift table. So the specific figure "1789240608"
in the trap note is **not corroborated by the saved run metadata — it is contradicted**
by both the lift buffers and the recorded `fit_runs` V values, all of which match
1789240512. A residual, honest caveat: the `lift_V+*.json` files store `cfg: {}` and do
not record the sec directly, so the pin relies on the deterministic `V = sec ^ usec`
mapping plus the `fit_runs` V values (which do record V and agree). The correct warning
for a future session is therefore: use the **recorded `V` values** (and the current
default 1789240512), not a remembered 1789240608.

(For completeness, the *second* documented trap — L3 `d0[1]==U[3]` failing 0/32 in the
emulator but 12/13 on device — is an acknowledged emulator/device discrepancy and is
out of scope for this byte audit.)

---

## Bottom line

- Attribution claim law: 246/248 and the sha256 are **PROVEN** self-consistent and
  reproduce byte-exactly from the device's own wire params; the 21-key selection is
  **corroborated by two real device attribution maps**; but it is **not byte-verified**
  against a real device desc10, because **no attribution EMIT/desc10 capture exists in
  the workspace** (definitive — `desc10_runs.json` has only session/click; the two
  >120 MB logs contain zero attribution markers).
- Attribution body: re-derivation is a `2^32`-seed search at ~36–42 s/candidate with no
  shortcut ⇒ **not feasible** (≈92,000 core-years; ~337 days even on 100k cores).
- pid/tid laws: **(a), (b), (c) all PROVEN** from saved captures alone (no emulator):
  seed = `V ^ ((pid & 0xffff) << 16)`; pid=70000 truncates to 4464 and reproduces
  exactly; tid is not consumed.
- The `sec`-drift "false negative" trap: the current default is 1789240512, and the
  saved lift buffers + recorded fit_runs V values pin the captures to **1789240512**,
  **not** 1789240608 — the documented 1789240608 figure is contradicted by the data.
