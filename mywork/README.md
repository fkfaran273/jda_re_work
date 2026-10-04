# mywork — isolated workspace for the Python-vs-libsigner byte-diff investigation

Created 2026-09-27. All files here are **copies** of others' work (originals in
`adj9/` untouched). Nothing in `adj9/` may be modified by this workstream.

## Goal

Ground truth (user-confirmed): Python network requests + **on-device
`libsigner` signatures** → NON-ORGANIC attribution. Python-minted (`F.py`)
signatures for the same payload shape → ORGANIC. Transport, TLS, and
GMS/Play-provenance hypotheses are **refuted** — the gate is inside the 176-byte
signature body. Task: feed identical inputs to device `libsigner` (via Frida/oracle)
and to the offline signer, then byte-diff outputs to isolate the mismatching field.

## Environment state (verified 2026-09-27)

- Device `ZD2228MY3X` (moto g42) **connected**, root OK (`/debug_ramdisk/su`).
- `com.penti.app` installed; `lspd` running; LSPosed oracle module installed —
  live control files present:
  - `/data/local/tmp/adj9_sign_in` (2849 B, 2026-09-24 22:33)
  - `/data/local/tmp/adj9_sign_out` (1245 B, 2026-09-25 21:08, `AUTH 0/1...`)
  - `/data/data/com.penti.app/files/adj9_capture.log` (10.8 MB)
- `frida-server` binary present at `/data/local/tmp/frida-server` (53.5 MB);
  **not currently running**. One adb invocation should both start it and probe.

## Two proven mint bridges (choose one; LSPosed is guard-proof)

1. **LSPosed oracle (recommended — frida-free, no anti-frida risk)**
   - Source: `bridge/Hook.java` (module `adj9-oracle.apk`, package `com.adj9oracle`).
   - Protocol: write TASK blocks (`KIND=`, `SDK=`, `key\x01value` lines) to
     `/data/local/tmp/adj9_sign_in` BEFORE a fresh app launch; collect
     `AUTH <idx> <authorization>` from `/data/local/tmp/adj9_sign_out`.
   - Proven non-organic: `arm/oracle_ab_oracle.json` → token `24xg6t54`,
     VKM Digital Yeni; python control arm `oracle_ab_python.json` → `wy7261z` Organic.
   - Driver to copy-adapt: `arm/oracle_ab.py` (`sign_on_device()` + `to_control()`).
2. **Frida RPC mint (`Signer.sign` overload)**
   - Agent: `bridge/mintcl_src.js` → compiled `bridge/mintcl.js`; RPC `mint({activity, globals})`
     returns `{authorization, nSignBlob, canonical, resKeys}`; also `health/kick/introspect/setInject`.
   - Driver: `bridge/real_sig_flow.py` (fresh frida-server, attach pid, `exports_sync.mint`).
   - Risk: anti-frida guard kills the app seconds after Java-bridge attach — mint fast, detach.

## Offline signer stack (copies in `signer/`)

- `F.py` — region transform (#0/#2/#4). Heads: `HEAD_FIRST=(0x22,0x2E)`,
  `HEAD_RESIGN=(0x2B,0x07,0x22,0x2E)` (genuine); SYNTH tables are fill_runs-only, DO NOT mint with them.
- `adj9_signer.py` — full offline signer: region + desc10 law + `FinEx` VM + header.
- `mint_pipeline.py` — live request builders (imports `header_gen`, `fin_vm2`, `desc10_law`).
- `fin_vm2.py`/`vm_final.py` — the lifted ARM64 VM (`FinEx(seed=signing_second, descriptors)`).
- `header_gen.py` — `make_header(second)` / `Random3` (srand(time)→8 rand→pair-XOR).
- `desc10_law.py` — claims → descriptor #10 packing (27-key session / 32-click / 21-attr law).
- `prove_byteexact.py` — acceptance harness: FinEx on captured descriptor plane → 48/48.
- `repro_oracle.py` — offline replay of the pulled oracle blobs (partially implemented).

## Key findings from others (see `findings/`)

- `SESSION_FINDINGS_SIGNATURE_GATE.md` — server verifies the 176 B body, bound to
  request claims (A2 bit-flip → Organic; A4 claim mismatch → Organic; A5 header-only OK).
  VM seed = signing **second**. Region = device-materialized from urandom `S`.
  Per-ordinal d0 head: sign 1–2 = `2b22252e…` H4-style, sign 3+ = H5 (+`07`).
  V/µs self-consistency required (`µs ≤ created_at.ms`).
  **Python arm with ALL fixes still Organic 4/4 (arm_transport2)** → discrepancy persists.
- `AGENT_exactness.md` — `winning_session.json` header matches law, body 0/44 offline
  (seed never captured). Open divergence: oracle custom map has **50 keys** at signing
  time but `claims_from_wire` packs only **27** (360 B vs possibly 451 B). The closing
  experiment: capture `d2` + `#10` + blob for one chosen-input signing, replay FinEx.
  ⚠ Also: `region(S,0)` failed fresh captures (d0 head) — fixed by per-ordinal head.
- `F_fresh_validation.md` — `rows_full.json` + `nblob_*.hex` byte-exact 48/48 on
  captured plane (region from device, NOT computed).

## ⚠ Known suspect list for the F.py-vs-device discrepancy (to test)

1. **#10 claims packing on custom/oracle maps** (50-key map vs 27-key law) — AGENT_exactness §5.
2. **d0 head phase** (per-ordinal H4/H5 vs F.py HEAD_FIRST/HEAD_RESIGN table mismatch —
   F.py says `(0x22,0x2E)` genuine vs SESSION_FINDINGS says `2b 22 25 2e`; reconcile!).
3. **V/µs self-consistency** in the live mint path (`make_V_consistent`).
4. Seed `S` source: device `/dev/urandom` vs our `V ^ (pid<<16)` construction.

## Next steps (plan)

1. Start frida-server + verify one live `mint()` RPC round-trip (or fall back to
   LSPosed control-file sign) with a **fixed test map**.
2. During that same signing, capture the full descriptor plane (S/d2, #10 bytes,
   second) via `foldhook_native.js` or the module log.
3. Rebuild the identical map offline, mint with `mint_pipeline`/`adj9_signer`
   at the same second + captured seed, byte-diff 192 B word-by-word (48 dwords).
4. Localize the first divergent descriptor → fix in `signer/` copies only.
5. Re-run arm_transport2-style A/B to confirm non-organic.

## Full dependency closure copied into `signer/` (verified imports resolve)

`F.py`, `adj9_signer.py`, `adj9_api.py`, `mint_pipeline.py`, `header_gen.py`,
`fin_vm2.py`, `vm_final.py`, `desc10_law.py`, `decryptors.py`, `elf.py`,
`native_d0.py`, `emu_8d6f4.py`, `adj9_full_chain.py`, `run_funnel.py`,
`verify_funnel.py`, `prove_byteexact.py`, `repro_oracle.py`.

Validation (all run from `mywork/signer/`, 2026-09-27):
- `python F.py` → region vectors print OK.
- `import mint_pipeline` → OK; `make_header(1790263011)` =
  `5faccf587a3179a10475ecbd0e29cc00` == the known winning-session header.
- `mint_pipeline.py selftest` → **PASS** (`=== DRY-RUN: PASS ===`, exit-clean,
  9,878,275 steps, nrand=8, header/`make_header` match, byte-identical remint,
  #10 = 360 B, #7 unpadded = 360; advisory: region law **L3 `X == U[3]` FAIL**).
- `adj9_signer.py selftest` → **exit-clean**, 10,519,758 steps, 192 B blob,
  header `4d1926a6…6a8d` = `make_header(1790451921)`, body 176 B emitted.
- Note: the two selftests minted at the same second → identical 16-B header,
  different bodies (different random `S`) — expected behavior.
- Interesting advisory to investigate later: **L3 `X == U[3]` FAIL** in
  `mint_pipeline` region-law check may be one of the payload discrepancies.
  **RESOLVED 2026-09-27 — L3 is NOT the bug.** The *device's own* d0 fails L3 on
  every genuine signing (L1=True L2=True L3=False, 3/3), matching the earlier
  `SIGNATURE_VERIFICATION_STATUS.md`. Gate on L1/L2 only.

## ROOT CAUSE FOUND 2026-09-27 — the d0 head tables (see findings/D0_HEAD_ROOT_CAUSE.md)

The shipped whitener head tables did not reproduce the device's descriptor #0,
and the Unicorn "real signer" was not a device oracle for d0:

| head table | device signings matched |
|---|---|
| old `F.HEAD_FIRST` / `F.HEAD_RESIGN` | 0/3 |
| old `mint_pipeline.DEVICE_SELECTORS` (12 entries) | 0/3 |
| `native_d0.posthead_region_native` (what `adj9_signer.region` shipped) | **0/3** (24/144 bytes off) |
| **solved `2b 22 25 2e 44`** (sign_id 1-2) | **2/2** |
| **solved `2b 07 22 25 2e 45`** (sign_id 3+) | **1/1** |

The re-sign phase prepends `2b 07`, shifting d0 by two half-words — which is why
every previously published table (4, 5 or 12 entries) missed.

Fixed in `signer/F.py`, `signer/mint_pipeline.py`, `signer/adj9_signer.py`:

```python
DEVICE_HEAD_FIRST  = (0x2B, 0x22, 0x25, 0x2E, 0x44)        # sign_id 1-2
DEVICE_HEAD_RESIGN = (0x2B, 0x07, 0x22, 0x25, 0x2E, 0x45)   # sign_id 3+
```

`adj9_signer.region()` now uses the pure-Python `F._d0_words` with the correct
head instead of the Unicorn post-head lift: **3/3 byte-exact, 0.00 s instead of
~115 s per call.** Old behaviour is still reachable with `ADJ9_USE_UNICORN_D0=1`.

Post-fix validation: `F.head_for_sign_id` 3/3 byte-exact on genuine device d0;
`mint_pipeline selftest` → `DRY-RUN: PASS`; `adj9_signer selftest` → exit-clean,
192 B blob.

### Reproduce
- `python decide_d0.py` — shipped-native vs device, 0/3 (cached; ~2 min/row)
- `python solve_resign_head.py 3` — brute-force solve → `2b 07 22 25 2e 45`
- `python probe_d0_models.py` — every row × every head table
- `python cmp_native_vs_F.py <seed>` — native vs F.region, all heads

### Still open
- `paired_mint.py` never completed: device `ZD2228MY3X` dropped off ADB mid-run
  and has not returned (no USB/wireless endpoint to retry). The live A/B
  (device-oracle vs corrected-Python) still needs one run to confirm non-Organic.

## Path caveat

Copies in `signer/` import each other by bare module name (`from header_gen import …`,
`import vm_final`) — they must be run with cwd/`sys.path` = `mywork/signer/`.
Scripts that reference `../device/*.json` (e.g. `prove_byteexact.py`) expect the
original layout; adjust paths **inside mywork copies only** when running.
