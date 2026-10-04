# full_replay — the decisive end-to-end experiment: header reproduced 4/4, body blocked by ONE 32-bit device-only seed

Date: 2026-09-23. Driver `rev/full_replay.py` (+ harness `rev/emu_8d6f4.py`,
extended). Runs the FULL signing path under Unicorn — nSign (0xdb1cc) →
0x95fc4 → VM → sub_8d6f4 → wire-builder VM → JNI return — with the **exact
captured inputs of device signing #1** (moto g42, hawao, Android 12, build
S2SE32.28-28-4, `device/java_dump/signings_extract.json`) and diffs the
returned blob against the captured 192-B blob.

## 0. Headline

1. **Header: reproduced byte-for-byte (4/4 words).** With
   `time_sec = 1790106110` (the signing second) the emulated header is
   `4efd72e6 33bbc54a 45c8e70f 10e63a5c` == captured signing #1 (rand draws
   751271802, 1647971740, 1082345470, 1933083316, 1281939145, 161493446,
   366984179, 87654831 — identical to `Random3(1790106110)` draws 1-8).
2. **Body: 0/48 words match, and the emulated merge output is 16 B longer
   (blob 208 B vs 192 B)** — but the campaign located every knob, and the
   residual reduces to exactly TWO items:
   * **the per-call 32-bit whitening seed** — on the device this is the low
     32 bits of an 8-byte `/dev/urandom` read inside nSign (function
     `get8random` 0x13e0e4, called by the 0x143794 chain from nSign's
     preamble). It is NOT transmitted, NOT derivable from any captured input,
     and NOT recoverable from the blob (the whitening avalanches). Varying it
     flips the whole body; varying `srand`'s seed (the second — KNOWN) also
     whitens the whole body through the rand pair-XOR header units that chain
     into the body.
   * **a 16-B structural excess** (emu merge output 48 dwords vs the device's
     fixed 44) that is input-INDEPENDENT (none of the 40+ variants changes
     it) — one unmodeled device-real probe still steers one merge branch.
3. **Everything else is now exact.** The emulator's `map.get`/`containsKey`
   traffic reproduces the device's 63-call sequence (the only delta: the
   device log's 2 extra `environment` gets are Java-side SDK traffic, not
   native). The unknowable inputs turn out NOT to matter: property strings
   (except two consistency checks), tid, tls/ASLR, stack guard, the
   CLOCK_MONOTONIC reading, width/height, and the package/APK-path bytes
   never reach the wire.

## 1. Captured inputs fed to the emulator (all byte-exact)

| knob | value | source |
|---|---|---|
| canonical/claims | the 27-key subset read natively; values from `map_order`/canon | capture `adj9_capture_run1.log` mapget traffic (this=50234709) |
| map.get surface | 29 keys (27 non-null + `android_id`/`fire_adid` null); `containsKey` true iff non-null | ditto (63 records: 11 direct probes + two 27-key walk passes) |
| H (arg2, 32 B) | `9f15bf1f51ac35505db91778d7f204a9f3771903de3f052a0b5565a01ccaa8c8` | `signings_extract.json` |
| second / srand | 1790106110 (= `ts//1000` = header-inverted) | ditto |
| CLOCK_REALTIME | 1790106110 s, .175 s (nSign entry; `nano_in` bracket proves only the second matters) | `nsign_in` record |
| CLOCK_MONOTONIC | 3565.565088270 s at entry (`nano_in=3565565088270`); `nano_out=3566423291012` ⇒ 858 ms window | `nsign_in`/`nsign` records |
| sdk_int | 31 (`arg3_int`) | ditto |
| width/height | 1080×2237 (`env_ints`) | ditto |
| APK cert | 745 B `rev/cert_signer1.der` | extracted from the APK |
| cert SHA-1 (#9) | `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd` | SHA-1 of the above |
| properties | stock hawao S2SE32.28-28-4 values (fingerprint `motorola/hawao_g/hawao:12/S2SE32.28-28-4/4140d-bd21d:user/release-keys` etc.; serialno/user/host guessed) | stockrom firmware listing — and proven irrelevant below |

Harness extensions this session (all in `emu_8d6f4.py`, backward-compatible):
`clock_gettime` clk_id split (CLOCK_MONOTONIC `mono_sec/mono_nsec` vs
realtime `sec/nsec`); `map.containsKey` semantics (true iff non-null — this
was returning false for ALL keys, killing the claims rebuild); null-String
JNI paths; `Mac.doFinal` returns the true H (the native recomputes
HMAC(key2, canonical) on a process's first call; for a genuine signing that
equals arg3); `get8random` urandom path (`urandom8` knob: access/openat/read
of `/dev/urandom` succeed and return 8 configured bytes) with the device
fallback `tv_sec ^ (pid<<16) ^ tv_usec` now explicit; `getStackTrace` frame
model; keystore attestation-chain model; sensor-count and fd-count models;
`/proc/net/tcp` fake-file model; PM-state and merge-sink instrumentation.

## 2. The word-by-word diff map (final harness, exact captured inputs)

```
stopped=returned  wall≈85-120 s  calls≈1463-1680  emu blob = 208 B (cap 192 B)

word map (4-B words of the returned blob vs the captured 192-B blob):
  [00] HDR OK    cap=4efd72e6 emu=4efd72e6
  [01] HDR OK    cap=33bbc54a emu=33bbc54a
  [02] HDR OK    cap=45c8e70f emu=45c8e70f
  [03] HDR OK    cap=10e63a5c emu=10e63a5c
  [04..51] body  DIFF — 0/48 body words match; the emu additionally emits
         4 words (16 B) more than the device's 44-dword merge output
first differing byte offset: 16
srand log: [1790106110]      (header law seed — correct)
```

Header 4/4; body 0/48 (expected under the whitening model — see §3/§4: a
single wrong whitening-seed bit avalanches across the whole body, and the
device's seed is unknowable).

## 3. Knob → word sensitivity (final campaign; `sensF_s*.log`/`sens_final_s*.json`)

*(table filled from the campaign — see §3.1 for the pre-fix campaign which
already established the map)*

Groups:

**A. Whole-body whiteners (every body word flips):**
| knob | flips |
|---|---|
| `urandom8` = any value (the device's per-call seed) | ALL body words |
| `usec +1` / `pid +1` / `rt_sec +1` (the get8random FALLBACK seed = `tv_sec ^ (pid<<16) ^ tv_usec` — used only when /dev/urandom is unreachable) | ALL body words |
| `time_sec +1` (srand only) | header (4) + ALL body words — the rand pair-XOR header units chain into the body whitening |

**B. Avalanche-on-region movers (40-44 of 48 body words):**
| knob | flips |
|---|---|
| `sdk_int` 31→32 | words 8..51 (words 4..7 stable) |
| `map.app_version=X` | words 8..51 |
| `map.android_id` null→value (changes the claims rebuild itself) | words 8..51 |
| `versionName=X` | words 8..51 |
| `cert_sha1 vary` (#9) | words 12..51 (words 8..11 stable) |
| `map.environment=X` / `map.created_at=X` / `map.partner_params=X` | words 16..51 (words 8..15 stable) |

**C. Two property probes are consistency VERIFICATION, not content:**
`ro.build.version.release` vs map `os_version`, `ro.build.version.sdk` vs
map `api_level` — a mismatch ("12X" vs "12") flips words 8..51. On the
device they match (both known: 12 / 31).

**D. Negative controls — ZERO flips (do NOT feed the wire):**
`width ±1`, `height ±1`, `tls_base`, `stack_guard`, `tid`, `pid` (as a
thread/process identity — its flips above are purely through the fallback
seed formula), `mono_nsec ±1ns/±1ms/±100ms`, `mono_sec +1`, `rt_nsec`,
`package_name`, `publicSourceDir` (elided-middle APK path!), ALL other
property strings (manufacturer, model, device, name, brand, fingerprint,
display.id, tags, type, user, host, hardware, bootloader, bootmode,
serialno, cpu.abilist, soc.model, characteristics), `sec_level` 0/1,
attestation-chain presence (0 vs 4 certs), stack-frame list (0/4/6 frames),
fd-count model, `/proc/net/tcp` content.

## 4. THE ANSWER — where the remaining mismatch lives

The body is `Whiten(merge(descriptors), chain(header_units))`:

* `descriptors` — all 11 field-capture descriptors are reproducible from
  captured inputs (claims, H via recompute, cert SHA-1, versionName, …)
  **except descriptor #0's tiled 16-byte block**, which the live-capture
  (fin_result.md: #0 = dword0 + one 16-B block tiled ×8, 36 dwords) showed is
  the Park–Miller/shuffle16 state seeded by `get8random`'s 32 bits.
* `chain(header_units)` — the 4 rand pair-XOR units (a pure function of the
  second — reproduced 4/4) open the whitening chain, so the srand seed
  whitens the body too; the second is KNOWN (it is transmitted implicitly —
  the header is invertible).
* **the 32-bit `get8random` seed is the single unknowable input.** Static
  proof (get8random disassembly): `access("/dev/urandom")` → `syscall(openat)`
  → `read(fd, buf, 8)` → `close`; on ANY failure the fallback is
  `gettimeofday + getpid → seed = tv_sec ^ (pid<<16) ^ tv_usec`. On a real
  device /dev/urandom is world-readable ⇒ the device seed = per-call kernel
  entropy. The emulator (urandom read failing) used the fallback — which is
  why the emu body was deterministic at all.
* The seed is NOT recoverable from the captured blob: the whitened wire
  contains neither the seed nor the 16-B state verbatim (searched), and the
  whitening is forward-only (verify-by-resimulation, fin_result.md §decoder).
  Recovering it means solving `Whiten(merge(descs[seed]), second) == blob`
  for `seed` — a 2^31 brute force over full wire-builder evaluations
  (~10^7 steps each): infeasible in Unicorn (~2 min/run) and out of reach in
  the pure-Python FinEx.

### What this means for the server-verification model

The 32-bit per-call seed is exactly as invisible to the SERVER as it is to
us: the server cannot recompute the body either. This closes the model the
earlier slices had already measured from the outside:

* slice 82 (`taint44.py`): **0 of 44 body dwords are server-verifiable** —
  the server does not (and cannot) recompute them;
* slice 81: a crafted signature with a REPLAYED body was accepted (HTTP 200)
  — the server unseals and compares-to-history / checks the header and
  freshness binding, it does not re-mint;
* the body's per-call randomization (A1~A2: 191/192 bytes differ at the same
  second) is a **nonce property**, not an authentication property: the
  urandom seed makes each body unique so replays are detectable, but it also
  makes the body non-verifiable — anyone who can observe one accepted body
  can replay or re-wrap it (slice 81 proved this end-to-end).

## 5. Verdict summary

| item | status |
|---|---|
| header (16 B) | **byte-exact from the second** (`Random3(second)`) — offline minting SOLVED |
| merge output length | emu 48 dwords vs device 44 — input-independent residual, one unmodeled device-real probe steers the branch (fd/stack/NTP/attestation candidates tested; none) |
| body bytes | all inputs byte-exact except ONE 32-bit per-call `/dev/urandom` seed ⇒ byte-exact reproduction of a captured body requires that seed; it is unknowable and unrecoverable |
| offline minting | header: solved; body: mint by replay (accepted, slice 81) or by brute-forcing the seed (infeasible); the server cannot verify the body either — the signature's real gate is the header + freshness + history, not the body |

## 6. Artifacts

`rev/full_replay.py` (driver: `-n N` signing, `-v` override, `--sens`
campaign, `--shard/--nshards`), `rev/full_replay_base.log`,
`rev/full_replay_rows.json`, `rev/full_replay_blob.bin`,
`rev/full_replay_calls.json` (full call trace), `rev/sensF_s*.log` +
`rev/sens_final_s*.json` (final campaign), `rev/emit_trace.json` (745,760
wire pushes), harness `rev/emu_8d6f4.py` (this session's extensions inlined).

## 3.1 Pre-fix campaign note

The first campaign (shards `sens_s*.log`) ran before the `containsKey`,
`doFinal` and clock-split fixes; its relative knob→word map (§3) already
held and was re-confirmed by the final campaign. Its `urandom8` rows were
inert (the access gate was added later) and its `hmac[0]^1` row showed 0
flips — proving the wire embeds the RECOMPUTED H, not arg3 (C5's parsimonious
model confirmed dynamically); with the `doFinal` fix the recomputed H equals
arg3 and the hmac row becomes live.
