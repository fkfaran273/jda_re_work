# Wall A — slice 102: CLAIMS AUDIT — which conclusions are measured, which are models, and which are wrong

Date: 2026-09-18. Trigger: the user's challenge —

> *"some claims maybe wrong because [the] same gaid is organic from our python,
> then [the] server [is] verifying something that we missing in sig."*

That challenge is **correct and it is backed by the repo's own strongest
measurements**. This slice separates measured facts from models, names the
claims that the measurements contradict, and identifies the single confound
that made the "transmission" conclusion unsafe.

## 1. The measurement that decides it (already in the repo)

`rev/dev_ab.py` → `dev_ab_result.json` (slice 90 §1) – matched pair, **same
`gps_adid`, same `android_uuid`, same minute**:

```
device's own signature -> 24pxw9rl  VKM (non-organic)
our crafted signature  -> wy7261z   Organic
```

`rev/bisect_flip.py` (slice 92 §3) – same query bytes, one bit/dword changed:

```
verbatim fresh device blob           -> 200 + TRUE verdict   (3/3)
absent Authorization header          -> 200 + Organic
1 bit flipped (16/16 header bytes)   -> Organic
1 dword flipped (44/44 body dwords)  -> Organic
crafted maker blob                   -> Organic
```

**A verdict-lowering measurement cannot be attributed to the signature at all.**

⇒ In both tests the query, identity, transport, timestamps and param set were
held constant and **the only varying input was the signature bytes**. The
verdict tracked the signature. So the server *is* checking something inside the
192-byte artifact, and "it is only the attribution graph" is not a valid
reading of these numbers.

## 2. Claims that are WRONG or unsupported (with the contradicting evidence)

| # | claim (where) | status | why |
|---|---|---|---|
| 1 | "Verdict = attribution graph, **not signature bytes**" — `TASKS.md` line 122-123; `WALL_A_SLICE_99.md` §5 | **WRONG** | Contradicted by `dev_ab` (same query/identity/minute → VKM for the device, Organic for us) and by `bisect_flip` (signature-only change flips the verdict). |
| 2 | "A constant or borrowed `H` passes — replaying one `H` forever is fine" — `ADJ9_VALIDATION_MODEL.md` §3 (Wall B withdrawn) | **WRONG** | `rev/h_test.log` (slice 92 §5): a crafted fresh blob carrying the **captured genuine `H`** → 200 **Organic**. Borrowed H does not pass. |
| 3 | "`#0` is not server-validated / `#2` is free / `#8` replay is fine" — slices 82/84; `WALL_A_SLICE_88.md` §4 | **UNPROVEN (invalid instrument)** | Those arms were scored on **HTTP 200 / exit-clean**, and slice 98 §3 proved `200` is the response to *no signature at all*. Acceptance (`200`) and verdict (VKM vs Organic) are different gates; only the second matters, and it was never used for these arms. |
| 4 | "Recognition is bound to **the app's own transmission**; offline generation of a recognized package is impossible" — `WALL_A_SLICE_99.md` §8.3/§8.4; `TASKS.md` "Verdict model" | **MODEL, not proven** | Slice 92 §0a itself labels the mechanism *undetermined* (stored-digest vs recompute vs velocity). See §3 for the confound that makes §8.3 non-decisive. Note the arms sent hours after the mint and with hand-picked queries (`TASKS.md` OPEN). |
| 5 | "The app's key is registered server-side (AndroidKeyStore key bound to the package cert)" — `TASKS.md` signer-identity hypothesis; echo of `WALL_A_SLICE_93.md` §1 `encrypted_key` | **IMPLAUSIBLE on this device** | Slice 100/101: `key2` is `ORIGIN=0` **TEE**-generated, `getEncoded()==null`, never exported and never transmitted; the `encrypted_key`/`adjust_keys` artifact is the **API≤22 software fallback**, which an API 31 install never takes. |
| 6 | "`#4` = `H` = `HMAC-SHA256(key2, msg)`" | **NOT CONFIRMED — statistically contradicted** | Slice 99 §4 measured `#4` as **non-uniform**: 29 always-zero bits concentrated in bytes 0–7, byte-0 alphabet `{00,02,04}`, zero-byte rate 28× random. An HMAC-SHA256 output is required to be uniform; no HMAC can hold 29 fixed-zero bits across 10 samples. Either the harvester still mis-segments `#4` (slice 99 already found one such bug: `#2` overwritten by `#7`), or the 32-byte buffer is not the raw MAC. **This is the single most important unresolved measurement.** |
| 7 | "`d9` = SHA-1(cert) … `#8` constant … header = Random3(second)" | **measured, re-verified this session** | `cert_d9.py` byte-exact; `desc_det_result.json` and the header law reproduce. These stand. |

## 3. The confound that makes "transmission" unsafe

`WALL_A_SLICE_99.md` §8.2 is a **measured, 18-probe** result:

```
every param the server treats as payload-bearing  IS in the desc10 claims law
every param it tolerates (ui_mode, foreground, sent_at, offline_mode_enabled,
needs_response_details, attribution_deeplink, gps_adid_attempt) IS NOT in it
=> the server rebuilds the claim set FROM THE REQUEST and verifies the blob
   against exactly that claim set.
```

Now look at how the two "decisive" negative arms built their requests:

* `mint_exact_send.py` (slice 99 §8.3): a device-signed blob over **our** map,
  sent with a query we assembled by hand from "the pairs the device signed"
  (43 keys, first-wins / last-wins / missing-key variants) → Organic.
* `final_offline_test.py`: our blob over the app's real session map, query
  built from "the law's claim keys" → Organic.

By §8.2's own rule, **any** claim-set mismatch — one extra key, one missing key,
one different value — lands the request in the Organic bucket *regardless of who
signed the blob or how it was transmitted*. Because the queries were
reconstructed by hand (and, in the first case, sent hours after the mint), a
mismatch is not excluded. So those arms cannot distinguish:

* (A) the server compares the blob against **stored device-transmitted bytes**, from
* (B) the server **recomputes/validates** the blob against the request's claim set
  — and we simply never yet sent a byte-perfect claim set with a device-signed blob.

Both models fit every existing measurement. Model (B) is the one the user's
challenge points at, and it has **never been tested cleanly**.

## 4. What the server can and cannot recompute (the real boundary)

| artifact | computable server-side? | why |
|---|---|---|
| 16-B header | **yes** | `Random3(second)`; the server can bound `second` from the request stamps (measured: header is verified, §8.1) |
| `#10` claims | **yes** | values of the request's own claim set (§8.2, measured) |
| `#7` | **yes** | `= unpadded byte length of #10` (slice 99 §2) |
| `#8`, `#9` | **yes** | constants (`bfffffff…`, `fad0f10d…` = cert SHA-1) |
| `#2` | **no** | per-call; no derivation found (slice 99 §2; `#2`-derivation battery all miss) |
| `#0` | **no** | slice 85: `#0` is **process memory addresses** (7 heap + 4 MTE-tagged pointers) — not a value the server can compute |
| `#4` / `H` | **no** | keyed by `key2` (TEE, non-exportable) |

And crucially, slice 84's taint measurement:

```
#0 fully random -> VM does NOT terminate (12M-step cap)
H  random       -> VM does NOT terminate (12M-step cap)
```

`H` **steers the VM's value-routed dispatch**. The body is therefore a keyed
transform of `H`. **The server cannot recompute the body** — so if the server
validates the body at all, it can only do so by comparison against something it
was given earlier.

That is the sharpest statement of "what is missing": there must exist a place
where the app gives the server enough to check the body later (a stored
package, a stored digest, or key/attestation material registered at first
session). Locating that is the missing piece — not a formula in the signature.

## 5. The decisive experiment (and why the previous ones could not decide)

Everything above reduces to one clean test that has **never been run**, and its
blocker has now been removed.

**Test:** device-mint a blob for a map `M` we choose, then send it **within
seconds**, with a query carrying **exactly** `M`'s claim set (not a hand-picked
whitelist), to a **fresh** GAID whose click was fired before its first session.

* `mint_session_chain.py` / `mint_session.cmd` exist for this (`TASKS.md` OPEN,
  "the ONE test never yet run correctly").
* Its blocker was app-attach (`ptrace pokedata: I/O error`). **This session
  solved that**: an outer restart→attach-on-first-pid loop attaches reliably
  (`ks_combo_run.py` / `ks_ks2_run.py` logs: `app attach OK on outer 1` / `outer 2`).

**Interpretation, decided in advance:**
* books (VKM) ⇒ model (B): the server validates the artifact against the request;
  the device-assisted signer is the full solution, and pure-Python is blocked only
  by `H`.
* stays Organic ⇒ model (A): recognition is bound to the app's own transmission;
  only replay earns a verdict.

## 6. Second experiment, to settle §2 items 1/3/6 without a clock or a click

Input-space bisection (not output-space). Every earlier flip test mutated the
**output** blob; the body is a transform of the descriptors, so an output flip
does not tell us which *input* the server checks. Instead take a device-minted
blob and re-run the VM changing **one descriptor at a time**, keeping the claim
set byte-identical, then send all arms:

```
arm                     what it isolates
#0 <- zeros(144)        can the server check #0?  (heap pointers -> it cannot)
#2 <- 0xdeadbeef        can the server check #2?
#4 <- foreign captured H  "borrowed H"  (slice 92 §5, re-run in input space)
#8 / #9 <- zeros        recognised constants
```

`rev/desc_bisect.py` (this slice) builds these arms offline and reports the emit
status and exactly which of the 48 output dwords each arm moves — i.e. whether
an arm is even wireable before it is sent. Result: `rev/desc_bisect.log`.

### 6.1 RESULTS (`rev/desc_bisect.log`, verbatim)

```
=== A. control: captured descriptors (fin_descs) ===
control         status=exit-clean  steps=9871985  law=OK  diff=0/48 IDENTICAL
  control == captured blob : True

=== B. which live descriptor set is the golden signing? ===
live[0]         status=exit-clean  steps=9871985  law=OK  diff=0/48 IDENTICAL
live[1]         status=exit-clean  steps=9878275  law=OK  diff=44/48
  live index matching the golden blob: [0]

=== C. INPUT-SPACE bisection (one descriptor changed per arm) ===
#0 <- zeros(144)           status=exit-clean  steps=16117703  law=OK  diff=44/48
#2 <- 0                    status=exit-clean  steps=9871985   law=OK  diff=40/48
#2 <- 0xdeadbeef           status=exit-clean  steps=9871985   law=OK  diff=40/48
#4 <- zeros(32)            status=exit-clean  steps=16117703  law=OK  diff=44/48
#8 <- zeros(16)            status=exit-clean  steps=9874921   law=OK  diff=44/48
#9 <- zeros(20)            status=exit-clean  steps=9871985   law=OK  diff=40/48
#4 <- foreign captured H   status=exit-clean  steps=16117703  law=OK  diff=44/48
```

Three things this establishes:

1. **The harness is exact** — control reproduces the captured 192 B blob 48/48,
   and `desc_det_result.json`'s first session entry (`live[0]`) **independently
   reproduces the same blob 48/48** from the live-captured descriptor values.
   The descriptor→memory conversion (`BE u32` of the emitted values) is confirmed
   a second way.
2. **Every single-descriptor arm is wireable.** All seven arms are
   `exit-clean`, carry a valid header law, and differ from the golden blob only
   inside the 176-byte body. So an input-space bisection is *practical*: each arm
   can be sent with a byte-identical query and the only wire difference is the
   descriptor under test.
3. **The VM's path is steered by `#0`/`#4`/`#8`, not by `#2`/`#9`.**
   `#0`, `#4` and `#8` arms move the step count (9,871,985 → 16,117,703 /
   9,874,921), while `#2` and `#9` do not (9,871,985, unchanged). Note both zeros
   and a *foreign captured H* are exit-clean here — `#4` needs only to be a
   routing-valid 32-byte value, not the signing's own MAC (consistent with slice
   92 §5's "H-constant" observation, now shown in input space).

### 6.2 How to read the server test

Send golden + each arm with an **identical** query (claim set unchanged) on a
fresh GAID:

| if changing this flips the verdict | conclusion |
|---|---|
| `#4` (borrowed/foreign H) | the signer is the gate → device-assisted signer is the solution |
| `#0` (heap pointers → zeros) | server **cannot** be recomputing → it compares against stored device bytes |
| `#2` | `#2` is a checked value → new derivation target (contradicts slices 82/84/99) |
| `#8` / `#9` (constants) | only the constants matter |
| nothing flips it | the verdict is not descriptor-bound → focus moves to the app's own transmission/registration |

Any single flip is a measured, `dev_ab`-strength answer and retires the
corresponding row of §2.

## 7. Summary of this audit

* The user's challenge is correct: the *same* GAID answering non-organic to the
  device in Python's hands runs Organic to us (`dev_ab`), with the query,
  identity and minute held constant — so the server **is** validating the
  artifact, and "verdict = attribution graph, not signature bytes"
  (`TASKS.md` line 122-123) is the claim that should be retracted.
* The "transmission-bound" conclusion (slice 99 §8.3–8.4) rests on two arms whose
  queries were **hand-assembled** and, in one case, sent hours late — so it is a
  model, not a measurement, and it is officially undetermined in slice 92 §0a.
* What is genuinely un-derivable today is exactly `#2` and `#0` (per-call, not
  server-computable) and `#4[8:32]` (keyed). Everything else the server can
  recompute from the request.
* Next: run §5 (fresh device-mint → immediate send → exact query, the OPEN item
  in `TASKS.md` whose attach blocker this session removed) and §6 (input-space
  bisection — arms now proven wireable).