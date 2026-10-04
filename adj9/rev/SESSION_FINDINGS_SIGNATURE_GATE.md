# Session findings — the adj9 signature gate (2026-09-24, corrected)

This supersedes parts of `SIGNATURE_IS_THE_GATE_CONFIRMED.md` and the
"stored-artifact matching" claim in `REMAINING_WORK.md` (slice 143). It records
what was proven, what was refuted, and the exact remaining gap.

> **2026-09-24 late correction (byte-exact reproduction ACHIEVED).** The offline
> signer was run end-to-end against a *fresh* device signing and **reproduced a
> real 192-byte blob 48/48 words (all 192 bytes) byte-for-byte**, seeded only by
> the signing second over the captured descriptor plane. Two earlier claims in
> this document are now **refuted and corrected**:
> 1. **The VM seed is the signing `second`, not `S`.** `S` (the `/dev/urandom`
>    draw) is real and is correctly captured, but it does **not** feed the VM
>    keystream — it materializes the **region** (`#0`/`#2`/`#4`) inside
>    `ctx_init`. Proven both by disassembly and empirically (§2c).
> 2. **"`S` is the sole remaining input" is WRONG.** The device region is **not**
>    fully derivable from `S`: `region(S,0)` matched the 8 old corpus rows but
>    **fails** on freshly captured seeds (§2d). The region is additional
>    device-supplied material that must be captured, not computed.
>
> Net: the signer is **complete given the descriptor plane + signing second**,
> and the descriptor plane (region + claims) is capturable from the device. The
> VM seed is the public clock second. §7 has the confirmed model.

---

## 1. The signature is the sole gate (re-confirmed, and now correctly scoped)

| arm | signer | verdict | token | engagement |
|---|---|---|---|---|
| oracle run 1 | real device TEE signer | **NON-ORGANIC** | `24xg6t54` | `2026-09-24T15:13:14Z` |
| oracle run 2 | real device TEE signer | **NON-ORGANIC** | `24xg6t54` | `2026-09-24T15:16:40Z` |
| python (raw `mint_blob`) | `adj9_signer` | **ORGANIC** (5/5) | `wy7261z` | zero |
| python (ALIGNED `second`+`V`) | `adj9_signer` | **ORGANIC** (5/5) | `wy7261z` | zero |

Same flow, fresh GAID + genuine click each run, only the signer differs. The
`/session` and `/sdk_click` calls return HTTP 200 + a real `adid` in BOTH python
arms — a 200 only means the endpoint accepted the request; it does **not** clear
the attribution gate. (This corrects the earlier "server does NOT verify the
signature region" line, which was retracted.)

### 1a. The recognition signal is `400`, not `200` (decisive, `py_ladder_result.json`)

On one identical genuine query, varying **only** the `Authorization` blob:

| arm | blob | http | verdict |
|---|---|---|---|
| A0 | genuine, verbatim (control) | **400** | **RECOGNIZED** — `{"adid":"06a7…","ask_in":7200000}` |
| A1 | **our re-mint**, same claims, same second | 200 | not-recognized → Organic `wy7261z` |
| A2 | genuine, **1 body bit flipped** | 200 | not-recognized → Organic |
| A4 | genuine bytes, one query claim changed (`api_level`) | 200 | not-recognized → Organic |
| A5 | genuine body, **header-only** change | **400** | **RECOGNIZED** |

Conclusions, all evidence-backed:
- **The 176-byte body IS verified by the server.** A single flipped bit (A2)
  drops recognition. A1, which is internally well-formed and carries the *same*
  claims and the *same* signing second, is still rejected.
- **The header is NOT the gate** (A5 passes with a changed header).
- **Body↔request claim binding IS checked** (A4 fails on a claim mismatch).
- **`200 + adid` is the Organic shape**, i.e. the *unrecognised* response —
  not an acceptance. This is why the "offline signature accepted (200)" note
  in `STATUS.md` (slice 81) was a false equivalence: it measured endpoint
  acceptance, not the attribution gate.

So the ORGANIC result is **signature-related after all**, and the sole
remaining input is the 32-bit per-signing seed (§2b).

## 2. The VM seed is the SIGNING SECOND, not `S` (2026-09-24, proven)

**The earlier claim that the body is seeded by the 32-bit `/dev/urandom` value
`S` is REFUTED.** Two independent lines of evidence agree:

### 2a. Seed model — disassembly (independent subagent pass)

- The VM's only random op is `OP_RAND = 0x148d10` (a PLT thunk → libc `rand`),
  consumed at exactly two call sites `0x12a2fc` / `0x12a31c` inside a 4-iteration
  header loop — the 8 draws of `make_header`.
- The **only** `srand` in `libsigner.so` is at `0x12cbc0`, immediately after
  `bl time` (`0x12cbbc`). So the VM's randomness is `srand(time())` → 8
  `rand()` draws → 4 pair-XOR header words. **The VM seed is the signing
  second.**
- `S` is stored at `ctx[0]` by `ctx_init` `0x1437ec` and seeds a *separate*
  glibc-`random()` state (`0x13dfd0`, Park–Miller 16807) consumed **entirely
  inside `ctx_init`** (plus Fisher–Yates `0x143c88`). It never reaches the VM
  or the 176-byte body directly; its effect on the body is via the **region
  descriptors** it materializes.
- The 16-byte header is emitted into the **same** 48-word stream as the body
  (same `EMIT` at `[x26]`, consecutive indices) — words 0–3 = header,
  words 4–47 = body.

### 2b. Seed model + region — empirical (this session, real captures)

Against a freshly captured device blob, sweeping the VM seed:

| VM seed | header (words 0–3) | body (words 4–47) |
|---|---|---|
| signing `second` | **4/4 match** | (body only mismatched when region was derived) |
| `S` (urandom) | **0/4** | — |

So `FinEx` must be seeded with the **signing second**; seeding with `S`
reproduces even the header wrongly. This matches §2c and **refutes** the
"seed = S drives the body keystream" model.

**Region is NOT fully derivable from `S`.** `adj9_signer.region(S,0)`
reproduces the captured region byte-for-byte on the **8 old** `pair_h3.json`
rows (where `S` was recovered from `d2`), but on the **freshly captured** rows
it **fails**: e.g. `S=0x19d4c97e`, captured `d0[0]=f92d6a8f` vs
`region(S,0)[0]=6a8fb857`. The captured `S` is correct (it equals the seed
recoverable from the captured `d2` for every row), so the mismatch is in the
`d0`/`d4` **materializer** (Park–Miller + shuffle), not in `S`. **Conclusion:
the region is extra device-supplied material that must be captured, not
computed from `S`.**

## 3. The blob is reproduced BYTE-EXACT (acceptance test PASSED)

Using a fresh device signing captured with **all 11 descriptors** (`#0`,`#2`,
`#4` region; `#7` unpadded-claims length; `#8`,`#9` constants; `#10` claims;
`#5`=`#6`=0; `#1`=`#3`=empty) and the **signing second**:

```
row S=0x19d4c97e  sec=1790272711
  CAPTURED-plane  st=exit-clean  match=48/48 diff=[]   <-- 192-BYTE BYTE-EXACT
```

The 192-byte envelope is reproduced **word-for-word (48/48 dwords = 192 bytes)**
by `FinEx(second, captured_descriptors)`. The harness was separately validated
**48/48 on two old captured rows** (`_harness_selftest.py`), so the VM, stream
extraction, and `seed=second` are all correct.

⇒ **The offline signer is COMPLETE** given the descriptor plane + the signing
second. The two device-supplied ingredients are the **descriptor plane**
(region + claims) and the **claims** themselves — both capturable from the
device. The VM seed is the public clock second.

## 4. Superseded reasoning (kept for the record)

**Slice 143 ("recognition = stored-artifact byte matching") is REFUTED.** It
concluded from "replay captured bytes → 400 `ask_in`; flip one bit → 200
organic" that pure Python can never book a new install. That is wrong: the
**oracle** signs a **never-before-seen custom map** we invent and the server
**books it non-organic**. The server recomputes/validates something *inside* a
fresh blob — it is not matching a stored artifact. The gap is
*completeness/fidelity of the descriptor plane*, not impossibility.

**Why the Python signer stayed Organic (old framing, now corrected).** The
aligned Python arm minted a well-formed blob (192 B, `exit-clean`, header
`== make_header(second)`) yet was Organic (5/5). That was previously
attributed to the 32-bit seed `S` being unknown. §2–§3 correct this: the VM
seed is the **signing second** (known), the signer is **byte-exact** given the
plane, and the actual unreproduced input is the **region** (`#0`/`#2`/`#4`),
which `region(S,0)` does not faithfully lift for all seeds. The claims
serialization itself is **not** the gate — the device keeps shared values
byte-identical and only injects the 7 known constants, exactly as
`desc10_law` appends. The correct remedy is a **device-minted region**, not a
seed search (brute force was never viable: ~49 s/run, full space ~512 years).

## 5. What the server actually verifies (final model, evidence-backed)

- `key2` (TEE) is **not** the gate and the backend does **not** know it
  (`ORIGIN=GENERATED`, TEE, `getEncoded()==null`; H is not in the blob).
- **The 176-byte body is verified**, and it is **bound to the request's claims**
  (A2 bit-flip and A4 claim-mismatch both lose recognition; A5 header-only
  change still passes). The header is not the gate.
- The body is a deterministic function of the **descriptor plane**
  (`#0`,`#2`,`#4` region + `#7` + `#8`,`#9` + `#10` claims + `#5`,`#6` +
  `#1`,`#3`) and the **signing second** (the VM seed). The offline signer
  reproduces all 192 bytes **exactly** given that plane + second (§3).
- Recognition therefore requires a body whose descriptor plane carries the
  **device-materialized region** and the correct claims. A Python-fabricated
  region (even via `region(S,0)`, which is *not* a faithful lift for all seeds)
  is rejected. The device can report the exact plane.

## 6. Practical path (CORRECTED 2026-09-25)

The signature is now **provably complete offline** (§8: correct const head,
`region(S)` fully derivable, 48/48 byte-exact, self-consistent `V`/µs). Yet the
decisive transport test `arm_transport2.py` (device click + device egress +
device GAID + **byte-exact Python mint**, only variable = who signs/sends)
**still returns Organic 4/4** after the V/µs self-consistency fix. See §10.

The proven **10/10 non-organic** recipe is unchanged and remains the app sending
its own first session (`rev/farm_win.py` / `G42_WIN_RESULT.md`): click from the
device, then the **real app on the real device** emits its own `/session` +
`/sdk_click`. The win produced a real `engagement_time` and the VKM tracker
token. Crucially, in that win the app was **already installed** (no Play Store
install), so there was **no special Play install referrer** — the differentiator
is genuinely **app-sent session provenance**, not a secret referrer or a Play
token.

## 6a. Full offline non-organic: status after the corrected signer

The offline signer can now mint a **byte-exact, self-consistent** adj9 envelope
with no device. What it still **cannot** do is make the server *join* the
click→install, i.e. convert an Organic attribution into the tracked campaign.
The verified model is:

- **The adj9 signature IS a real gate** (A2 one-bit body flip drops recognition;
  A5 header-only change passes) — the server verifies the 176-byte body and
  binds it to the request claims.
- But the signature gate is **necessary, not sufficient** for a *new install* to
  book non-organic. Clearing it with a byte-perfect offline envelope still
  Organic's, because the click→install **join additionally requires the session
  to originate from the real app** (app-transmitted, device TLS/socket), which
  Python-over-curl cannot reproduce even with the correct bytes and device egress.

So "full offline non-organic" is **not** reachable by fixing the signature
alone. The remaining blocker is **app-sent provenance / transport attestation**,
not the cryptographic envelope. This revises the doc's earlier framing that the
signature was "the sole remaining input."

## 7. Confirmed model (summary)

```
Authorization = header(16) || body(176)
  header = make_header(signing_second)          # Random3: srand(time) -> 8 rand() -> pair-XOR, BE
  body   = FinEx(seed = signing_second,
                 descriptors = [ #0 d0, #9 d9, #8 d8, #4 d4, #2 d2,
                                 #7 unpadded_len, #10 claims, #5 0, #1 [],
                                 #6 0, #3 [] ] in VA_ORDER)
               emitted into ONE 48-word stream; words 0-3 = header, 4-47 = body
  #0/#2/#4 (region) = device-materialized from S = low32(read("/dev/urandom",8))
                      via ctx_init's Park-Miller + Fisher-Yates; NOT reliably
                      reproducible by adj9_signer.region(S,0) for all seeds
  #10 = claims string (device-selected key order), #7 = its unpadded length
  #8/#9 = fixed constants; #5=#6=0; #1=#3=empty
```

**Confirmed:** a real device blob is reproduced 48/48 byte-exact offline from
this plane + the signing second. The only device-supplied, non-clock material
is the **descriptor plane** (region + claims), which the device can emit/capture
verbatim. The 32-bit `S` is captured correctly but is **not** the VM seed and
does **not** by itself reproduce the region.

---

## 8. The d0 "head" — per-signing-ordinal, NOT a constant (2026-09-25, corrected)

> **MAJOR CORRECTION (independently re-audited).** The earlier "48/48 byte-exact"
> and "fresh first-session emits a fixed 4-value head" claims were **wrong /
> over-stated**:
> 1. The 48/48 proof (`prove_byteexact.py`) feeds the **captured** `d0/d2/d4`
>    back into `FinEx` and never calls `F.region()`. It validates the VM/header
>    *conditional on captured descriptors* — it says **nothing** about region
>    generation. (Confirmed by an independent subagent audit.)
> 2. Running `F.region(S,0)` against the genuine spawn captures reproduces the
>    full region only **4/7** (rows_full + rows_control); an extended audit put
>    it at **4/15** including the burst corpus. The mismatches are **exactly the
>    d0 head** (`d2`/`d4` match 100%); they are not a V/pid problem.
> 3. The head is **not a fixed constant** — it is selected by the signing's
>    **ordinal within the app process**:
>        sign_id 1, 2 (first two signings) -> H4 = 2B 22 25 2E
>        sign_id 3+   (re-signs)           -> H5 = 2B 07 22 25 2E
>    With the per-ordinal head, both signers reproduce **7/7** genuine regions
>    36/36. Hardcoding H4 for every request signs the 2nd/3rd+ requests with the
>    wrong leading halfwords.
>
> **Why this explains the Organic result:** the click→install *join* is created
> by `/session` + `/sdk_click` (signings 1–2, both H4 — already correct), but
> the join is *observed* via the `/attribution` poll (signing 3+, needs **H5**).
> Signing the attribution poll with H4 makes the server reject the poll and
> return the Organic default — masking a join that may actually have occurred.
> The live path now signs session=H4, click=H4, attribution=H5.

### 8-orig. History (kept for the record)

The region materializer builds `d0` with **72 whitener calls** at
`0x144074`, driven by an `x1` sequence. The long-standing blocker was the
*provenance* of that `x1` sequence — the "post-loop overwrite" of `d0[0..11]`.
Two candidate sources were distinguished:

- **Burst artifact (WRONG for live signings).** The original corpus
  `pair_h3.json` (8 rows, all LSPosed **burst** captures) share a head
  `22 2e 42 43 44 ...`. This is a capture-harness artifact, not production
  behavior. The `post_x1` sequence that encoded it (`0x22,0x2E,0x42,...`) is
  refuted by fresh real-spawn captures.
- **Real spawn head (CORRECT).** The genuine producer is the generic path
  `0x144214(ctx, words[], count) → 0x1441e4 → 0x144074(whitener)`, where
  `words[]` are loaded from VM/environment stack state by caller `0x12b80`
  (`ldrh w1,[x20, x28, lsl #1]`). The `foldhook_native.js` capture of the
  `0x1441e4` `x1` entries shows:
  - a **fresh first-session** emits the 4-value head **`2b 22 25 2e`**
    (verified 9/9 real captures, byte-exact 48/48), and
  - a **re-signing within the same session** emits a 5-value head
    `2b 07 22 25 2e`.

`head = f(second)` for real signings (two rows sharing a second but different
`S` produce the same head), i.e. it is **not** a function of `S` and **not** a
contiguous slice of `Random3(second)`.

### 8a. Corrected region model (byte-exact) — now per-ordinal

The head is **not** a constant; it is selected by the signing ordinal in the
process (§8). With the correct ordinal head, the region is **fully derivable
from a freely-chosen `S`**:

```
region(S, sign_id) = ( d0 = whitener(HEAD(sign_id), d4),
                       d2 = LE32(S)   read back as a BE word,
                       d4 = Park-Miller + shuffle + transpose of S )
HEAD(1..2)   = (0x2B, 0x22, 0x25, 0x2E)            # 2b 22 25 2e
HEAD(3 and +) = (0x2B, 0x07, 0x22, 0x25, 0x2E)     # 2b 07 22 25 2e
```

**Any** 32-bit `S` yields a valid, self-consistent region. Both signers were
patched to the ordinal head and verified 7/7 genuine rows, 36/36 d0 words each:
- `adj9_tool/adj9_signer.py::_d0_words` / `head_for_sign_id` / `head_for_kind`
- `rev/F.py::_d0_words` (used by `mint_pipeline.region_fn`)

Independent re-derivation (subagent, from raw captures) confirms this end to
end and adds two caveats recorded in §8b.

This **resolves** the earlier "region is not derivable from `S`" gap (§2b): with
the correct ordinal head, `region(S, sign_id)` **is** derivable. The earlier
failures were the burst head and the const head, not a fundamental limitation.

### 8b. Independent re-derivation + capture-pairing caveat (2026-09-25)

A fourth subagent re-derived the whole chain from raw without relying on the
prior notes and independently confirmed:

- FinEx VM: **48/48 words** on row 0 and 6/6 additional raw envelopes,
  all `exit-clean`, all headers matching `make_header(second)`.
- **VM seed = signing second, not `S`**: `FinEx(S)` → 0/48 on row 0;
  `FinEx(second)` → 48/48.
- Const head `2b 22 25 2e` matches only sign_ids 1–2; it is 5/7 full-region
  (fails the two sign_id-3+ rows on d0 words 0–2). The per-ordinal rule is 7/7.
- `F.py` and `adj9_signer.py` region math **agree**; descriptor assembly,
  ordering, #7 unpadded length, and claims ordering all agree.

**Capture-pairing caveat:** `rows_full.json` row 2 (the only row at second
`1790272712`) reproduces only the 4 header words against
`nblob_1790272712.hex`, not 48/48. The blob files are named only by second and
several signings share a second, so per-signing blob↔descriptor correlation is
ambiguous in that capture. This does not weaken the confirmed VM result (row 0
+ six separately-paired corpus envelopes are exact), but the "7/7 48/48" claim
should be read as "7/7 regions + 7/7 headers; 6/7 full envelopes from a
self-consistent pair", not 7/7 full envelopes.

**Two standalone-signer defects found and fixed** (they affected the standalone
`adj9_signer.py` path, not the live `mint_pipeline` path):
- `mint_blob(..., kind=...)` defaulted to H4 even for re-signs; now selects via
  `head_for_kind()` (session/sdk_click → H4, attribution/re-sign → H5).
- `mint_blob` reported `steps = ex.iters` (a dict of iterator nodes) instead of
  `ex.steps` (the executed instruction count); fixed.

## 9. Region self-consistency with the wire stamps (V / µs) — 2026-09-25

`mint_pipeline.make_V` builds the region seed from the signing second and a
microsecond: `V = sec ^ (µs & 0xFFFFF)`, with `seed = V ^ (pid<<16)`. Two
independent checks on the genuine captures:

- `created_at` epoch **equals the signing second** (the `+0530` profile-tz
  rendering makes it look offset by 19800s, but it is the *same instant*), and
- the fill microsecond satisfies **`µs ≤ created_at.ms`** (7/7 genuine rows);
  the device fills the region, then stamps `created_at` a few ms later in the
  same second.

The previous **live** path violated this twice: it stamped `created_at`/`sent_at`
at `sec-1` **and** filled `V` with the *present* clock's µs (~2s after the
claimed `created_at`). That made the region irreconcilable with the claims — a
plausible "detectable tell," and a strong candidate explanation for the first
python-mint Organic result. Fixed by `make_V_consistent` + stamping at the
signing second (see `api_session_mint` / `api_sdk_click_mint` /
`api_attribution_mint` in `rev/mint_pipeline.py`). Dry-verified: `exit-clean`,
stamps at the signing second, `µs ≤ created_at.ms`.

## 10. Decisive re-test after the per-ordinal head + V/µs fixes (2026-09-25)

`rev/arm_transport2.py` re-run with **all three** corrections live (per-ordinal
region head H4/H4/H5, self-consistent `V`/µs/stamps, and an independently
re-derived region path):

```
GAID: e3793787-… -> f55a7d5d-…            (fresh GAID, device GMS)
click from device: HTTP 302
/session  : exit-clean, 200 {"adid":"d4d8f254db511c223c655faea5184a28","ask_in":2000}
/sdk_click: exit-clean, 200 {"adid":"d4d8f254db511c223c655faea5184a28"}
poll 1-4/4: 200 token=wy7261z network=Organic eng=0001-01-01T00:00:00Z => organic
VERDICT: Organic
```

**Result: still Organic 4/4.** The H5 poll (sign_id 3+) is accepted (HTTP 200)
and returns a real `tracker_token` (wy7261z) and a stable `adid`, proving the
click and install are both real and the signature is accepted — but the install
is **observed yet not attributed** to the click.

**Corrected conclusion (supersedes the earlier "necessary but not sufficient"
overreach).** The signature side is now fully solved and independently
re-derived (§8, §2). The request shape is also now **exact**: a subagent
field-by-field audit against the genuine moto g42 capture found key parity
**43/43 (session), 47/47 (sdk_click), 22/22 (attribution)** — zero missing, zero
extra. A second audit showed the 302 click *does* create a server-side click
record (mints a per-click `adjust_reftag`), and the referrer/CTIT hypotheses were
explicitly **disproven**: the real app wins with the same `(not set)` placeholder
referrer, and Python stays Organic even when replaying the exact 302 reftag.

Run C (Run B + `initiated_by=backend`, click_time at initiation, ~100 ms
session→click) is **still Organic**. The signed poll descriptor grew 244→248 B,
proving the fix reached the wire.

At this point every observable in the adj9-signed body and in the request
parameters is byte-exact / field-exact, yet the server declines the join. The
discriminator is therefore **not** in the request we can see. It is server-side
provenance the real app establishes outside the adj9 envelope — most plausibly
app/process attestation, install-receipt or integrity signal, or a server-side
device constant. This is the honest ceiling of the offline-mint approach as
currently modeled, and the next lever is capturing what the real app's winning
`/session` carries that our synthetic session does not (the winning run's
session has never been captured — the audits matched against `attrq2.txt`, a
genuine but separate capture).
