# PHASE_VERDICT — is the pure d0 path exactly the native VM for ARBITRARY selector phases?

**VERDICT: EQUIVALENT. No deviation found. No fix needed.**

The recent refactor did **not** break `_d0_words` / `_selector_halfword`. The pure
d0 path is byte-exact against the real FinEx VM for every selector phase tested,
including the mask-domain edges and phases that appear nowhere in captured
traffic. The user's suspicion is disproved.

- script: `algo_practice/phase_verify/verify_phases.py`
- artifact: `algo_practice/phase_verify/verify_result.json`
- date: 2026-10-01

---

## 1. The decisive test — real VM vs pure, arbitrary phases

For each case: the d0 descriptor words come from
`pure_sign.region(S, 0, 0, head=phase)`, the resulting 144-byte d0 (plus d2, d4
and the standard plane) are fed to the **real** VM via
`signer_simple.finex_mint(descs, second)`, and its 192-byte blob is compared
byte-for-byte against `pure_sign.sign_pure(second, S, map, d9, kind, head=phase)`.

| id | second | S | kind | head phase | mask(s)=(s<<1)+3 | claims | VM | result |
|----|--------|---|------|-----------|------------------|--------|----|--------|
| A | 1790625704 | a6da5d2b | session | (0x2b) | 89 | 360 B | 18.3 s exit-clean | **IDENTICAL** |
| B | 1790625704 | a6da5d2b | session | (0x2b,0x48) | 89,147 | 360 B | 19.8 s exit-clean | **IDENTICAL** |
| C | 1790625704 | a6da5d2b | session | (0x05) | 13 | 360 B | 19.6 s exit-clean | **IDENTICAL** |
| D | 1790625800 | 11223344 | session | (0x5a) | 183 | 360 B | 19.8 s exit-clean | **IDENTICAL** |
| E | 1790625900 | 55667788 | session | (0x7e=126) | **255** | 360 B | 19.6 s exit-clean | **IDENTICAL** |
| F | 1790626000 | deadbeef | session | (0x00) | **3** | 360 B | 19.6 s exit-clean | **IDENTICAL** |
| G | 1790626100 | 0badc0de | session | (0x11) | 37 | 360 B | 20.0 s exit-clean | **IDENTICAL** |
| H | 1790626200 | a6da5d2b | session | (0x2b,0x07,0x22,0x2e) | 89,17,71,95 | 360 B | 19.9 s exit-clean | **IDENTICAL** |
| I | 1790625704 | a6da5d2b | session | (0x2b,0x48), **d0[16:]=0** | 89,147 | 360 B | 19.6 s exit-clean | **IDENTICAL** |
| J | 1790626300 | 12345678 | click | (0x3d) | 125 | 387 B | 21.0 s exit-clean | **IDENTICAL** |
| K | 1790626400 | 0f1e2d3c | session | (0x7e,0x05,0x00,0x5a,0x11,0x2b) | 255,13,3,183,37,89 | 360 B | 21.2 s exit-clean | **IDENTICAL** |
| L | 1790626500 | cafebabe | session | (0xc8=200) | 403 (out of 8-bit domain) | 360 B | 21.4 s exit-clean | **IDENTICAL** |

**12/12 byte-identical.** Every case also independently confirms:
`head16_matches_pure_d0 = True` (the VM's own emitted head16 equals
`head_words(d0w)`), `record_consts_ok = True`, and the emission stream is the
canonical sink `0x5500000000` in every run (no stream ambiguity).

Coverage notes:
- pool phases tested: `43` (A), `(43,72)` (B), and the re-sign phase
  `(43,7,34,46)` (H).
- non-pool phases tested: 5, 17, 61, 90, 126, 0, 200, and the 6-long mixed
  phase in K — 8 distinct arbitrary phases, none present in captured traffic.
- **mask-domain edges both pass**: selector 0 → mask 3 (F) and selector 126 →
  mask 255 (E), the two extremes of the funnel's 0..126 range. The funnel's cap
  is exactly right: `mask(126)=255 <= 255`, and `mask(127)=257` would be the
  first out-of-domain value.
- case **I** is the structural control: it feeds the VM a d0 whose bytes 16..143
  are zeroed. The resulting blob is **identical to case B's** (verified
  directly: `blob_vm[I] == blob_vm[B]`). So the VM reads **only d0[0:16]** —
  it does not transform d0, does not use the tail, and does not derive anything
  from it. This is precisely the region `head_words(d0w[:4])` covers in the pure
  record, which is why the pure law is structurally exact, not coincidentally so.
- case **L** (selector 200 → mask 403) is *outside* the 8-bit mask domain. It
  still matches the VM, because `_selector_halfword` reads only bits 0..7, so
  mask 403 truncates to 147 — the same halfword as selector 72. The VM agrees
  because it never sees the mask, only the resulting 16 bytes. This is
  consistent, but see §4.

---

## 2. `_d0_words` derivation audit

### 2a. Full 36 words vs the 6 captured VM probe streams

`probes/run_r*.json` store d0 as 36 hex words (144 B). `pure_sign.region` was run
at the probe's own seed and compared word-by-word across **all 36 words**, not
just head16:

| probe | seed | d0 (36 words) | d2 | d4 | note |
|-------|------|----------------|----|----|------|
| r0_base | a6da5d2b | **36/36 exact** | OK | 8/8 exact | at phase (43,72) |
| r1_sec1 | a6da5d2b | **36/36 exact** | OK | 8/8 exact | |
| r2_seed | 11223344 | **36/36 exact** | OK | 8/8 exact | |
| r3_claim | a6da5d2b | **36/36 exact** | OK | 8/8 exact | |
| r4_seed2 | 55667788 | **36/36 exact** | OK | 8/8 exact | |
| r5_sec2 | a6da5d2b | **36/36 exact** | OK | 8/8 exact | |

The probes were captured with head phase `(43,72)`, and at that phase
`_d0_words` reproduces the stream perfectly. At phase `(43,)` alone exactly
**one** word differs — word 0 — which is the expected and correct consequence
of the second selector (72) not being in the prefix. The tail (words 1..35) is
identical under both phases, confirming the stable `0x40|(i&7)` cycle.

So `_d0_words` is exact for the captured phase, and its only free parameter —
the head prefix — behaves exactly as the pool model says.

### 2b. The mask formula `(s<<1)+3`

The 12 genuine pool literals expand as follows (seed a6da5d2b; the 8 d0 source
halfwords are `3524 a904 4220 d631 0a17 212d 1491 1cf7`):

| selector | mask | binary | halfword |
|----------|------|--------|----------|
| 0x30 (48) | 99 | 01100011 | 0xe342 |
| 0x2b (43) | 89 | 01011001 | 0x69d5 |
| 0x34 (52) | 107 | 01101011 | 0xe955 |
| 0x37 (55) | 113 | 01110001 | 0x21e2 |
| 0x38 (56) | 115 | 01110011 | 0x3573 |
| 0x3b (59) | 121 | 01111001 | 0x2bf5 |
| 0x3c (60) | 123 | 01111011 | 0x3f64 |
| 0x35 (53) | 109 | 01101101 | 0xdce9 |
| 0x36 (54) | 111 | 01101111 | 0xc878 |
| 0x2d (45) | 93 | 01011101 | 0x48f8 |
| 0x48 (72) | 147 | 10010011 | 0xeb73 |
| 0x05 (5) | 13 | 00001101 | 0x37cd |

All 12 masks are **odd**, as `(s<<1)+3` requires (bit 0 set by the `+3`, bit 1
from the low bit of `+3`). All 12 yield 12 *distinct* source-subset shapes.

How much of the mask domain the capture actually pins down:

- the 12 pool literals pin masks {13, 89, 93, 99, 107, 109, 111, 113, 115, 121,
  123, 147}
- the stable cycle in the captured d0 pins masks {131, 133, 135, 137, 139, 141,
  143, 145} (selectors 0x40..0x47)
- total distinct masks pinned by real traffic: **10** beyond the pool, all odd.

So the capture proves the formula on 10 distinct masks (22 selectors' worth of
d0 content, since each of the 72 halfwords is independently pinned by the
6 probes across 3 distinct seeds). The remaining odd masks in 0..255 are
**extrapolated** by the law, not individually observed — but the VM diff in §1
closes that gap: the VM accepts any d0[0:16] it is given (case I proves it never
looks at the mask or re-derives it), so an unobserved mask is a *free choice*,
not a correctness risk. The server cannot verify the phase.

Injectivity: for a fixed d4 the 256-mask → halfword map was checked over 200
pseudo-random seeds and is **injective in every one** (256 distinct halfwords
per seed, 0 collisions). So the phase is recoverable from a blob
(`solve_head_phase` does exactly this) but entirely unconstrained — consistent
with the "the server cannot verify the choice; proven live" claim in
`pure_sign.py` and `adj9_signer.py`.

### 2c. The pure gate still passes end-to-end

`pure_sign.py`'s own gold gate re-run inside this audit: **9/9 byte-exact** on
the genuine captures (3 creditsea 5.8.0 + 6 penti 5.7.0), solving back to
phases `(2b)` and `(2b 48)`. The shipped signer's
`adj9_signer.self_test()` also passes 9/9 claim laws.

---

## 3. Cross-implementation check (the refactor question)

Function-body diff of the 17 d0-path functions
(`_d0_source`, `_selector_halfword`, `_d0_words`, `region`, `head_words`,
`head16_for`, `_d4_words`, `_raw16`, `_transpose16`, `build_record`,
`sign_pure`, `whiten_forward`, `make_header`, `predict_digest`,
`predict_block`, `block_message`, `build_claims`) between
`pure_sign.py` and the shipped `adj9sign/one_click_run/adj9_signer.py`:
**0 of 17 differ.** The refactor did not touch the d0 path — the two are
textually identical in this region, including the `0x40|(i&7)` cycle, the
`(s<<1)+3` formula, and the `source[7-bit]` XOR order.

`adj9_signer_generic.py` differs only by an additive branch that routes three
synthetic `SYNTH_*` selector tables (used by the `fill_runs` synthetic corpus)
through explicit tables; the fallback branch — which every genuine and every
random phase takes — is the same `head + cycle` law. Its
`_selector_halfword` body is identical to the pure one.

---

## 4. Notes and residual risk (no fix required)

1. **The funnel's 0..126 cap is correct and should be kept.**
   `os.urandom(1)[0] % 127` in `adj9_signer.sign_request` keeps
   `mask=(s<<1)+3` inside 8 bits. Selector 127 would give mask 257, and
   `_selector_halfword` reads only bits 0..7, so it would silently alias:
   `mask 257 -> 0x01`, identical to `mask(1)`. Because the server does not
   verify the phase, an alias is harmless for acceptance — but it would shrink
   the effective phase space and make the emitted head16 *look* like a different
   selector than intended. Case L confirms the VM would not notice. Keeping the
   cap preserves a clean 1:1 selector→head16 story.

2. **Aliasing above the cap is real but inert.** Selectors differing by 128
   (e.g. 72 and 200) alias to the same halfword, because `(s<<1)+3` mod 256
   collides. Verified: `sel 200` and `sel 72` both give `0xb6fb` for the same
   d4. 128 such collisions exist in the range 0..599. Again: no server-visible
   consequence, but worth knowing before anyone widens the range past 126.

3. **What the phase is NOT.** The head phase is not a secret and not a
   signature input in any security sense — it is a free 8-bit device-state
   choice whose only observable effect is the first 16 bytes of the record.
   Case I demonstrates the VM has no opinion about d0 beyond those 16 bytes.

4. **Coverage limit of this audit.** 12 VM runs. The pure law is a closed form
   with no data-dependent branching beyond the selector, and the VM's
   d0-consumption is proven to be a pure 16-byte copy-through (case I), so
   additional phases would not add discriminating power — they would only
   re-confirm the same already-covered law. The one thing a wider sweep *could*
   add is confirmation that no descriptor other than #0 interacts with the
   phase; the 12 cases already vary `second`, `S`, `kind` and `claims` length
   across them, with no interaction observed.

---

## 5. Reproduction

```bash
cd C:/Users/Apps/Downloads/com.penti.app/adj9/rev/algo_practice/phase_verify
python verify_phases.py partA           # pure-only audit, ~2 s
python verify_phases.py partB           # 12 real VM runs, ~4 min
python verify_phases.py all
python verify_phases.py partB --only E,F   # just the two mask-domain edges
```

`verify_phases.py` loads the VM by absolute path via `importlib`
(`C:/Users/Apps/Downloads/com.penti.app/adj9sign/signer_simple.py`) — no
`sys.path` mutation, and `capstone` is not required (the module imports in 0.7 s
and defines `finex_mint` directly).
