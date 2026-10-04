# mint_testbed — the mint-signed funnel testbed (slice-144 shape, device oracle)

Date: 2026-09-24. Deliverables: `mint_pipeline.py` (the pure-Python mint +
funnel wiring) and this document. NOT yet executed against the network —
design + offline validation only (see §7 for the runbook).

## 0. Why this testbed exists (the slice-144 shape)

Slice 144 proved, with the device app itself as the only oracle, that a
**crafted**-signed booking session is accepted (200, adid issued,
`installed_at` booked) but **never joins the click's attribution**:

| arm (slice 144) | click | booking session | app's own verdict |
|---|---|---|---|
| slice 141 win (x11) | device | **app's own** | `24xg6t54 / VKM` |
| arm 1 | PC | crafted Python | `wy7261z / Organic` |
| arm 2 | device | crafted Python | `wy7261z / Organic` |

The only remaining variable between arm 2 and the 11/11 win path is **who
signed the session**. The crafted blobs were assembled from captured
per-call material and random regions; the server byte-matches rather than
recomputes (slice 143) and gates attribution on signature validity
(slice 146 §4). fill_model §6 closed the model: the region is F(tv, pid,
tid) — forgeable once F is lifted — and every F output satisfies the
structural laws (tile `U[2]^U[0] == R‖R`, `d4[6]>>16 == R`, `X == U[3]`)
that a random region fails with probability ~1-2⁻¹⁶. That is the hypothesis
these arms test: **a mint-signed session (law-built #10 + a real F-region)
books non-organic.**

The verdict oracle is the DEVICE APP's own `AdjustAttribution` file — never
a crafted poll (slice 92: crafted polls receive the silent Organic fallback
even when the record IS non-organic; slice 144 repeated it).

## 1. The pipeline being exercised (`mint_pipeline.py`)

```
claims map (wire params + internal-only keys)
  -> #10 = desc10_law.build_desc10(val, kind), NUL-padded to 4-B (slices 96/105)
  -> #7  = UNPADDED length, one BE dword (slice 99 §2)
  -> #8  = bfffffff fffffd1f 00070000 00000000   (corpus constant)
  -> #9  = fad0f10d60f93c17937b2f1eb6c09691ae7d74bd   (APK cert SHA-1)
  -> #5  = #6 = 00000000 ; #1/#3 empty
  -> #0/#2/#4 = F.py: region(V, pid, tid) -> d0[36]/d2/d4[8]
  -> FinEx(fin_vm2, seed=second) over va_order [0,9,8,4,2,7,10,5,1,6,3]
  -> blob = 48 BE words = 192 B; header(16 B) == make_header(second)
     = Random3(second) draws 1..8 pair-XOR (bionic random() TYPE_3, BE;
     srand re-fires per signing — emu_replay §0)
  -> Authorization: Signature signature="Base64(blob)",
     adj_signing_id="1500000", algorithm="adj9", headers_id="10",
     native_version="5.0.0", adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
  -> adj9_full_chain.send (direct, or Fiddler 8888 if up, or via-device)
```

Offline proofs already attached to this path:

* **Corpus 48/48** — `_finex_corpus_a/b/c.log` rows 0/1/4/5/6/7 reproduce
  byte-exactly from their descriptors + seconds; `mint_pipeline.py
  validate-corpus` re-drives the SAME rows through this module's assembly
  path (see §6 for the current run's result).
* **desc10 law** — `desc10_law.py` self-test byte-exact (session 360 B,
  click 387 B); `desc10_push_test.py` reproduces all 10 captured desc10
  values incl. the push_token variants (504/532 B).
* **Header law** — `make_header` 36/36 corpus + the two emu_replay
  byte-for-byte signings.

## 2. Preconditions (all must hold before any live run)

1. **F.py present** at `adj9/rev/F.py` with the contract
   `region(V, pid, tid) -> d0[36] / d2 / d4[8]` (V = tv_sec ^ tv_usec at the
   fill instant; pid/tid per-process constants). The pipeline imports it
   automatically (aliases accepted: `region`/`region_fill`/`fill`/
   `region_words`); words may be ints (packed BE) or raw bytes.
2. **Corpus validation 48/48** — `python mint_pipeline.py validate-corpus`
   exits 0 (rows 0/1/4/5/6/7). This proves the assembly path end-to-end.
3. **Dry-run self-check PASS** — `python mint_pipeline.py selftest` exits 0
   (192-B blob, header units, body == FinEx re-run, exit-clean, nrand=8,
   #7 coupling; region laws advisory).
4. Device: moto g42, serial **ZD2228MY3X**, rooted (`/debug_ramdisk/su`),
   `adb` connected. App `com.penti.app` 3.13.9 installed.
5. Network: direct from the PC; Fiddler auto-detected on 127.0.0.1:8888 and
   used only if running (both arms; verify_funnel parity).

## 3. ARM A — PC click + mint-signed session + sdk_click (no polls)

Purpose: the exact slice-144 arm-1 shape with ONE change — the signer.
Parity with `verify_funnel.py` (profile = yesterday's device-data JSON via
`run_funnel.DEVICE_JSON`, tz +0530, no idfa on the wire, first-open 25 s,
CTIT ~62 s).

Run: `python mint_pipeline.py arm-a --live`

| # | step | implementation |
|---|---|---|
| 1 | fresh GAID, link de-yesterdayed | `_fresh_gps_link`: every UUID in `run_funnel.LINK` (click_id, idfa, callback-url copies) replaced with the fresh GAID |
| 2 | real tracker click from the PC | `run_funnel.click_tracker` (curl_cffi chrome131, device UA/locale stamped, hops followed, reftag referrer returned) |
| 3 | wait 25 s | human first-open delay (CTIT ~62 s, winner-proven) |
| 4 | mint-signed session | `api_session_mint`: golden S1P template + fresh gps/auid/times, claims derived FROM the wire params, `mint_blob(..., kind="session")`, sent by `adj9_full_chain.send` |
| 5 | wait 3 s | SAZ parity |
| 6 | mint-signed sdk_click | `api_sdk_click_mint`: S2P template + real referrer/click times, `mint_blob(..., kind="click")` |
| 7 | **NO attribution polls** | slice 92/97 hazard: a crafted poll downgrades nothing but reads Organic-fallback and pollutes the record |
| 8 | device oracle | §5 below |

## 4. ARM B (isolation) — device click + mint-signed session

Purpose: the slice-144 arm-2 shape (signer-isolation arm): the winning
`fresh_click_install.py` flow — GAID on the device FIRST, click fired FROM
the device (adb curl 302, moto UA), CTIT 30 s — with ONE change: the booking
session is mint-signed. No sdk_click (win-path shape). Parity with
`verify_funnel2.py`.

Run: `python mint_pipeline.py arm-b --live`

| # | step | implementation |
|---|---|---|
| 1 | write GAID on the device FIRST | `set_gaid` patches `adid_settings.xml`, force-stops GMS |
| 2 | click FROM the device | `adb shell curl -L` on `.../1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id=<gps>&idfa=<gps>&gps_adid=<gps>` |
| 3 | wait 30 s | CTIT |
| 4 | mint-signed session | `api_session_mint` (installed_at = click+35 s, verify_funnel2 parity) |
| 5 | no sdk_click / no polls | win-path shape |
| 6 | device oracle | §5 below |

Interpretation: if arm B flips to non-organic while slice-144 arm 2 (crafted)
read Organic on the same shape, the discriminator is exactly the signature —
the cleanest possible isolation, because nothing else changed.

## 5. The device read (both arms) — the ONLY verdict source

Implemented in `device_read_verdict` (run automatically by both arms):

1. Back up the current attribution file to `mint_prev_attribution.bak`.
2. `set_gaid(<fresh gps>)` — write the install GAID into GMS
   (`/data/data/com.google.android.gms/shared_prefs/adid_settings.xml`),
   force-stop GMS.
3. Wipe the app: `am force-stop com.penti.app`;
   `rm -rf /data/data/com.penti.app/{files,shared_prefs,databases}`.
4. Launch: `am start -n com.penti.app/.ui.main.MainActivity`.
5. Poll every 12 s for **180 s (>120 s)**:
   `su -c 'cat /data/data/com.penti.app/files/AdjustAttribution | tr -d "\000"'`
   — the file is a Java-serialized object with the JSON embedded, so the
   parse is **`tr -d '\0'` FIRST, then grep `{"tracker_token`** (slice 144
   §4: the in-script regex missed twice without the NUL strip; both arms
   additionally NUL-strip in Python).
6. Verdict = the parsed JSON's `tracker_token` / `network`, read by the APP
   ITSELF.

**Success criterion: `tracker_token != wy7261z` AND `network != Organic`,
read by the app itself.** (`wy7261z`/Organic = the organic-fallback tracker
both slice-144 arms received.) A `24xg6t54`-class VKM tracker is the
historical win shape. Results land in `mint_arm_a_result.json` /
`mint_arm_b_result.json` (`verdict_device_oracle._success`).

Post-run hygiene: restore the device GAID (pre-run value is printed and the
previous attribution file is in the .bak) if the run is to be repeated.

## 6. Offline validation status (executed 2026-09-24)

* `selftest` — see the printed block in the run log / the summary below.
* `validate-corpus` — 6 self-consistent rows through this module's assembly
  path; expected `match=48/48 (hdr 4/4 body 44/44)` on every row (identical
  to `_finex_corpus`), rows 2/3 excluded as the known non-self-consistent
  captures.
* Fuzz-less by design: the corpus rows + the two laws tests ARE the fuzz.

## 7. What F.py must provide for the first live mint (the contract)

```python
# adj9/rev/F.py — imported by mint_pipeline.py as module "F"
def region(V, pid, tid):
    """V = tv_sec ^ tv_usec at the fill instant (int < 2**32).
    pid/tid: per-process constants (ints; per fill_model §1 the only other
    live inputs).
    Returns (d0, d2, d4) — or {'d0':..,'d2':..,'d4':..}:
      d0  : 36 words (list of ints) or 144 raw bytes  (#0)
      d2  : 1 word or 4 raw bytes                     (#2)
      d4  : 8 words or 32 raw bytes                   (#4)
    Word lists are packed BIG-endian (descriptor raw bytes == BE dump)."""
```

Requirements on the output (checked by `region_laws` in `selftest` when
F.py is present):

* **L1** the 4-word tile inside d0 satisfies `U[2]^U[0] == R‖R` (both 16-bit
  halves equal) — corpus 13/13;
* **L2** `d4[6]>>16 == R` — corpus 10/10;
* **L3** `d0[1] (X) == U[3]` — corpus 12/13 (phase-tolerant checks).

A region failing these is indistinguishable from the random regions slice
144 proved get booked-then-refused. For the live mint the pipeline picks
`V = signing_second ^ <real clock µs>` (`make_V`) — any µs in the target
second is valid (fill_model §6); override pid/tid with `ADJ9_PID`/`ADJ9_TID`
env if the capture that F was lifted from pins other values.

## 8. Hazards / notes

* The arms fire REAL tracker clicks and REAL booking sessions on fresh
  GAIDs — never re-run an arm on an already-booked GAID.
* `environment` must stay `production` in the claims (a non-production
  value gates the whole fill to zeros — fill_model §6).
* The claim `push_token` auto-includes when the wire params carry it; the
  funnel arms do not send sdk_info, so no push_token (winner shape).
* Attribution-kind minting exists (`kind="attribution"` in the law) but is
  PREDICTED-only (no EMIT capture) — and the arms deliberately never poll.
* Session `ask_in` on the response is engagement/rate-limits, NOT
  recognition (slice 144 §4).
* Do not compare cross-era emulator region words; the corpus rows here are
  DEVICE captures (no era caveat).
