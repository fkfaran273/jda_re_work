# Wall A — slice 11: REAL DATA pack (2026-09-11)

Heap mining closed first: `heap_mine.py` (70 known blobs × straight+dwordrev
over `hp_0.bin` 17 MB) = **0 hits**; `heap_mine2.py` (34 H + 34 LE headers +
claim strings over hp_0/1/2 + libdata + rwdata) = **0 in heap, static-table
hits only in `.data`**. The scudo dumps mistimed the burst (quarantine
recycles writers in seconds — slice 6 §5.4 predicted exactly this). Real data
therefore comes from synchronous logs, not async dumps. It is sufficient.

## 1. Golden pack (all in `rev/`, all real, all paired by ts)

| file | contents |
|---|---|
| `golden_saz.json` (`golden_saz.py`) | S1–S4: endpoint + HTTP status (**all 200 OK**) + full `Authorization` + param maps (S1 45× session, S2 49× sdk_click, S3 21× sdk_info; S4 = GET, params in query). S1 `created_at=2026-09-08T14:05:22.928Z+0530`, `gps_adid=1a89cb29…`, `app_token=jut9tib0eeps`, OnePlus DN2101/api30 |
| `golden_oracle_event1.json` (`golden_oracle.py`) | live event: 1280-B canonical (d3.a HMAC input, `event_token=p90b20`, moto g42/api31) + 54-field `sign_input` map + 192-B nSign blob + final header, ts-anchored `17889387889xx` |
| `../device/pairs_run.json` | **34 × (ts_ms, H_32B, blob_192B)** — the H-paired corpus (e.g. `1789072137644 efa2f9b7… 251adf8d…`). Rows 0/1 same second ⇒ same header, different bodies (re-confirms clock/body split; early misread of truncated print corrected: blobs differ) |
| `real_blobs.json` | 70 unique 192-B blobs (pairs_run 34 + probe 40 − overlap) |
| `../device/capture_oracle_125753.log` | 2 full signings: canonical + `adj_verification` + nsign + map + header |

## 2. The 11 descriptors: known / derivable / unknown (one event)

| # | len | content | status |
|---|---|---|---|
| 0 | 36 dw | 144-B core record (claims/env verdicts/ts?) | UNKNOWN layout; vocabulary = canonical + map + live `.data` table |
| 1 | 0 | NULL | known (skip) |
| 2 | 1 dw | 4 B ? | unknown |
| 3 | runtime | `{len,ptr}` string (time-string? property blob `0xe3c44` 2048-B read?) | unknown ptr; candidates on disk |
| 4 | 8 dw | **H = arg3 TEE-HMAC** | **KNOWN per call** (pairs_run; e.g. event triples above) |
| 5–7 | 1 dw | level (`arg4` = 31/30), ? , ? | 5 ≈ KNOWN const per device; 6–7 unknown |
| 8 | 4 dw | 16 B ? | unknown |
| 9 | 5 dw | 20 B SHA-1 digest (app cert? params?) | DERIVABLE (see §3) |
| 10 | runtime | caller struct `+0x128` `{len,ptr}` | unknown |

## 3. Routes to close the unknowns (ordered, cheapest first)

- **R1 — cert SHA-1, offline.** JCA trace (`adj9_hp.log`) proves once-per-process `SHA-1(745-B cert)`. `base.apk` has no v1 `META-INF/*.RSA` (v2/v3 only) → parse the APK Signing Block for the DER cert (expect 745 B), SHA-1 it → descriptor-9 candidate #1. Candidate #2 = SHA-1(canonical) / SHA-1(SAZ param body) from the golden pack. Zero device work.
- **R2 — cert digest, on-device, synchronous.** Xposed hook `java.security.MessageDigest.digest` filtered to the 745-B update (no frida, no timing race — in-call logging like the existing d3.a/u2.a hooks). Kills the R1 ambiguity in one run.
- **R3 — ns stamps (the hard one).** Record entropy = 2× native `clock_gettime` ns + env drift (slice 7). ms part is anchored (`ts_in`, `created_at`); sub-ms is open (10^6/ms × 2 stamps too big to brute force blindly — needs the un-whiten arithmetic from slice 10 first, which turns it into verify-by-resimulation).
- **R4 — core-record layout.** Once R1/R2 + stream-struct model (slice 10) land: forward-simulate with descriptor 4 = known H + 9 = R1/R2 + timestamps from the golden ts, compare 48-dword output vs the paired blob; layout = whatever maps.

Heap lesson (do not repeat): async `/proc/mem` scans after a burst are
structurally late — quarantine wins. All further real data must be
synchronous in-call logs (R2 pattern).
