# COMMIT_FINDINGS.md — the 3.62.0 claims-commitment law (c20 / c32) — SOLVED

Date: 2026-10-05.  Work dir: `adj7/work/`.  Everything outside `adj7/` read-only.
Oracle: 3 mints of session params (doodhvale sid 0015) under the genuine
libsigner.so 3.62.0 in Unicorn (`adj7_work/adj7s3_emu.py`):
A (sec 1771238644, claims C0), B (sec …645, same claims), C (sec …644, claims C1
app_version "8.4.2"→"9.9.9" — actual claims value "8.4.4"→"9.9.9", 3 bytes
differ at claims offsets 50/52/54), plus a fresh mint D run for this task
(sec 1771239000, app_version "7.7.7").

## 0. Verdict

**SOLVED — byte-exact on A, C and the fresh mint D (new second + third claims
variant).**  `commit2_hunt.py` reproduces all six targets and cross-checks
them against the heap snapshots.

```python
IV0   = 16ba6d02 11a298c2 82187e46 4c148c22 3a5cbc15 06519f14 97b9e370 08ec3bec
        # constant for this device/app (see §4)
msg   = 00*40
        || d666bf34 44ddccca 7eada76a            # 12-B device/app constant
        || hex-upper(sha256(b""))                # 64 ASCII chars, the anchor
        || claims                                # build_claims("session", P)
        # 460 B for a 344-B claims; one 512-B padded block-set (8 blocks)
H     = SHA-256 with custom IV = IV0 over msg (STANDARD rounds, standard
        K, standard padding, standard feed-forward chaining — nothing else
        is custom except the IV and the message)
H_prev= chaining value before the last block
c20   = LE-word-encode( H[12:32] )     # digest words d..h, byte-swapped in RAM
c32   = LE-word-encode( H - H_prev )   # the last block's raw working vars
```

* Every dword the native stores in memory is **byte-swapped** (LE) relative to
  the standard BE digest words — the "word-swapped engine domain".  This alone
  invalidated the entire earlier exclusion grid (it compared standard hex
  digests against the swapped RAM bytes).
* c20 is **not** a SHA-1 and not a standalone hash: it is the **last 20 bytes
  of the same 32-B digest** whose first 12 bytes are the c32 relation's
  partner.  `c32 = H − H_prev` is exactly the final block's raw working
  variables (what the VM leaves in its state buffer after round 63 before the
  feed-forward add).

Verification (H = final digest, numeric BE words):

| mint | sec | claims | H | c20 (RAM) | c32 (RAM) |
|---|---|---|---|---|---|
| A | 1771238644 | C0 | `99e41c69 796c7e00 8a60e68e 51eaff6c 0994a910 5752e810 08c61db5 22c577c5` | `6cffea51…c522` OK | `095ccb38…1656b` OK |
| C | 1771238644 | C1 | `b2fe627a a43c2387 b84d0aee 705dbe40 a485dc51 820dec5b 7e546932 de642dd5` | `40be5d70…64de` OK | `a8c5b456…fd1f65` OK |
| D | 1771239000 | "7.7.7" | `eb9fbb83 4202b1d5 190a41ad 3c18a5ad b560346e aa6e898e f195b771 5639907e` | `ada5183c…03956` OK | `c390048a…e507c9` OK |

## 1. How it was found (trace mining, reproducible)

`commit2_probe.py` mints one signature with full write/read instrumentation
(value bus 0x71ef67c, all heap writes, deduped reads).  `commit2_extract.py` +
`commit2_wextract.py` reconstruct the VM op stream `(value, dest)` and recover
every SHA-256 run:

1. The VM materialises `sha256(b"")` itself: FIPS-IV init at heap 0x900bcd8,
   one block `80 00…00 || len=0` → `e3b0c442…` (standard, with feed-forward).
2. An earlier chain (IV = `sha256(b"")`, message computed in VM registers,
   first words `b38b4898 967137fd 76892298 … b206f53d`) produces **IV0** —
   this hash never touches a contiguous state buffer for its rounds, so its
   message is not in the trace; IV0 is treated as a constant (it verified on
   mint D at a different second, so it does not depend on time or claims).
3. The c32-hash: 8 single-block runs at heap 0x900be98 (inits
   `16ba6d02…, f26a358a…, 1ed707df…, 2120755b…, d12b9434…, 6c107c85…,
   0dac4574…, 6118c060…`), each 64 rounds with W recovered **algebraically**
   (`T1 = new_e − old_d`; `W = T1 − h − Σ1(e) − Ch(e,f,g) − K[r]`) — the W
   words spell the message text directly.  Round-level recompression matches
   the recorded states exactly (standard K, standard expansion).
4. The per-block chaining is the standard `H_{k+1} = working_k + H_k`; the
   final digest `99e41c69…` is written to 0x900bb78 (where c20 = words d..h),
   while the *un-added* last-block working vars (`38cb5c09…`) stay at
   0x900be98 as c32.

## 2. The message, byte-exact (460 B)

```
offset  0.. 39  00 *40                       (zero field, constant)
offset 40.. 51  d6 66 bf 34 44 dd cc ca 7e ad a7 6a   (device/app constant)
offset 52..115  "E3B0C44298FC…7852B855"      hex-upper(sha256(b"")), 64 chars
offset 116..459 claims (344 B, build_claims order: profile-vals ||
                "1300000" || tail-vals || block2)
padding         80 00…00 || BE64(3680)       (standard, total 512 B = 8 blocks)
```

The 40 zero bytes and the 12-B constant are written as VM immediates before
the claims are staged (ops 3795–3807 of the probe trace); they are constant
across seconds and claims.  The `sha256(b"")` anchor matches the adj9-family
law — except it enters as **ASCII hex, not raw 32 B** (adj9-iOS uses raw).

## 3. Claims-derived data in the VM program structures (A-vs-C diff map)

Each of the 4 program structures (starts −16 B head16, then c20) is ~2.5–3 KB.
A-vs-C differing ranges **inside every structure** (relative to c20):

| offset | len | content |
|---|---|---|
| +0x000 | 20 | **c20** |
| +0x0B9 | 7 | the app_version bytes inside the swap4(claims) copy ("8.4.4"→"9.9.9" spreads to 7 B in the 4-B-swapped text) |
| +0x314 | 32 | **c32** |
| +0x560* | 64 | ASCII-hex of another claims-dependent 32-B digest D (A `4e9996c1…c225c77`, C `ef2ba726…6ed5dd2`; derivation open — not needed for c20/c32) |
| +0x799* | 7 | app_version inside a second swapped-claims copy |

\* the 64-B/second-7-B offsets drift by +0x20 between structures 1/3 and
2/4 (structures 2..4 embed one extra 32-B word before those fields).
Structures 1..4 begin at 0x900bb74 / 0x900c564 / 0x900cf74 / 0x900db84; the
16-B head16 before each c20 is the MINSTD record head (A-vs-B only).
A-vs-B differs ONLY in: head16 copies (6×16 B), the head16-as-LE32-word table
at 0x900f058/0x900f09c, and two 1–2-B stragglers — the record/time plane.
A-vs-C additionally differs at: 0x9001120, 0x9004312 (raw claims copies,
5 B), 0x90052d5/0x900549d/0x9007141/0x900a395/0x900a55d/0x900b92d (7 B,
app_version in further swapped-claims copies), the six 64-B D-hex copies
(0x90056f4, 0x900b6f4, 0x900ba98, 0x900caf4, 0x900ce98, 0x900d704,
0x900daa8, 0x900e514), the tail fragment tables at 0x900e8bc–0x900e9b8, and
0x900f12c–0x900f224 (claims materialised as LE32 word tables).

swap4(claims) copies (raw memory = claims with each 4-B group reversed; the
dump reads correctly "one byte in"): 0x90052a4, 0x900546c, 0x9007110,
0x900a364, 0x900a52c, 0x900b8fc, 0x900bc0c, 0x900c2ec, 0x900c5fc, 0x900ccfc,
0x900d00c, 0x900d90c, 0x900dc1c, 0x900e71c.  The copies at 0x900bc0c etc. sit
inside the program structures directly after a 24-B tail of sha256("")-hex
text and are followed by the engine-domain SHA-256 padding (`00 00 00 80…`
raw = `0x80, zeros` in the swapped domain).

## 4. Notes / residual unknowns

* **IV0 origin.**  IV0 = `16ba6d02…` is produced by a hash chained from
  `sha256(b"")` whose message runs in VM registers (invisible to the trace).
  It is *not* time- or claims-dependent (mint D verifies at sec 1771239000),
  so it is a per-device/app constant; recalibrate with one instrumented mint
  if the device/app changes.  Its first consumed words are
  `b38b4898 967137fd 76892298 …` (not the MINSTD draws, not DK37/KB362).
* **The 12-B prefix** `d666bf3444ddccca7eada76a` — likewise a constant
  immediate (same caveat).
* **D digest** (`4e9996c1…` ASCII-hex, stored in the JSON-ish buffers and
  inside each program structure): claims- and not time-dependent; not one of
  the obvious chains (sha256 of msg460/claims under FIPS or IV0, with or
  without feed-forward, all excluded).  Not required for c20/c32.
* **KB362** (`adj7s4_immruns.json["d20a0"]`, 64 dwords) is staged in reverse
  at 0x900ba78..0x900bb74 right before the c32-hash, but the c32-hash uses
  the **standard K** — KB362 belongs to a different consumer (likely the
  whitening SPN, cf. `crack_grid.py`).
* The earlier `commit_hunt.py` exclusion grid failed for three stacked
  reasons: (1) swapped digest storage, (2) the custom IV0 + message prefix
  (the hash input is *not* the bare claims), (3) c20 being a *slice of* the
  32-B digest rather than a 20-B hash.

## 5. Artifacts (all new, in `adj7/work/`)

* `commit2_hunt.py` — the closed-form law + verification on A/C/D + heap
  cross-check (`python commit2_hunt.py` → LAW VERIFIED).
* `commit2_extract.py` — snapshot mapping (claims copies, diff clusters).
* `commit2_probe.py` — instrumented mint (bus/writes/reads capture).
* `commit2_wextract.py` — SHA-run segmentation + W recovery via round algebra.
* `commit2_fresh.py` — fresh mint D (new second, third claims variant).
* `commit2_snap_D.bin`, `commit2_blob_D.hex`, `commit2_probe_heap.bin`,
  `commit2_bus.bin` — evidence snapshots (kept small; the multi-GB raw logs
  were deleted).
