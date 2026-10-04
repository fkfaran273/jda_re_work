# SAZ LIVE TRAFFIC VALIDATION — `pentindroid_logs.saz`

Source: `C:\Users\Apps\Downloads\pentindroid_logs.saz` (Fiddler Session Archive,
4 sessions). Extracted to `pentindroid_logs_saz/raw/{1..4}_{c,s,m}.{txt,xml}`.

**This is the first corpus of real, server-ACCEPTED adj9 signatures from a
second, independent device** — it converts the model from "self-consistent
against our own device" to "externally validated".

## 0. Capture metadata

| field | value |
|---|---|
| device | **OnePlus DN2101** (NOT our ZD2228MY3X) |
| OS | Android **11**, `api_level=30` |
| app | `com.penti.app` 3.12.1, `app_token=jut9tib0eeps` |
| `Client-SDK` | `android5.7.0` (Adjust SDK 5.7.0) |
| capture time | 2026-09-08T14:05:2x +0530 |

Endpoints: `/session` (S1), `/sdk_click` (S2), `/sdk_info` (S3),
`/attribution` (S4). **All four returned `HTTP/1.1 200 OK`** with valid
payloads (e.g. S4 returns the full `attribution` block, `tracker_name=Organic`,
`adid=df7a1b1e7057b8c329f83ff1104e3b87`). ⇒ the server **accepted** these
signatures; nothing else was required.

## 1. `Authorization` header — structure confirmed verbatim

```
Authorization: Signature signature="<256 base64 chars>",adj_signing_id="1500000",
               algorithm="adj9",headers_id="10",native_version="5.0.0",
               adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
```

- `signature` = 256 base64 chars = **192 raw bytes** (16 header + 176 body). ✓
- `adj_signing_id="1500000"`, `algorithm="adj9"`, `headers_id="10"`,
  `native_version="5.0.0"` — exactly the values read out of the live
  decrypted string table (`device/rwdata2.bin`). ✓
- **`adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"` is byte-identical to
  the value computed fully offline**
  (`Base64(XOR('{"os_name":"android"}', "Quoh8uafohgh7CahM2h", i%19))`).
  This is the strongest single confirmation of the offline-computable subset.

**New distinction:** `Client-SDK: android5.7.0` (Adjust SDK version) is NOT the
same as `native_version="5.0.0"` (the signer library version). Two independent
version axes; do not conflate them.

## 2. Header law — 4/4 on live traffic (first external validation)

Decoding the first 16 bytes of each `signature` and running
`rev/header_gen.py::make_header(unix_sec)` against the request's own
`created_at` stamp:

| sess | observed header (bytes 0..15) | created_at | law-match |
|---|---|---|---|
| S1 | `40c8114d3f66c6da1f0f75727e1c44e6` | 1788856522 | **YES @ 1788856523** |
| S2 | `40c8114d3f66c6da1f0f75727e1c44e6` | 1788856522 | **YES @ 1788856523** |
| S3 | `1cd2ae9f0e15b37b03f74f477ce50120` | 1788856525 | **YES @ 1788856526** |
| S4 | `22765532499ffa6739b7d93e539dcb22` | 1788856527 | **YES @ 1788856528** |

- The law reproduces every header exactly, at `created_at + 1 s` (the sign
  happens ~1 s after the payload is stamped). Consistent offset across all 4.
- **S1 and S2 share a byte-identical 16-byte header** despite being different
  endpoints (`/session` vs `/sdk_click`) with completely different bodies —
  because they were minted in the same wall-clock second. This is a direct,
  external confirmation that **the header is a pure function of `time(NULL)`
  and carries nothing from the payload**.
- `api_level=30` here vs `31` on our device ⇒ the header law is API-level
  independent (as the `Random3`/bionic-`rand()` model predicts).

## 3. Body (176 B) — external high-entropy confirmation

Bodies of all four requests (bytes 16..191) dumped in `SAZ_BODIES.txt` style
above: fully high-entropy, **no ASCII, and 0 byte positions constant across the
four samples**. Consistent with the model:

- the body is the fold output over (record ⊕ ctx material) with a fresh
  32-bit `/dev/urandom` seed per call — so it re-randomises even for identical
  inputs and has no fixed positions;
- S1 and S2 share a header but have **completely different bodies** (176/176
  bytes differ), which the "header = time, body = payload+urandom" split
  predicts exactly.

## 4. Corrections to earlier notes

1. **"libsigner is re-mapped at every signing with a fresh ASLR base" is
   WRONG.** The library is mapped **once per process launch** (normal ASLR) and
   **persists** — verified: PID 23802 showed base `0x7b8164b000` on two map
   reads several minutes apart, *after* the signing had completed. The observed
   `7b82a02000 → 7b8bc89000` change was across **process restarts**, not across
   signings. Consequence: **no need to race a signing** — the `.data` is
   readable at any time.
2. **How to compute the runtime base from maps alone** (no guessing):
   libsigner.so sits at **APK offset `0x54000`** inside
   `split_config.arm64_v8a.apk` (`lib/arm64-v8a/libsigner.so`,
   `data_off=0x54000`). Its first `PT_LOAD` has `p_offset=0, p_vaddr=0`, so
   `base = start_of_the_r-xp_mapping_whose_file_offset_is_0x54000`.
   In this session: `7b8164b000-7b81794000 r-xp 00054000 …` ⇒
   **base = `0x7b8164b000`**, and e.g. `va 0x151d18 → 0x7b8179cd18` (inside the
   live `rw-p` APK mapping `7b8179c000-7b817a1000`). Verify by matching the
   ELF's other `PT_LOAD`s to the page-aligned APK offsets
   (`0x19ce60→0019c000`, `0x19dc20→0019d000`).

## 5. Why the stack-ctx scan found nothing (root cause)

The `ctxcap5` capture **did** land correctly: the watcher triggered on
`nsign_in` growth, resolved the `Adjust-pool-*` stacks, and dumped the top
64 KB of each (offsets verified against `/proc/23802/maps` — correct).

The scan still returned 0 hits because **the fold ctx / marker data is not on
the stack at all** — it lives in libsigner's **`.data`**, mapped from the split
APK (see §4.2). A stack scan is structurally incapable of finding it. The
"stack-resident ctx" premise in the earlier notes was the error.

Additional confirmation that `.data` holds no mutable per-call state: diffing
two independent sessions' `.data` dumps (`rwdata2.bin` @ base `0x7b82a02000`
vs `signer_data.bin` @ base `0x7b8164b000`) gives **1067 differing bytes, all
of them 8-byte relocated pointers in the table at va `0x14ce60`** differing by
exactly the ASLR delta. No non-relocation bytes differ ⇒ `.data` is
semantically static; the per-call ctx must be stack/heap after all, but it is
*not* the marker array.
