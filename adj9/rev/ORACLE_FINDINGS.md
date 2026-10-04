# adj9 192-byte envelope — oracle-run findings (2026-09-10)

Post-summary work on disk: `cap/oracle_run1..7.log` (LSPosed chosen-input oracle,
`adj9/module/src/com/adj9oracle/Hook.java`) + `cap/rand_trace.js`.
Re-analysis scripts: `oracle_map.py`, `oracle_analyze.py`, `oracle_pairs.py`,
`nsign_cipher.py`, `body_diff.py`, `fiddler_map.py`.

## 0. Answer to "is the Fiddler form data what's inside the blob?"

**The Fiddler form fields ARE the signed content — but they are NOT what's inside
the 192-byte blob.**

```
request fields (45 in form) ──► LinkedHashMap (50 entries incl. adj_verification,
   │                            excl. the 4 header fields; map_size=54 after signing)
   │                              │  ~1.2–1.5 kB as "{k=v, k=v, ...}"
   │                              ▼
   │                        HMAC-SHA256(canonical, key2)  = 32 B  (arg3 / "H")
   │                        SHA-1(app signing cert)       = 20 B  (fad0f10d…)
   │                        + trust-store CA digests (MD5/SHA-1/SHA-256)
   ▼                              ▼
HTTP POST body (1041 B)     nSign ──► 192 B = [16 B PRNG header][176 B body]
```
The map is 1.2–1.5 kB; the body is 176 B. The form cannot be, and is not,
carried inside the envelope — only digests/claims derived from it are.

## 1. Field-for-field: signed map ↔ Fiddler POST body (`fiddler_map.py`)

- 43 of the 45 Fiddler form field names are signed verbatim, same values
  (device-independent fields match exactly: `app_token=jut9tib0eeps`,
  `app_version=3.12.1`, `store_name_from_system=com.android.vending`,
  `os_name=android`, `cpu_type=arm64-v8a`, …).
- **In form, NOT signed:** `mcc`, `mnc`.
- **Signed, not in form:** `activity_kind`, `adj_signing_id`, `adj_verification`,
  `algorithm`, `client_sdk`, `headers_id`, `native_version`, `push_token`,
  `session_length`, `subsession_count`, `time_spent`.
- Device-specific only: `api_level` (31 vs 30), `os_version` (12 vs 11),
  `gps_adid`, `android_uuid`, `hardware_name`, `device_name`,
  `device_manufacturer`, `display_height`, `installed_at`, `created_at`,
  `sent_at`, `updated_at`, `session_count`.

## 2. NEW — the 176 B body re-randomizes on every call (`body_diff.py`)

`oracle_run7.log` rapid-fire: 24 nSign calls with **byte-identical** inputs
(same map, same arg3, same apiLevel).

| rows | t0 (ms) | header[:16] | body |
|------|---------|-------------|------|
| 4,5  | 1788956309411 / 1788956310340 | `49672b213dde2d9d11aad13516394cf7` (equal) | **176/176 bytes differ**, common prefix 0 B, hamming 696/1408 = 49.4 % |
| 10,11| 1788956314443 / 1788956315253 | `7c73f29a26ceedd8080b78182800ddaf` (equal) | **176/176 bytes differ**, hamming 49.4 % |

Same seed-second → **identical header** (header law holds), but the body is
random-independent. So the body is **not** a deterministic function of
(map, H, apiLevel, seed-second): it consumes entropy the header does not
(`.data` has `/dev/urandom`; `libsigner.so` imports `gettimeofday`).
Header words are 31-bit (MSB never set); body bytes are uniform (MSB 0.50 over
35 blobs) → body looks like cipher output, not PRNG output.

⇒ Consequence for the goal: the header is forgeable offline for **any**
timestamp; the body is **not** synthesizable by replaying the header law.
Every genuine mint needs the on-device oracle (or the envelope scheme + key).

## 3. Where the encryption is NOT (negative results that narrow it)

- **Runtime cipher census** (all runs, full app process): only
  `AES/GCM/NoPadding` (468×) and `AES/GCM-SIV/NoPadding` (91×) — every one is
  the app's own EncryptedSharedPreferences (keystore alias
  `_androidx_security_master_key_`, prefs `core_network_sec`, `access_token`,
  `user_session`). **`RSA/ECB/PKCS1Padding` is never instantiated at runtime.**
- No RSA OID `1.2.840.113549.1.1.1` anywhere in `libsigner.so`; entropy scan of
  all PT_LOADs peaks at 6.62/8 over 256 B windows (= dense ARM64 code) → no
  embedded RSA/AES key blob.
- Keystore aliases: `key2` (HmacSHA256, TEE-generated) + androidx master key only.
- `libsigner.so` has native SHA-1 (`init @0x12e5f4`) and no cipher constants;
  ⇒ the body is assembled by native code we have not yet sliced.

## 4. Oracle experiment results (`oracle_analyze.py`, `oracle_pairs.py`)

- `apiLevel=0` → nSign returns **null** (`len=-1`): level is gated.
- `zero_h` (arg3 = 32×0x00) → still a valid 192 B blob: nSign **recomputes its
  own HMAC** internally (`mac.update` len 1142/1355 inside the window, output =
  the true H) and ignores the Java-passed arg3.
- `empty_map` → still 192 B: the body does not inline the map.
- `hflip` (one bit of arg3) / `mapflip` → blob changes, but every pair crossed a
  second boundary, so these do **not** isolate cleanly (only the rapid-fire
  pairs do).
- srand fires ~600–700 ms into each call (call durations 0.8–2.2 s) → seed is
  `sec_in` or `sec_in+1`, which is why the two 929 ms-apart rapid calls can
  share a seed second.
- FIFO pairing is required: nSign calls overlap (`nsign_in` @631649 and @632037
  both complete inside second 632).

## 5. Open

- `1:782059328469:android:7ccc8778c27aa4edd2235c` — Base64'd (flags=11) then
  SHA-1'd over 88 B (`<that string>` + app_version + …), logged **outside**
  nSign (1.5–24 s before each session signing), device-stable across runs.
  Origin unknown — likely SDK signing-id material. Not found in `.data` yet.
- Next static slice: rand-loop return → body assembly path; or dynamic: trace
  `/dev/urandom` reads + `gettimeofday` inside nSign (`cap/rand_trace.js`).
