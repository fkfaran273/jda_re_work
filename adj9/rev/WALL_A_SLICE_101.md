# Wall A — slice 101: key2 mechanism CONFIRMED, and three claims from slice 100 corrected

Date: 2026-09-18. Status: **mechanism closed; earlier blocker explained; key2 extraction
proven unnecessary for the offline goal.**

## 0. What this slice set out to do
Slice 100 ended at "extraction is one successful signing away: hook keystore2's
`HMAC_Init_ex` and make the app do one keystore HMAC". This slice ran that
experiment to completion and found *why it could never have worked*.

## 1. CORRECTION 1 — the app's namespace is not 10350
`ks.sqlite` was stale. The live DB (`pull_ks_db.py` -> `ks_after.sqlite`,
`exec-out` as root to keep the file binary-clean) shows the app in namespace
**10402**. Key entries:

| entry | value |
| --- | --- |
| `key2` (ns 10402) | `km_uuid = 00000000000000000000000000000001`, state 1 |
| `master_key` (ns 10402) | same uuid |
| `k2probe` (ns 10402) | same uuid (left by the probe in slice 100) |

## 2. CORRECTION 2 — km_uuid `000...001` is NOT "the soft instance"
Slice 100 read the old DB and concluded `000...001` was the software instance.
The live DB inverts that:

```
km_uuid=00000000000000000000000000000001  count=83  namespaces=[101,102,103,1000,1001,1017,2000,10145]
km_uuid=41e3b9ce27584e91bcfda55d9185ab11  count=6   namespaces=[0,102,1000]
```

`000...001` is the **normal per-app/TEE instance UUID**; the hardware UUID
belongs to keystore2's own six system keys only. Decisive control: a key minted
by `keystore_cli_v2 generate --name=... --seclevel=tee` also lands on
`000...001`, i.e. that uuid is what this device uses for **TEE**. The device
exposes **no software security level and no StrongBox**
(`--seclevel=software` -> "Unknown Security level";
`--seclevel=strongbox` -> `-68`). key2 is therefore a **TEE key**, which is why
its blob is sealed to the KeyMint instance key and no DB-only key opens it.

## 3. THE MECHANISM — where a keystore HMAC actually executes
The probe read `javax.crypto.Mac`'s private `spi` field after a successful MAC
with key2 and enumerated the providers. Verbatim from the device:

```
default Mac provider  : AndroidOpenSSL
prov#1 : AndroidOpenSSL             -> com.android.org.conscrypt.OpenSSLMac$HmacSHA256
prov#3 : AndroidKeyStoreBCWorkaround -> android.security.keystore2.AndroidKeyStoreHmacSpi$HmacSHA256
```

and this negative result, which is the crux:

```
Mac.getInstance("HmacSHA256", "AndroidKeyStore")
  -> java.security.NoSuchAlgorithmException:
     no such algorithm: HmacSHA256 for provider AndroidKeyStore
```

Consequences:

* The AndroidKeyStore provider itself offers **no Mac at all**; the SDK works
  only because the `AndroidKeyStoreBCWorkaround` provider installs
  `android.security.keystore2.AndroidKeyStoreHmacSpi`. That class is the one the
  slice-100 search was circling.
* `AndroidKeyStoreHmacSpi` is named for and lives in the **keystore2** package:
  the HMAC is executed **through keystore2**, not in the app.
* `key.getEncoded()` returns **null** — key2 is not exportable, so no Java-level
  capture is possible.

### 3.1 Why the slice-100 hook address was the wrong one
With minimal (non-hot) hooks installed *and verified live* in the app, in
keystore2 and in the vendor HAL at the same time:

```
[app ready]                               hooks=14
[keystore2:<pid> ready]                   hooks=5   (HMAC_Init_ex, HMAC_Final, HMAC, EVP_DigestSignInit, EVP_DigestSignUpdate)
[android.hardware.keymaster@...:623 ready] hooks=5
```

…and then the MAC ran successfully and **no HMAC/EVP symbol fired in
keystore2 or the HAL** (`hmac_key` events: 0 in both; the only `HMAC_Init_ex`
hits were app-side TLS with `klen=48`). So `libpuresoftkeymasterdevice` does
**not** reach its HMAC through the exported libcrypto entry points that slice 100
identified, and the HAL is not used either. A SIGSTOP probe agreed: freezing
keystore2 tears the app's session down (keystore2 is on the path) while the
exported-symbol hooks stay silent.

Net: key2's HMAC is computed by **internal / statically linked crypto inside the
keystore2 process**, reachable only by address-based hooks or by reading the
keystore2/pure-soft device internal symbols — not by export hooks.

### 3.2 Two environment traps that cost the earlier session its capture
* **Frida 17 removed the built-in `Java` global.** A probe using bare
  `Java.use` fails with `ReferenceError: 'Java' is not defined`; it must be
  bundled with the local `frida-compile` + `frida-java-bridge` (this is why
  `ks_probe_bundle.js` exists).
* **keystore2 restarts constantly** (pids 11561 -> 4268 -> 9857 -> 18222 ->
  21500 -> 29830 -> …) and dies on attach ("connection is closed"). A hook
  installed a moment earlier is already gone. `ks_ks2_run.py` therefore keeps a
  watcher thread that re-attaches on every new pid before the MAC is triggered.

## 4. Was the previous conclusion still right?
Yes on the substance:

* `H = HMAC-SHA256(key2, message)` stands (SDK 5.0.0 bytecode, slice 100 §1).
* `d9 = SHA1(cert_s0_0.der)` re-verified this slice (`cert_d9.py`:
  `fad0f10d60f93c17937b2f1eb6c09691ae7d74bd`, 745-B cert).
* key2 is per-install, sealed in the TEE and never leaves it, so **the Adjust
  server cannot verify H cryptographically**. H attests a device-side signer; it
  is not a server-checkable MAC.

## 5. Independent, verifiable results from this slice
1. **Offline signer reproduces a real device signing 48/48 byte-exact**
   (`sign_control.log`): control mode, `second 1789240512`, VM exit-clean in
   43.1 s / 9 871 985 emit steps, header == Random3 law, *48/48 BYTE-EXACT ==
   captured blob*.
2. **The header law inverts the genesis time of a genuine signature**
   (`verify_genuine2.py`): brute-forcing `Random3` over `fresh_genuine.json`'s
   192-B blob recovers exactly one `second` (1789474915), matching its
   `created_at` to the minute.
3. **The maker builds exit-clean, law-correct blobs for an arbitrary real map**
   (`vg4.log`): the genuine `/attribution` query plus the session-law fields
   yields `status=exit-clean law=OK`. Only the 4 header dwords match, and the
   body cannot match because `#0` (36-dword per-request core) and `#4` (H) are
   per-call inputs the genuine request had and we do not.
4. Descriptor inputs for the golden second are recorded in
   `desc_det_result.json` (d0/d4/d8/d9/d2/d7/d10 per kind). Notably **`d0` is not
   random**: it is a 5-dword unit repeated
   (session `[321327729, 3679515724, 3057096908, 3669488922, 3083901227]` ×7+1),
   which makes `#0` a promising derivation target — and `#0` is the only other
   opaque input besides H.

## 6. Artefacts added this slice
`pull_ks_db.py`, `km_uuid_cmp.py` (+ logs), `ks_after.sqlite`,
`agent/ks_min.js` (multi-module, no-dedup HMAC hook set),
`agent/ks_sweep.js`, `agent/ks_sweep_probe.js`, `agent/ks_probe_src.js` +
`agent/ks_probe_bundle.js` (frida-compile bundle), `ks_sweep_run.py`,
`ks_hal_run.py`, `ks_combo_run.py`, `ks_ks2_run.py` (keystore2+HAL re-attach
watcher), `ks_freeze_test.py`, `verify_genuine.py`, `verify_genuine2.py`,
`probe_procs.sh`, plus `ks_*_capture.json` and the corresponding logs.

## 7. Next (in order)
1. Derive `#0`'s 5-dword repeating unit — then `#0` stops being an opaque input
   and every byte except `#4` becomes computable from the map.
2. Only if a byte-exact genuine H is required: hook keystore2 by **internal**
   address (resolve `libpuresoftkeymasterdevice.so`'s HMAC path through its own
   symbols/GOT instead of exports), reusing the re-attach watcher already in
   `ks_ks2_run.py`.
3. Otherwise treat H as a random per-call nonce: it is not server-verifiable, and
   the crafted path already returns 200 (`amc_final.log`).