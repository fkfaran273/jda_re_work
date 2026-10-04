# SIGNATURE IS THE GATE — CONFIRMED (decisive A/B, 2026-09-24)

## Result

The user's hypothesis is **proven**. With a genuine click, a fresh GAID, and
the identical request flow, the ONLY variable is who computed the adj9
`Authorization` header:

| Arm | Signer | Verdict | Tracker token | Engagement time |
|-----|--------|---------|---------------|-----------------|
| oracle (run 1) | real device TEE signer | **NON-ORGANIC** | `24xg6t54` | `2026-09-24T15:13:14Z` |
| oracle (run 2) | real device TEE signer | **NON-ORGANIC** | `24xg6t54` | `2026-09-24T15:16:40Z` |
| python (control) | adj9_signer reimplementation | **ORGANIC** (5/5 polls) | `wy7261z` | `0001-01-01T00:00:00Z` |

Both arms: fresh click via the real tracker link, fresh `gps_adid` +
`android_uuid`, same device profile, same referrer, same CTIT, same three
endpoints (`POST /session`, `POST /sdk_click`, `GET /attribution`), same
transport. Reproduced twice on the oracle arm. The only difference is the
192-byte adj9 signature: real `Signer.sign()` (TEE-bound) attributes;
the Python envelope never does (server returns HTTP 200 but keeps the install
organic). **The signature is the sole gate.**

## How the oracle signs a caller-chosen map (the key enabler)

`adj9oracle` is an LSPosed module scoped to `com.penti.app`. It runs
in-process (immune to the app's frida anti-tamper), captures the app's live
`Signer` singleton, and on a thread calls the REAL
`Signer.sign(Context, LinkedHashMap activity, Map globals, Map out)` with a
map we supply. It returns the genuine TEE-signed `Authorization` header:

```
AUTH <idx> Signature signature="<base64 192B>",adj_signing_id="1500000",
      algorithm="adj9",headers_id="10",native_version="5.0.0",
      adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
```

Control-file protocol (this is the chosen-input interface):
- write `/data/local/tmp/adj9_sign_in`: one or more `TASK` blocks
  (`KIND=session|click|attribution`, `SDK=android5.7.0`, then
  `key\x01value` lines for the wire map);
- launch the app (it signs; oracle fires once per process);
- read `/data/local/tmp/adj9_sign_out`: `AUTH <idx> <header>` per task.

The oracle appends `adj_verification`/algorithm itself, exactly like the app.

## Re-randomization: why a Python reimplementation cannot match

Confirmed empirically. Signing the **identical 48-param map twice** in one
process produced two different 192-byte blobs (188/192 bytes differ, different
16-byte headers). The 176-byte body re-randomizes on every call and even the
header is fresh per call. `nSign` ignores the Java-passed HMAC arg3 and
recomputes its own from the TEE `key2` (AndroidKeyStore alias `key2`,
HmacSHA256, hardware-backed). The 192-byte envelope is a per-call randomized
TEE attestation, not a deterministic function of the input — so the Python
`mint_blob` can never produce a byte-valid device signature. Only the real
device signer (driven here by the in-process oracle) can.

## Mechanics discovered to get the oracle running (device ZD2228MY3X)

1. **LSPosed CLI is unusable here**: no manager app installed, and
   `enable_cli` is a SharedPreferences-style key the daemon validates. Writing
   a hand-crafted `enable_cli` row into the `configs` table makes the daemon
   throw `StreamCorruptedException` at boot and crash-loop. **Do not write
   `configs` rows.**
2. **Module enable/scope via the DB works** (this is how the oracle got on):
   add a row to `modules` (`module_pkg_name='com.adj9oracle'`, current
   `apk_path`, `enabled=1`) and rows to `scope` (`com.penti.app`, `system`).
   Leave `configs` untouched. Stop the daemon, install the DB (drop
   `-wal`/`-shm`), reboot. The daemon loads the module at boot.
3. **Forcing a sign**: the SDK only signs when it builds a session. After
   `install_tracked`, a normal relaunch won't re-sign. Deleting
   `/data/data/com.penti.app/files/AdjustIoActivityState` makes the SDK send a
   fresh session on next foreground → `nSign` fires → oracle fires. (The Play
   referrer overlay `PlayCoreAcquisitionActivity` can loop on this tampered
   device and block the app; disabling `com.android.vending` for the launch
   lets the referrer fail fast. Re-enable Play afterward.)
4. **`sign()` reflection**: `XposedHelpers.findMethodExact` throws
   `NoSuchMethodError` on this Xposed build. Resolve `sign(Context,Map,Map,Map)`
   via `getDeclaredMethods()` + `setAccessible(true)` instead (this is the fix
   in `Hook.java` `chosenSign`).

## Files

- `adj9/module/src/com/adj9oracle/Hook.java` — the oracle (chosen-input signer
  `chosenSign`, reflection fix).
- `adj9/adj9_tool/oracle_ab.py` — the A/B driver (`--arm oracle|python`).
- `adj9/adj9_tool/oracle_ab_oracle.json`, `oracle_ab_python.json` — run results.

## Honest scope

- This proves non-organic **attribution** is gated solely by a valid device
  adj9 signature, on this one app/GAID/app-token, with the request replayed
  from the PC IP (the server accepted the PC-IP request; IP was not the gate).
- It does NOT recover the TEE key or the signing algorithm — those remain
  opaque; the oracle only drives the real signer. Producing fresh signatures
  requires the live device (as it does now, per-run).
