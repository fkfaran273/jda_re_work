# Wall A - slice 93: the signing pipeline solved end-to-end (2026-09-16)
## 0a. ACCURACY CORRECTION (2026-09-16, final review)
The §1 pipeline map is observed (dex + live capture). The §3 "closure" —
"nothing is missing, the 33-byte delta is TEE-held key2" — is a HYPOTHESIS:
mint3's failure has alternative explanations (any byte difference in the
package, canonical mismatch, timing/velocity checks), and the server-side
mechanism was never established. The maker's 48/48 result applies to the
captured test cases only, NOT to signing arbitrary requests.


Follows slice 92. Goal: find the "missing calculation" that lets the APK signer
produce verifiable packages while our maker cannot. Result: there is none —
the pipeline is now mapped 100%, and the missing piece is a **non-exportable
per-install key**, not a computable step.

## 1. The complete signing pipeline (from dex + live capture)

```
LinkedHashMap params (22 fields, insertion-ordered)
  └─ u2.a: map + "client_sdk"="android5.7.0" + "adj_verification"=o3.a()
       └─ d3.a(toString) -> UTF-8  = THE CANONICAL MESSAGE (captured live, 1360B)
            └─ t1.a(ctx, msg) = Mac("HmacSHA256").doFinal(msg)
                 key = "key2", KeyGenerator("HmacSHA256","AndroidKeyStore")
                 → AndroidKeyStore / StrongBox TEE — NON-EXPORTABLE
            └─ nSign(ctx, map, H, 1500000) -> 192B blob (our 48/48 VM)
```

- `o3.a()` (adj_verification) = `b64(XOR19(json{"os_name":"android"}))`,
  XOR key **`Quoh8uafohgh7CahM2h`** (s2.a, classes3.dex).
  **Reproduced byte-exact**: `KlcAG2cbAAsKSl1KVi0FGiJbDHMI` (decode_adjv.py).
- The genuine `/attribution` query carries NO adj_verification/client_sdk —
  u2 injects them into the signed map only (genuine_attr_raw_query.txt).
- `encrypted_key` (prefs `adjust_keys`) is deleted by t1.a(ctx) on key reset —
  a key-distribution artifact, consistent with the server holding per-install
  key material registered at first session.

## 2. Anti-hook guard (why attaches kept dying)

Kills young processes on ptrace: spawn + early attach die
("unable to perform ptrace pokedata"); **aged attach (>~25s) works**.
Guard also uses poisoned-pointer SIGSEGV + native exit/kill/tgkill +
java System.exit/Runtime.exit/killProcess — all blocked in
`rev/agent/main.js` (Phase 0/2 + killguard; frida 17 syntax fixed).
Working stack: `fs17root`/`frs64` + client 16.7.19 (workbuddy python)
or 17.17.0 (C:\Python314) — **major versions must match the server binary**.

## 3. Why the TEE mint cannot beat the server (model closure)

mint3 (device-signed package with OUR canonical) still changes bytes
(new timestamps/H over new message) → the server's stored-package match
fails → silent Organic (slice 92's rule). The only verifiable packages are
the app's own sends; the only offline read is verbatim replay (fresh_ab 3/3).
**Nothing is missing from the maker — 48/48 computable steps are exact;
the 33-byte delta is TEE-held key2 state.**

## 4. tee_install run post-mortem (Phase A/B/D)

A: fresh GAID 686b80bf…, click 302, reftag c9LjYm8Ua44vw (cline_tee1) — OK.
B: net-blocked signing captured; D: sent via Python (proxy 8888) — session
booked **Organic**. Root cause (measured): `grep -c 686b80bf ActivityState = 0`
— the app never presented that GAID (GMS propagation race: set → force-stop →
read happened before GMS committed; farm_win's readback-verified set is the
fix). **Farm lesson: always verify the GAID readback AND that the app's
ActivityState carries the same GAID before trusting a run.**

## 5. Standing results (unchanged, re-proven today)

- farm_win B: **NON-ORGANIC 24lp4oje** (VKM, creative=cline_fw_b joined,
  eng 04:42:20Z, inst 04:42:27Z) — the 8th win of the campaign.
- Recipe: fresh GAID (readback-verified) → Python click (idfa+gps_adid) →
  wipe+relaunch → app signs → verdict from device/MITM/verbatim-replay.
