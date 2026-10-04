# adj9oracle — chosen-input signer (ready to run)

## What this is
The in-process LSPosed oracle (`adj9/module/src/com/adj9oracle/Hook.java`), extended
this session with a **chosen-input signer**. It calls the app's OWN initialized
`Signer.sign(ctx, activity, globals, outMap)` singleton (captured as `sLastSigner`)
over caller-supplied params, producing a **real, TEE-signed `Authorization`**.
This runs inside the app (no frida), so the app's anti-tamper — which neuters
frida-server — never triggers.

Status: **built (`adj9-oracle.apk`) and installed (`com.adj9oracle`)**. One manual
step remains (enable it in LSPosed — see below). Everything else is ready.

## Why the earlier frida path was dead
frida-server attach to `com.penti.app` fails with `PermissionDeniedError: unable
to access process` (the app hides itself) or spawn `InvocationTargetException`.
All `device/oracle_att*.log` / `oracle_val_err.log` show this. The in-process
oracle is the only working path.

## Enable (one manual step — LSPosed daemon owns its DB)
The LSPosed zygisk daemon keeps `modules_config.db` in memory and overwrites
manual file edits on reboot, so the module must be enabled through the manager:
1. Open the **LSPosed manager** → Modules.
2. Enable **adj9oracle** (`com.adj9oracle`) and set its scope to **com.penti.app**.
3. Force-stop / relaunch `com.penti.app` (LSPosed injects at process fork).

(Alternative: repurpose `gadget_loader` — it is currently scoped to
`com.turkcell.paycell` and both gadget modules are disabled.)

## Use
1. Write the control file **`/data/local/tmp/adj9_sign_in`** BEFORE launching the
   app. Format: one or more `TASK` blocks; within a block, `KIND=`, `SDK=`, then
   one activity-map entry per line as `<key>\x01<value>` (`\x01` = U+0001). The
   SDK appends `adj_verification`/`algorithm` itself.
2. Launch `com.penti.app` (its first genuine sign warms the SDK, then the oracle
   fires once, signs every TASK, ~1.4s later).
3. Read **`/data/local/tmp/adj9_sign_out`**: lines `AUTH <idx> <authorization>`.
4. For the decisive A/B, POST each signed request (session → sdk_click →
   attribution) and poll the verdict. Expect the oracle-signed identity to go
   NON-ORGANIC while the Python-signed one is ORGANIC — confirming the signature
   is the sole gate.

Capture log (passive oracle + chosen-signer records): `/data/local/tmp/adj9_capture.log`
(or the app-private copy). Chosen-signer records use tags `sign_task`, `sign_done`,
`sign_err` / `sign_skip`.
