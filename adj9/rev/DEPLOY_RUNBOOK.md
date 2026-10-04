# ADJ9 oracle LSPosed module: build, deploy, activate, and reboot runbook

Reconnaissance date: 2026-09-24. Device: `moto g42`, serial `ZD2228MY3X`. The commands below are written for the workspace's **Git Bash** shell. Every `adb` command is prefixed with `MSYS_NO_PATHCONV=1` so Git Bash does not rewrite Android paths.

> Safety: reconnaissance on 2026-09-24 was read-only. The write/install/reboot commands below were intentionally not run. Run them only when redeploying is intended.

## 1. Exact module tree

Module root:

- Windows: `C:\Users\Apps\Downloads\com.penti.app\adj9\module`
- Git Bash: `/c/Users/Apps/Downloads/com.penti.app/adj9/module`

Files that define/build the module:

- Hook: `C:\Users\Apps\Downloads\com.penti.app\adj9\module\src\com\adj9oracle\Hook.java`
- Manifest: `C:\Users\Apps\Downloads\com.penti.app\adj9\module\AndroidManifest.xml`
- Xposed entry point: `C:\Users\Apps\Downloads\com.penti.app\adj9\module\assets\xposed_init` (`com.adj9oracle.Hook`)
- Default scope: `C:\Users\Apps\Downloads\com.penti.app\adj9\module\res\values\arrays.xml` (`com.penti.app`)
- Build script: `C:\Users\Apps\Downloads\com.penti.app\adj9\module\build.sh`
- Compile-only Xposed API stubs: `C:\Users\Apps\Downloads\com.penti.app\adj9\module\stub\de\robv\android\xposed\`

This is **not a Gradle project**. There is no `build.gradle`, `settings.gradle`, `gradlew`, `gradlew.bat`, Android `CMakeLists.txt`, Android `Android.mk`, JNI directory, or module native source. The checked-in stubs are Java-only and are deliberately excluded from the APK dex.

### Build dependencies hard-coded by `build.sh`

- Android Studio JBR: `C:\Program Files\Android\Android Studio\jbr\bin\{java,javac,keytool}.exe`
- Android SDK platform: `C:\Users\Apps\AppData\Local\Android\Sdk\platforms\android-36\android.jar`
- Build tools: `C:\Users\Apps\AppData\Local\Android\Sdk\build-tools\36.0.0\`
- `d8`: `C:\Users\Apps\AppData\Local\Android\Sdk\build-tools\36.0.0\lib\d8.jar`
- `apksigner`: `C:\Users\Apps\AppData\Local\Android\Sdk\build-tools\36.0.0\lib\apksigner.jar`
- ZIP/dex injection helper: `C:\Python312\python.exe`

The normal PATH Java is old Java 8, but the script explicitly invokes Android Studio's JBR, so that does not affect this build.

## 2. Existing signed APKs and validated build command

Build from any Git Bash directory with:

```bash
bash C:/Users/Apps/Downloads/com.penti.app/adj9/module/build.sh
```

The script compiles the stubs, compiles `Hook.java` with `--release 17`, dexes it, links resources, injects `classes.dex`, aligns, and signs the APK. It preserves:

- `C:\Users\Apps\Downloads\com.penti.app\adj9\module\build\debug.keystore`

Do **not** delete that keystore. A replacement key makes `adb install -r` fail with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`.

Current prebuilt outputs:

- Final APK: `C:\Users\Apps\Downloads\com.penti.app\adj9\module\build\adj9-oracle.apk`
- Intermediate APKs: `unsigned.apk`, `withdex.apk`, and `aligned.apk` in the same directory
- Signing sidecar: `adj9-oracle.apk.idsig`

At reconnaissance time, the final APK was last modified **2026-09-24 20:23:53 +0530**, size 37,331 bytes, SHA-256:

```text
f54e854f6cc983a26568d9be4403a53a98ad6a067d272847556c24c582579346
```

The installed module had the same SHA-256 and was updated at 2026-09-24 20:24, proving the current build script and artifact were used successfully.

Optional post-build verification:

```bash
"C:/Program Files/Android/Android Studio/jbr/bin/java.exe" \
  -jar "C:/Users/Apps/AppData/Local/Android/Sdk/build-tools/36.0.0/lib/apksigner.jar" \
  verify --verbose --print-certs \
  C:/Users/Apps/Downloads/com.penti.app/adj9/module/build/adj9-oracle.apk

sha256sum C:/Users/Apps/Downloads/com.penti.app/adj9/module/build/adj9-oracle.apk
```

## 3. Current live installation and activation state

Current installed APK path observed on 2026-09-24:

```text
/data/app/~~toUYy0Hh0G-RBvUPN81jeA==/com.adj9oracle-2Q3acq9AWFivIo4Z9BGv3w==/base.apk
```

Do not hard-code this path for the next rebuild. Android may generate a new `/data/app/~~.../com.adj9oracle-.../base.apk` directory. Query it after every install.

Root is available only through:

```text
/debug_ramdisk/su
```

The live framework is LSPosed, not Vector:

- `/data/adb/modules/zygisk_lsposed`: enabled (no `disable` file)
- `/data/adb/modules/zygisk_vector`: disabled
- Process `lspd`: running

There is no installed LSPosed manager, and `/data/adb/lspd/cli` is not usable for reliable module activation on this setup. Prior attempts to manufacture `configs.enable_cli` caused `StreamCorruptedException`/crash-loop behavior. Leave the `configs` table untouched.

LSPosed database:

```text
/data/adb/lspd/config/modules_config.db
/data/adb/lspd/config/modules_config.db-wal
/data/adb/lspd/config/modules_config.db-shm
```

Current database state copied read-only on 2026-09-24:

```text
modules: mid=59, package=com.adj9oracle, enabled=1, automatic_add=0
scope:   (59, 'com.penti.app', 0)
scope:   (59, 'system', 0)
```

Current DB ownership/mode/context:

```text
root:root  0600  u:object_r:system_file:s0
```

### Why the DB repair is required after reinstall

`adb install -r` may change the randomized installed APK path. The historical notes also observed LSPosed registering a replacement row/new `mid` with `enabled=0` and dropping the scope. A live LSPosed daemon can overwrite direct file edits from its in-memory state. The reliable sequence is therefore:

1. Install the new APK and query its new path.
2. Stop LSPosed by disabling `zygisk_lsposed` and rebooting.
3. Edit the DB while LSPosed is offline.
4. Make the edited DB self-contained, install it with the correct owner/mode/SELinux label, and remove stale WAL/SHM files.
5. Re-enable `zygisk_lsposed` and reboot.
6. Verify LSPosed logs the exact new APK path.

Workspace DB helper:

- `C:\Users\Apps\Downloads\com.penti.app\adj9\device\enable.sh`

That script searches for an on-device `sqlite3` binary, but none is currently installed. The host-Python procedure below is therefore the executable path to use.

## 4. Exact deployment runbook

### 4.1 Define paths and check the device

```bash
export SERIAL=ZD2228MY3X
export MODULE_APK='C:/Users/Apps/Downloads/com.penti.app/adj9/module/build/adj9-oracle.apk'
export WORK='C:/Users/Apps/Downloads/com.penti.app/adj9/rev/lspd-stage'

MSYS_NO_PATHCONV=1 adb -s "$SERIAL" get-state
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell /debug_ramdisk/su -c id
```

### 4.2 Build the new APK

```bash
bash C:/Users/Apps/Downloads/com.penti.app/adj9/module/build.sh
sha256sum "$MODULE_APK"
```

Do not proceed if compilation/signing fails.

### 4.3 Install with the preserved signing key

```bash
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" install -r "$MODULE_APK"
```

Do not uninstall `com.adj9oracle` as a workaround for `INSTALL_FAILED_UPDATE_INCOMPATIBLE`; restoring the existing `debug.keystore` is the correct fix.

Query the actual installed path and save it for the DB edit:

```bash
APK=$(MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell "/debug_ramdisk/su -c 'pm path com.adj9oracle'" | tr -d '\r' | sed -n 's/^package://p')
printf 'APK=%s\n' "$APK"
test -n "$APK"
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell "/debug_ramdisk/su -c 'test -f \"$APK\" && sha256sum \"$APK\"'"
```

### 4.4 Stop LSPosed completely

```bash
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'touch /data/adb/modules/zygisk_lsposed/disable; reboot'"

MSYS_NO_PATHCONV=1 adb -s "$SERIAL" wait-for-device
while [ "$(MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell getprop sys.boot_completed | tr -d '\r')" != "1" ]; do sleep 2; done
sleep 5

# Must print no PID.
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell pidof lspd
```

If `lspd` is still running, do not edit the DB; resolve that first.

### 4.5 Pull DB + WAL/SHM to a host staging directory

```bash
rm -rf "$WORK"
mkdir -p "$WORK"

MSYS_NO_PATHCONV=1 adb -s "$SERIAL" exec-out /debug_ramdisk/su -c \
  'cat /data/adb/lspd/config/modules_config.db' > "$WORK/modules_config.db"

# Copy these too if present; the current database normally has both.
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" exec-out /debug_ramdisk/su -c \
  'cat /data/adb/lspd/config/modules_config.db-wal' > "$WORK/modules_config.db-wal" || true
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" exec-out /debug_ramdisk/su -c \
  'cat /data/adb/lspd/config/modules_config.db-shm' > "$WORK/modules_config.db-shm" || true
```

### 4.6 Repair `apk_path`, `enabled`, and scope while LSPosed is offline

Pass the queried path into Python as `ADJ9_APK_PATH`; this avoids quoting problems in the device path:

```bash
export ADJ9_APK_PATH="$APK"

C:/Python312/python.exe - "$WORK/modules_config.db" <<'PY'
import os
import sqlite3
import sys

db_path = sys.argv[1]
apk_path = os.environ["ADJ9_APK_PATH"]
conn = sqlite3.connect(db_path)
conn.execute("PRAGMA foreign_keys=ON")
conn.execute("BEGIN IMMEDIATE")
conn.execute(
    """INSERT INTO modules(module_pkg_name, apk_path, enabled, automatic_add)
       VALUES('com.adj9oracle', ?, 1, 0)
       ON CONFLICT(module_pkg_name) DO UPDATE SET
         apk_path=excluded.apk_path,
         enabled=1,
         automatic_add=0""",
    (apk_path,),
)
mid = conn.execute(
    "SELECT mid FROM modules WHERE module_pkg_name='com.adj9oracle'"
).fetchone()[0]
conn.execute(
    "DELETE FROM scope WHERE mid=? AND app_pkg_name IN ('com.penti.app','system')",
    (mid,),
)
conn.executemany(
    "INSERT INTO scope(mid,app_pkg_name,user_id) VALUES(?,?,0)",
    [(mid, "com.penti.app"), (mid, "system")],
)
conn.commit()

# Fold any pulled WAL content into the main DB and make the file self-contained.
conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
conn.execute("PRAGMA journal_mode=DELETE")
conn.commit()
conn.close()

for suffix in ("-wal", "-shm"):
    try:
        os.remove(db_path + suffix)
    except FileNotFoundError:
        pass

check = sqlite3.connect(db_path)
print("module:", check.execute(
    "SELECT mid,module_pkg_name,apk_path,enabled,automatic_add "
    "FROM modules WHERE module_pkg_name='com.adj9oracle'"
).fetchall())
print("scope:", check.execute(
    "SELECT * FROM scope WHERE mid=(SELECT mid FROM modules "
    "WHERE module_pkg_name='com.adj9oracle') ORDER BY app_pkg_name"
).fetchall())
check.close()
PY
```

The important repair is `modules.apk_path = $APK` and `modules.enabled = 1`; the two scope rows ensure the hook is injected into Penti and loaded into the framework path used by this setup.

### 4.7 Install the repaired DB and remove stale sidecars

Stage it through `/data/local/tmp`, because direct `adb push` to the protected LSPosed config directory may fail:

```bash
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" push \
  "$WORK/modules_config.db" /data/local/tmp/modules_config.db.adj9-new

MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'set -e; cp /data/local/tmp/modules_config.db.adj9-new /data/adb/lspd/config/modules_config.db; rm -f /data/adb/lspd/config/modules_config.db-wal /data/adb/lspd/config/modules_config.db-shm; chown 0:0 /data/adb/lspd/config/modules_config.db; chmod 600 /data/adb/lspd/config/modules_config.db; restorecon /data/adb/lspd/config/modules_config.db; rm -f /data/local/tmp/modules_config.db.adj9-new'"

MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'ls -lZ /data/adb/lspd/config/modules_config.db; test ! -e /data/adb/lspd/config/modules_config.db-wal; test ! -e /data/adb/lspd/config/modules_config.db-shm'"
```

Older notes say `chmod 660`, but the live LSPosed-created DB is currently `0600`; preserve the live daemon's actual mode.

### 4.8 Re-enable LSPosed and reboot

```bash
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'rm -f /data/adb/modules/zygisk_lsposed/disable; test -e /data/adb/modules/zygisk_vector/disable; reboot'"

MSYS_NO_PATHCONV=1 adb -s "$SERIAL" wait-for-device
while [ "$(MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell getprop sys.boot_completed | tr -d '\r')" != "1" ]; do sleep 2; done
sleep 20
```

The `test -e /data/adb/modules/zygisk_vector/disable` deliberately refuses the reboot if the broken Vector framework is still enabled. If that check fails, enable Vector only by explicitly creating its `disable` marker; do not remove LSPosed's `disable` marker.

### 4.9 Verify the NEW APK is the one loaded

```bash
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell pidof lspd
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'grep -RIna \"Loading legacy module com.adj9oracle from $APK\" /data/adb/lspd/log/ | tail -5'"

MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'ls -lZ /data/adb/lspd/log/modules_*.log | tail -3'"
```

A successful launch later must show both `Loading legacy module com.adj9oracle from <new path>` and `Loading class com.adj9oracle.Hook` in the newest `/data/adb/lspd/log/modules_*.log`.

## 5. How signing is triggered

### In-process threads, not a separate process

Both named workers are Java threads inside the injected `com.penti.app` process:

- `adj9-oracle`: one-shot re-sign diagnostic started after the first real `NativeLibHelper.a(...)` returns. It makes repeated/diagnostic calls and writes probe records.
- `adj9-chosen-sign`: the production chosen-input signer. It is also started once per process after the first genuine `nSign` result, then calls the app's captured real `Signer.sign(Context,Map,Map,Map)` singleton on caller-supplied tasks.

There is no adb broadcast and no standalone `adj9-oracle` OS process. A genuine Adjust signing event must occur first so the native library/TEE key is warm and `sLastSigner` has been captured. The chosen-input thread waits 1.4 seconds, then waits up to 8 seconds for the captured signer.

### Exact file paths on device

- Control input: `/data/local/tmp/adj9_sign_in`
- Signature output: `/data/local/tmp/adj9_sign_out`
- Primary oracle log: `/data/data/com.penti.app/files/adj9_capture.log`
- Fallback oracle log: `/data/local/tmp/adj9_capture.log`

`openOutput()` tries the app-private path first and falls back to `/data/local/tmp` only if the first path cannot be opened. On the live device, the private file was 14,496,860 bytes and current. The `SIGN_OUT` rows have this form:

```text
AUTH <idx> Signature signature="...",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="..."
```

Logcat/Xposed tag:

```text
ADJ9ORA
```

### Control-file format

Write `/data/local/tmp/adj9_sign_in` **before** launching/forcing a fresh signing. One or more blocks:

```text
TASK
KIND=session
SDK=android5.7.0
<param_key><U+0001><param_value>
<param_key><U+0001><param_value>

TASK
KIND=click
SDK=android5.7.0
...
```

Keys and values are separated by one literal U+0001 byte. `KIND` and `SDK` are parsed specially; every other U+0001 line is inserted into the activity map. The SDK itself appends `adj_verification` and algorithm metadata.

### Manual trigger sequence (for later use)

```bash
export CONTROL='C:/Users/Apps/Downloads/com.penti.app/adj9/adj9_tool/_ctrl2.tmp'
# First create $CONTROL with TASK blocks, then:
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" push "$CONTROL" /data/local/tmp/adj9_sign_in
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'chmod 666 /data/local/tmp/adj9_sign_in; : > /data/local/tmp/adj9_sign_out; chmod 666 /data/local/tmp/adj9_sign_out; am force-stop com.penti.app; rm -f /data/data/com.penti.app/files/AdjustIoActivityState'"
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  monkey -p com.penti.app -c android.intent.category.LAUNCHER 1
sleep 15
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'cat /data/local/tmp/adj9_sign_out'"
```

Deleting `/data/data/com.penti.app/files/AdjustIoActivityState` forces Adjust to treat the next foreground launch as a new session. A normal relaunch within the session interval may not sign at all.

### Existing drivers

- Corrected decisive A/B driver: `C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool\oracle_ab2.py`
- Earlier driver: `C:\Users\Apps\Downloads\com.penti.app\adj9\adj9_tool\oracle_ab.py`
- Organic-install/device-state driver: `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\farm_win.py`

`oracle_ab2.py --arm oracle` performs the control push, clears output, force-stops Penti, deletes `AdjustIoActivityState`, launches through `monkey`, polls `adj9_sign_out`, and performs the network A/B. The exact driver command is:

```bash
C:/Python312/python.exe C:/Users/Apps/Downloads/com.penti.app/adj9/adj9_tool/oracle_ab2.py --arm oracle
```

`farm_win.py` is not the chosen-input protocol driver: it wipes Adjust state, relaunches, and reads attribution. It triggers a genuine sign but does not create `adj9_sign_in` itself.

Read the passive log with:

```bash
MSYS_NO_PATHCONV=1 adb -s "$SERIAL" shell \
  "/debug_ramdisk/su -c 'tail -200 /data/data/com.penti.app/files/adj9_capture.log'"

MSYS_NO_PATHCONV=1 adb -s "$SERIAL" logcat -d -s ADJ9ORA
```

## 6. Existing notes/scripts that document this plumbing

Most relevant local sources:

- `C:\Users\Apps\Downloads\com.penti.app\adj9\README.md` (build/install/reboot recipe)
- `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\SIGNING_PIPELINE.md` (DB repair and fresh-session requirements)
- `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\ORACLE_SIGN_HANDOFF.md` (control/output protocol)
- `C:\Users\Apps\Downloads\com.penti.app\adj9\rev\SIGNATURE_IS_THE_GATE_CONFIRMED.md` (live DB/scope and forcing a sign)
- `C:\Users\Apps\Downloads\com.penti.app\adj9\STATUS.md` (LSPosed active, Vector disabled, log path)
- `C:\Users\Apps\.workbuddy-ai\memory\2026-09-09.md` (original module build/deploy history)
- `C:\Users\Apps\Downloads\com.penti.app\adj9\device\enable.sh` (on-device SQL intent, but unusable without `sqlite3`)
- `C:\Users\Apps\Downloads\com.penti.app\adj9\device\read_lsposed.py` and `check_scope.py` (local DB inspection examples; stale hard-coded DB names/mid)
