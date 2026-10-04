#!/usr/bin/env bash
# Build the adj9-oracle Xposed module APK.
set -e

JBR="C:/Program Files/Android/Android Studio/jbr/bin"
JAVAC="$JBR/javac.exe"
JAVA="$JBR/java.exe"
KEYTOOL="$JBR/keytool.exe"

BT="C:/Users/Apps/AppData/Local/Android/Sdk/build-tools/36.0.0"
AJ="C:/Users/Apps/AppData/Local/Android/Sdk/platforms/android-36/android.jar"
D8="$BT/lib/d8.jar"
APKSIGNER="$BT/lib/apksigner.jar"

M="C:/Users/Apps/Downloads/com.penti.app/adj9/module"
B="$M/build"

# keep debug.keystore across builds, otherwise the APK's signing key changes on
# every build and `adb install -r` fails with INSTALL_FAILED_UPDATE_INCOMPATIBLE
if [ -f "$B/debug.keystore" ]; then cp "$B/debug.keystore" /tmp/adj9debug.ks; fi
# NOTE: no rm -rf here (sandbox blocks bulk deletes). javac/d8/aapt2/zipalign all
# overwrite their outputs in place, which is safe because the source set is stable.
mkdir -p "$B/stubs" "$B/classes"
find "$B/stubs" "$B/classes" -name '*.class' -delete 2>/dev/null || true
if [ -f /tmp/adj9debug.ks ]; then cp /tmp/adj9debug.ks "$B/debug.keystore"; fi

echo "== [1/7] compile Xposed API stubs =="
find "$M/stub" -name '*.java' > "$B/stublist.txt"
"$JAVAC" -nowarn --release 17 -encoding UTF-8 -cp "$AJ" -d "$B/stubs" @"$B/stublist.txt"

echo "== [2/7] compile module =="
"$JAVAC" -nowarn --release 17 -encoding UTF-8 -cp "$AJ;$B/stubs" -d "$B/classes" \
    "$M/src/com/adj9oracle/Hook.java"

echo "== [3/7] dex =="
"$JAVA" -Xmx1024M -cp "$D8" com.android.tools.r8.D8 --lib "$AJ" --min-api 26 \
    --output "$B" "$B/classes"/com/adj9oracle/*.class
ls -la "$B/classes.dex"

echo "== [4/7] aapt2 compile res =="
"$BT/aapt2.exe" compile --dir "$M/res" -o "$B/res.zip"

echo "== [5/7] aapt2 link =="
"$BT/aapt2.exe" link -I "$AJ" --manifest "$M/AndroidManifest.xml" \
    -A "$M/assets" --min-sdk-version 26 --target-sdk-version 36 \
    --auto-add-overlay -o "$B/unsigned.apk" "$B/res.zip"

echo "== [6/7] inject classes.dex =="
C:/Python312/python.exe - "$B" <<'PY'
import sys, zipfile, shutil, os
b = sys.argv[1]
src = os.path.join(b, 'unsigned.apk')
tmp = os.path.join(b, 'withdex.apk')
shutil.copyfile(src, tmp)
with zipfile.ZipFile(tmp, 'a', zipfile.ZIP_DEFLATED) as z:
    z.write(os.path.join(b, 'classes.dex'), 'classes.dex')
print('dex injected')
PY

echo "== [7/7] zipalign + sign =="
"$BT/zipalign.exe" -f 4 "$B/withdex.apk" "$B/aligned.apk"
# only create the keystore once -- regenerating it changes the APK signing key
# and makes `adb install -r` fail with INSTALL_FAILED_UPDATE_INCOMPATIBLE
if [ ! -f "$B/debug.keystore" ]; then
"$KEYTOOL" -genkeypair -v -keystore "$B/debug.keystore" -alias androiddebugkey \
    -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android \
    -dname "CN=Android Debug,O=Android,C=US"
fi
"$JAVA" -jar "$APKSIGNER" sign --ks "$B/debug.keystore" --ks-pass pass:android \
    --key-pass pass:android --ks-key-alias androiddebugkey \
    --out "$B/adj9-oracle.apk" "$B/aligned.apk"

echo "== DONE =="
ls -la "$B/adj9-oracle.apk"
