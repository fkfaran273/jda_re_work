#!/usr/bin/env bash
set -e
JBR="C:/Program Files/Android/Android Studio/jbr/bin"
JAVAC="$JBR/javac.exe"
JAVA="$JBR/java.exe"
KEYTOOL="$JBR/keytool.exe"
BT="C:/Users/Apps/AppData/Local/Android/Sdk/build-tools/36.0.0"
AJ="C:/Users/Apps/AppData/Local/Android/Sdk/platforms/android-36/android.jar"
D8="$BT/lib/d8.jar"
APKSIGNER="$BT/lib/apksigner.jar"
M="C:/Users/Apps/Downloads/com.penti.app/reverify/oracle/module"
B="$M/build"
if [ -f "C:/Users/Apps/Downloads/com.penti.app/adj8/module/build/debug.keystore" ]; then
  cp "C:/Users/Apps/Downloads/com.penti.app/adj8/module/build/debug.keystore" "$B/debug.keystore" 2>/dev/null || true
fi
mkdir -p "$B/stubs" "$B/classes"
find "$B/stubs" "$B/classes" -name '*.class' -delete 2>/dev/null || true
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
python - "$B" <<'PY'
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
if [ ! -f "$B/debug.keystore" ]; then
"$KEYTOOL" -genkeypair -v -keystore "$B/debug.keystore" -alias androiddebugkey \
    -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android \
    -dname "CN=Android Debug,O=Android,C=US"
fi
"$JAVA" -jar "$APKSIGNER" sign --ks "$B/debug.keystore" --ks-pass pass:android \
    --key-pass pass:android --ks-key-alias androiddebugkey \
    --out "$B/adj7-rv-oracle.apk" "$B/aligned.apk"
echo "== DONE =="
ls -la "$B/adj7-rv-oracle.apk"
