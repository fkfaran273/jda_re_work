r"""dev_state.py — read the phone's live Adjust state (no writes).

Reads, via /debug_ramdisk/su (base64 to survive binary):
  files/AdjustIoActivityState        -> android_uuid (auid), sessionCount,
                                        lastActivity/lastInterval
  files/AdjustAttribution            -> the verdict the SDK last stored
  shared_prefs/adjust_preferences.xml
  files/adj9_capture.log             -> oracle capture if present
and greps the last Adjust logcat lines.

Usage: python dev_state.py
"""
import base64
import re
import subprocess
import sys

PKG = "/data/data/com.penti.app"
FILES = ["files/AdjustIoActivityState", "files/AdjustAttribution",
         "shared_prefs/adjust_preferences.xml", "files/adj9_capture.log"]


def sh(cmd):
    r = subprocess.run(["adb", "shell", '/debug_ramdisk/su -c "%s"' % cmd],
                       capture_output=True)
    return r.stdout


def sh_b64(cmd):
    r = subprocess.run(
        ["adb", "shell", '/debug_ramdisk/su -c "%s | base64"' % cmd],
        capture_output=True)
    try:
        return base64.b64decode(r.stdout)
    except Exception:
        return b""


def strings(d, n=4):
    return [m.group(0).decode("ascii", "replace")
            for m in re.finditer(rb"[ -~]{%d,}" % n, d)]


def main():
    print("--- adb devices ---")
    print(subprocess.run(["adb", "devices"], capture_output=True)
          .stdout.decode().strip())
    for f in FILES:
        d = sh_b64("cat %s/%s" % (PKG, f))
        print("\n=== %s (%d B) ===" % (f, len(d)))
        if not d:
            print("   (empty / not readable)")
            continue
        for s in strings(d)[:60]:
            print("   ", s[:160])
        for pat in (rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    rb"24pxw9rl", rb"24ibsv01", rb"wy7261z", rb"Organic",
                    rb"VKM Digital"):
            hits = set(re.findall(pat, d))
            if hits:
                print("    [%s] %s" % (pat.decode(),
                                       [h.decode() for h in list(hits)[:6]]))
    print("\n--- last Adjust logcat lines ---")
    out = subprocess.run(["adb", "logcat", "-d", "-t", "400"],
                         capture_output=True).stdout.decode("utf-8", "replace")
    for ln in out.splitlines():
        if re.search(r"Adjust|attribution", ln, re.I):
            print("   ", ln[:200])
    print("\n--- pid / process ---")
    print(sh("pidof com.penti.app").decode().strip())


if __name__ == "__main__":
    main()