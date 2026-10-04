r"""gaid_set.py — read / set the moto's advertising ID (root).

The GAID lives in /data/data/com.google.android.gms/shared_prefs/adid_settings.xml
(found by grepping the live value in gaid_probe.py). A fresh GAID = a fresh,
unattributed Adjust identity, which is the only way to test whether a
PYTHON-fired tracker click earns a non-organic install (the moto's own record is
already attributed and sticky).

Usage:
  python gaid_set.py read
  python gaid_set.py set 11111111-2222-4333-8444-555555555555
All adb work goes through su with base64-wrapped commands (no quoting layers).
"""
import base64
import re
import subprocess
import sys
import uuid

XML = "/data/data/com.google.android.gms/shared_prefs/adid_settings.xml"
APP = "com.penti.app"
GMS = "com.google.android.gms"


def sh(cmd):
    r = subprocess.run(["adb", "shell", cmd], capture_output=True)
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def su(cmd):
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return sh('/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2)


def read_xml():
    return su("cat %s" % XML)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "read"
    if mode == "read":
        print("=== %s ===" % XML)
        print(read_xml())
        print("=== stat ===")
        print(su("ls -l %s" % XML))
        return
    if mode != "set":
        raise SystemExit("usage: gaid_set.py read|set <uuid>")
    new = sys.argv[2] if len(sys.argv) > 2 else str(uuid.uuid4())
    cur = read_xml()
    old = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cur)
    old = old.group(0) if old else None
    print("current GAID: %s" % old)
    print("new GAID    : %s" % new)
    if old is None:
        raise SystemExit("no GAID found in %s" % XML)
    patch = cur.replace(old, new)
    # write via base64 (file is small, 660 root-owned by u0_a207)
    b64 = base64.b64encode(patch.encode()).decode()
    su("cp %s /data/local/tmp/adid_settings.xml.bak" % XML)
    print(su("echo %s | base64 -d > /data/local/tmp/adid_new.xml" % b64))
    print(su("cat /data/local/tmp/adid_new.xml > %s" % XML))
    print(su("ls -l %s /data/local/tmp/adid_new.xml" % XML))
    print("--- verify ---")
    print(read_xml())
    print("--- restart GMS + app so the new value is read ---")
    print(su("am force-stop %s; am force-stop %s" % (GMS, APP)))
    print("backup kept at /data/local/tmp/adid_settings.xml.bak")


if __name__ == "__main__":
    main()