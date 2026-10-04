r"""gaid_probe.py — where does the moto keep its advertising ID, and can root set it?

A fresh GAID is the enabler for the one test that matters: can a PYTHON-fired
tracker click earn a non-organic install? The moto's current record is already
attributed and sticky, so its own GAID can never show a new click. A new GAID =
new unattributed identity = the only way to see a Python click joined.

Probes (all read-only):
  * Settings.Secure/Global advertising_id
  * which GMS/GSF files contain the current GAID (d016e7e4)
  * GMS shared_prefs / databases inventory + any *adid* artefacts
  * the package that owns the value (uid) and its mode

Usage: python gaid_probe.py [grep-token]
"""
import subprocess
import sys

GAID = "d016e7e4-fb1c-4d0a-b619-db01f6a6a262"
GAID_ND = GAID.replace("-", "")
GMS = "/data/data/com.google.android.gms"
GSF = "/data/data/com.google.android.gsf"


def sh(cmd):
    r = subprocess.run(["adb", "shell", cmd], capture_output=True)
    return (r.stdout + r.stderr).decode("utf-8", "replace").strip()


def su(cmd):
    # base64 the command to survive every quoting layer
    import base64
    b = base64.b64encode(cmd.encode()).decode()
    inner = "echo %s | base64 -d | sh" % b
    b2 = base64.b64encode(inner.encode()).decode()
    return sh('/debug_ramdisk/su -c "echo %s | base64 -d | sh"' % b2)


def main():
    tok = sys.argv[1] if len(sys.argv) > 1 else "d016e7e4"
    print("--- identity ---")
    print(sh("getprop ro.product.model"), sh("id"))
    print("--- settings ---")
    for k in ("secure advertising_id", "global advertising_id",
              "secure limit_ad_tracking", "global limit_ad_tracking"):
        print("  %-28s = %r" % (k, su("settings get %s" % k)))
    print("--- files containing %s ---" % tok)
    print(su("grep -rl %s %s %s 2>/dev/null | head -30" % (tok, GMS, GSF)))
    print("--- files containing %s (no dashes) ---" % GAID_ND)
    print(su("grep -rl %s %s %s 2>/dev/null | head -30" % (GAID_ND, GMS, GSF)))
    print("--- gms shared_prefs ---")
    print(su("ls -l %s/shared_prefs/ 2>/dev/null | head -40" % GMS))
    print("--- gms files/databases (adid-ish) ---")
    print(su("ls -l %s/files/ %s/databases/ 2>/dev/null | grep -i -E 'ad|id' "
             "| head -30" % (GMS, GMS)))
    print("--- any *adid* artefact on data ---")
    print(su("find /data/data/com.google.android.gms /data/data/"
             "com.google.android.gsf -iname '*adid*' 2>/dev/null | head -20"))
    print("--- gservices.db adid-ish rows ---")
    print(su("for f in %s/databases/gservices.db; do echo $f; strings $f 2>/dev/null "
             "| grep -i -E '^(adid|ad_id|advertising)' | head -20; done" % GSF))


if __name__ == "__main__":
    main()