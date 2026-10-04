r"""crosscheck_device.py — shared device helpers for the offline crosscheck.

All adb goes through /debug_ramdisk/su with base64-wrapped commands (no
quoting layers). Binary-safe pulls via exec-out + base64.
"""
import base64
import subprocess

SERIAL = "ZD2228MY3X"
SU = "/debug_ramdisk/su"


def sh(args, timeout=60):
    r = subprocess.run(["adb", "-s", SERIAL] + args, capture_output=True,
                       timeout=timeout)
    return r.stdout, r.stderr, r.returncode


def su(cmd, timeout=60):
    """Run cmd on-device as root (base64-wrapped). Returns text."""
    b = base64.b64encode(cmd.encode()).decode()
    inner = 'echo %s | base64 -d | sh' % b
    b2 = base64.b64encode(inner.encode()).decode()
    out, err, rc = sh(["shell", '%s -c "echo %s | base64 -d | sh"' % (SU, b2)],
                      timeout=timeout)
    return (out + err).decode("utf-8", "replace")


def su_bin(cmd, timeout=120):
    """Run cmd on-device as root, return raw stdout (binary-safe exec-out)."""
    b = base64.b64encode(cmd.encode()).decode()
    out, err, rc = sh(["exec-out", "%s -c \"echo %s | base64 -d | base64\"" % (SU, b)],
                      timeout=timeout)
    return out


def su_pull(path, timeout=120):
    b = base64.b64encode(("base64 %s" % path).encode()).decode()
    out, err, rc = sh(["exec-out", "%s -c \"echo %s | base64 -d | sh | base64\"" % (SU, b)],
                      timeout=timeout)
    # layers: inner sh's `base64 file` output is itself base64'd again by the
    # trailing `| base64` -> decode twice
    d = out
    for _ in range(2):
        try:
            d = base64.b64decode(d)
        except Exception:
            break
    return d


if __name__ == "__main__":
    import sys
    print(su("id; grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/1/status /proc/self/status; "
             "getenforce; which su; ls -l /system/bin/su 2>&1 | head -2"))
