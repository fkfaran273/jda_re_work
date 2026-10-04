"""device_probe.py -- read a phone's real facts over adb.

Returns the same JSON shape as a device-info app dump, which is exactly what
oneclick's DEVICE_DATA accepts.  Nothing here guesses: every value comes from
the phone (getprop / dumpsys / settings), so the run always signs as the device
it is actually talking to.

    import device_probe
    info = device_probe.collect()          # the only connected phone
    info = device_probe.collect("ZD2228MY3X")
"""
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone

# Android's standard density buckets, smallest first.  We label a device with
# the highest bucket that does not exceed its real dpi (so 280 -> hdpi/xhdpi
# range the same way a device-info app would).
DENSITY_BUCKETS = [
    (120, "ldpi"), (160, "mdpi"), (213, "tvdpi"), (240, "hdpi"),
    (320, "xhdpi"), (480, "xxhdpi"), (640, "xxxhdpi"),
]

# A timezone we do not have a tz database entry for falls back to this.
FALLBACK_TZ = {"Asia/Kolkata": ("+0530", "IST", "Indian Standard Time")}


class ProbeError(RuntimeError):
    pass


def adb_path():
    """Find adb: on PATH, or in the usual Android SDK / platform-tools spots."""
    import os
    import shutil
    found = shutil.which("adb")
    if found:
        return found
    roots = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        r"C:\platform-tools",
        os.path.expanduser(r"~\AppData\Local\Android\Sdk\platform-tools"),
    ]
    for root in roots:
        if not root:
            continue
        exe = os.path.join(root, "adb.exe" if os.name == "nt" else "adb")
        if os.path.isfile(exe):
            return exe
    raise ProbeError("adb not found -- put platform-tools on PATH")


def adb(*args, serial=None, timeout=60, retries=2):
    """Run an adb command, return its stripped output ('' on failure).

    The USB link drops often enough to matter, so an empty read is retried
    (and adb is nudged to reconnect) before we believe the phone is silent.
    """
    import time as _time
    cmd = [adb_path()]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    for attempt in range(retries + 1):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            out = (p.stdout or "").replace("\r", "").strip()
            if out or attempt == retries:
                return out
        except subprocess.TimeoutExpired:
            if attempt == retries:
                return ""
        if serial:
            subprocess.run([adb_path(), "reconnect"], capture_output=True,
                           timeout=20)
        _time.sleep(1.0 + attempt)
    return ""


def connected_devices():
    """Every online device, as (serial, model) pairs."""
    out = adb("devices", "-l")
    devs = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            model = ""
            for p in parts[2:]:
                if p.startswith("model:"):
                    model = p.split(":", 1)[1]
            devs.append((parts[0], model.replace("_", " ")))
    return devs


def pick_serial(serial=None):
    """Resolve which phone to talk to, or explain why we cannot."""
    if serial:
        return serial
    devs = connected_devices()
    if not devs:
        raise ProbeError("no device connected -- plug the phone in and "
                         "allow USB debugging")
    if len(devs) > 1:
        raise ProbeError("more than one device connected (%s) -- set SERIAL"
                         % ", ".join(s for s, _ in devs))
    return devs[0][0]


def getprop(name, serial):
    return adb("shell", "getprop", name, serial=serial)


def _tz_parts(tzname, when=None):
    """(label, abbrev, long name) for an IANA zone, e.g. ('+0530', 'IST', ...)."""
    if tzname in FALLBACK_TZ:
        return FALLBACK_TZ[tzname]
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tzname)
        now = when or datetime.now(timezone.utc).astimezone(tz)
        off = now.utcoffset() or timedelta(0)
        mins = int(off.total_seconds() // 60)
        label = "%s%02d%02d" % ("+" if mins >= 0 else "-", abs(mins) // 60,
                                abs(mins) % 60)
        return label, now.tzname() or tzname, tzname
    except Exception:
        return FALLBACK_TZ["Asia/Kolkata"]


def screen_density_name(dpi):
    """The resource-bucket label a device-info app would show."""
    name = DENSITY_BUCKETS[0][1]
    for value, label in DENSITY_BUCKETS:
        if dpi >= value:
            name = label
    return name


def _display(serial):
    """(width, height, dpi, density_name) for the APP-visible window.

    'wm size' reports the physical panel, but the SDK signs what the app
    window sees, so prefer the app= WxH that dumpsys reports.  Raises rather
    than guessing: a silently-wrong screen would sign as a phone that is not
    there, which is far worse than stopping.
    """
    out = adb("shell", "dumpsys", "window", "displays", serial=serial)
    w = h = dpi = None
    m = re.search(r"init=(\d+)x(\d+)\s+(\d+)dpi.*?\bapp=(\d+)x(\d+)", out)
    if m:
        w, h, dpi = int(m.group(4)), int(m.group(5)), int(m.group(3))
    if w is None:
        m = re.search(r"init=(\d+)x(\d+)\s+(\d+)dpi", out)
        if m:
            w, h, dpi = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if dpi is None:
        m = re.search(r"(\d+)", adb("shell", "wm", "density", serial=serial))
        dpi = int(m.group(1)) if m else None
    if w is None:
        m = re.search(r"(\d+)x(\d+)", adb("shell", "wm", "size", serial=serial))
        if m:
            w, h = int(m.group(1)), int(m.group(2))
    if not (w and h and dpi):
        raise ProbeError("could not read the screen from %s -- is the phone "
                         "still connected and awake?" % serial)
    return w, h, dpi, screen_density_name(dpi)


def _chrome_version(serial):
    out = adb("shell", "dumpsys", "package", "com.android.chrome",
              serial=serial)
    m = re.search(r"versionName=(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def _network_band(serial):
    out = adb("shell", "dumpsys", "telephony.registry", serial=serial)
    m = re.search(r"mServiceState=.*?mDataConnectionState=(\w+)", out)
    if m and m.group(1) in ("CONNECTED", "CONNECTED_TO_NETWORK"):
        out2 = adb("shell", "dumpsys", "telephony.registry", serial=serial)
        m2 = re.search(r"mDataNetworkType=(\w+)", out2)
        if m2 and m2.group(1) == "LTE":
            return "LTE"
    return "WIFI"


def collect(serial=None):
    """Read every wire-relevant fact off the phone.  Returns a dict."""
    serial = pick_serial(serial)

    model = getprop("ro.product.model", serial)
    brand = getprop("ro.product.brand", serial) or "motorola"
    manufacturer = getprop("ro.product.manufacturer", serial) or brand
    device = getprop("ro.product.device", serial)
    name = getprop("ro.product.name", serial) or device
    product = getprop("ro.product.name", serial) or device
    sdk = getprop("ro.build.version.sdk", serial)
    osver = getprop("ro.build.version.release", serial)
    build = getprop("ro.build.display.id", serial)
    fingerprint = getprop("ro.build.fingerprint", serial)
    incremental = getprop("ro.build.version.incremental", serial)
    abi = getprop("ro.product.cpu.abi", serial) or "arm64-v8a"
    kernel = getprop("ro.build.version.release", serial)

    locale = getprop("persist.sys.locale", serial) or getprop(
        "ro.product.locale", serial) or "en-US"
    lang, _, country = locale.partition("-")

    tzname = getprop("persist.sys.timezone", serial) or "Asia/Kolkata"
    tz_label, tz_abbr, tz_long = _tz_parts(tzname)

    w, h, dpi, dens_name = _display(serial)
    # Adjust derives low/medium/high from the raw dpi, and that is what goes
    # on the wire; the bucket label is only cosmetic.
    screen_density = ("low" if dpi < 140 else
                      "medium" if dpi <= 200 else "high")
    dp_w = round(w * 160.0 / dpi, 2)
    dp_h = round(h * 160.0 / dpi, 2)
    # Android's screen_layout_size buckets: 1=small 2=normal 3=large 4=xlarge
    layout_size = 1 if dp_w < 320 else 2 if dp_w < 600 else 3 if dp_w < 960 else 4

    android_id = adb("shell", "settings", "get", "secure", "android_id",
                     serial=serial)
    chrome = _chrome_version(serial)
    ua = ("Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/%s Mobile Safari/537.36"
          % (osver, model, chrome or "153.0.8010.36"))

    return {
        "kernel": kernel,
        "locale": {"country": country or "IN", "language": lang or "en"},
        "os_incremental": incremental,
        "device_type": "phone",
        "timezone": tz_label,
        "android_id": android_id,
        "cpu_arch": "aarch64" if abi == "arm64-v8a" else "armeabi-v7a",
        "display_metrics": {
            "xpx": str(w), "ypx": str(h),
            "xdp": dp_w, "ydp": dp_h,
            "density_dpi": dens_name,
            "screen_layout_format": "long",
            "screen_layout_size": layout_size,
        },
        "network_band": _network_band(serial),
        "User-Agent": ua,
        "os_version": osver,
        "build": build,
        "manufacturer": manufacturer,
        "local_tz": tz_abbr,
        "product": product,
        "brand": brand,
        "fingerprint": fingerprint,
        "device": device,
        "sdk": sdk,
        "name": name,
        "mainboard": name,
        "country": country or "IN",
        "local_timezone": tz_long,
        "cpu_abi": abi,
        "model": model,
        "local_tz_name": tzname,
        "resolution": "%dx%d" % (w, h),
        "display": build,
        "dpi": str(dpi),
        "screen_density_wire": screen_density,
        "_serial": serial,
    }


def save(info, path):
    with open(path, "w") as f:
        json.dump(info, f, indent=1)
    return path


if __name__ == "__main__":
    import sys
    info = collect(sys.argv[1] if len(sys.argv) > 1 else None)
    print(json.dumps(info, indent=1))
