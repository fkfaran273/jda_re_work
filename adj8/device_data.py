# -*- coding: utf-8 -*-
"""device_data.py -- the device profile in the AutoLabs backend's shape, plus
the translation into Adjust's wire parameters.

DEVICE below is the same nested blob their backend prints ("DEVICE DATA
{...}"), populated from the connected moto g42 (adb getprop, 2026-10-02).
device_to_params() does the mapping; the rules are the ones proven against the
genuine adj8 captures:

  screen_density   Adjust's vocabulary from density_dpi:
                   >=600 veryhigh, >=480 xhigh, >=400 high, >=320 medium,
                   >=240 low, else low
  hardware_name    the SoC (mainboard), NOT the build string
  mcc / mnc        present in the blob but STRIPPED before sending -- genuine
                   bodies carry neither, even on SIM
  timezone         local metadata for the timestamps only, never sent
  connectivity_type  1 on wifi/mobile data, 0 only when there is no network
  device_name      the model, device_type stays "phone"
"""

# screen_density buckets (Adjust SDK vocabulary, not the device's dpi string)
_DENSITY = [(600, "veryhigh"), (480, "xhigh"), (400, "high"),
            (320, "medium"), (240, "low")]


def screen_density(dpi):
    try:
        dpi = int(dpi)
    except (TypeError, ValueError):
        return "high"
    for floor, name in _DENSITY:
        if dpi >= floor:
            return name
    return "low"


DEVICE = {
    "kernel": "16",
    "locale": {
        "country": "IN",
        "language": "en"
    },
    "ram": {
        "available": "11085",
        "shown": "12288"
    },
    "os_incremental": "S928USQU4CYI9",
    "bluetooth": "3.0",
    "hardware": "",
    "imei": "866212510036076",
    "cpu_core": "7",
    "private_ip": "10.0.213.226",
    "device_type": "phone",
    "timezone": "+0530",
    "serial": "2045787d83ee6ea3",
    "mnc": "56",
    "android_id": "e3d3324eece03d90",
    "cpu_arch": "aarch64",
    "display_metrics": {
        "ypx": "1080",
        "screen_layout_name": "large",
        "screen_layout_format": "long",
        "xpx": "2340",
        "ydp": 451.694,
        "xdp": 452.174,
        "aspect_ratio": "14:6",
        "density_dpi": "xxhdpi",
        "screen_layout_size": 3
    },
    "last_rebooted_at": 1791016742307,
    "network_band": "LTE",
    "cpu_abi2": "",
    "User-Agent": "Mozilla/5.0 (Linux; Android 16; SM-S928U Build/BP2A.250605.031.A3; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/153.0.8010.36 Mobile Safari/537.36",
    "cpu_frequency": {
        "max": "2265.0",
        "min": "364.0"
    },
    "os_version": "16",
    "build": "BP2A.250605.031.A3",
    "gpu": {
        "version": "ARM",
        "vendor": "ARM",
        "name": "Immortalis-G925",
        "opengl_version": "262400"
    },
    "build_prop": {
        "dalvik_vm_isa_x86_features": "",
        "dalvik_vm_isa_x86_variant": "",
        "dalvik_vm_isa_arm_variant": "",
        "dalvik_vm_isa_arm64_features": "default",
        "dalvik_vm_isa_arm64_variant": "kryo300",
        "dalvik_vm_isa_arm_features": "",
        "ro_build_user": "dpi"
    },
    "manufacturer": "samsung",
    "subAgent": "w77le91flo6o902n18",
    "local_tz": "IST",
    "product": "e3qsqw",
    "brand": "samsung",
    "screen_size": "5.7",
    "mcc": "405",
    "device_id": "a6f6194e-1197-4633-b226-a7e02a9610c8",
    "mac": "b3:9c:b9:5c:77:40",
    "adid": "a6f6194e-1197-4633-b226-a7e02a9610c8",
    "apps_count": {
        "user_apps": 74,
        "sideloaded_apps": 18,
        "stock_apps": 240
    },
    "fingerprint": "samsung/e3qsqw/e3q:16/BP2A.250605.031.A3/S928USQU4CYI9:user/release-keys",
    "device": "e3q",
    "sensors": {
        "magnetometer": {
            "vendor": "akm",
            "name": "AK09918 Magnetometer"
        },
        "gyroscope": {
            "vendor": "STMicro",
            "name": "lsm6dsv LSM6DSO Gyroscope Non-wakeup"
        },
        "accelerometer": {
            "vendor": "STMicro",
            "name": "lsm6dsv LSM6DSV Accelerometer Non-wakeup"
        }
    },
    "sdk": "36",
    "name": "e3q",
    "currency": {
        "code": "INR",
        "name": "Indian Rupee"
    },
    "mainboard": "pineapple",
    "country": "India",
    "local_timezone": "Indian Standard Time",
    "processor": "AArch64 Processor rev 4 (aarch64)",
    "network": "WiFi",
    "carrier": "AirTel",
    "os_codename": "REL",
    "cpu_abi": "arm64-v8a",
    "internal_memory": {
        "available": "461.16 GB",
        "shown": "512 GB"
    },
    "model": "SM-S928U",
    "local_tz_name": "Asia/Kolkata",
    "resolution": "1080x2340",
    "display": "BP2A.250605.031.A3.S928USQU4CYI9",
    "dpi": "450"
}





def props_from_device(device=None):
    """The 15 system properties the 3.67.0 native fingerprints, derived from
    the AutoLabs device blob so the served environment MATCHES the device
    story being signed (the server cross-checks the record's embedded device
    data against the request's api_level/os_version/device_name claims)."""
    d = device or DEVICE
    fp = str(d.get("fingerprint", ""))
    parts = fp.split("/")
    # fingerprint: brand/product/device:version/build/type-keys  -> bootloader
    # best-effort from the fingerprint's build segment when absent
    props = {
        "ro.product.name": str(d.get("name", "")),
        "ro.product.model": str(d.get("model", "")),
        "ro.product.manufacturer": str(d.get("manufacturer", "")),
        "ro.product.device": str(d.get("device", "")),
        "ro.product.cpu.abilist": (str(d.get("cpu_abi", "arm64-v8a"))
                                   + ",armeabi-v7a,armeabi"),
        "ro.product.brand": str(d.get("brand", "")),
        "ro.hardware": str(d.get("mainboard", "")),
        "ro.build.version.sdk": str(d.get("sdk", "31")),
        "ro.build.version.release": str(d.get("os_version", "12")),
        "ro.build.user": str(d.get("build_prop", {}).get(
            "ro_build_user", "dpi")),
        "ro.build.type": "user",
        "ro.build.host": "dpi",
        "ro.build.fingerprint": fp,
        "ro.build.display.id": str(d.get("display", "") or d.get("build",
                                   "")),
        "ro.bootloader": (parts[4] if len(parts) > 4 else "unknown"),
    }
    if d.get("build_prop", {}).get("ro_build_type"):
        props["ro.build.type"] = str(d["build_prop"]["ro_build_type"])
    return {k.encode(): v.encode() for k, v in props.items()}


def tz_minutes(device):
    """'+0530' -> minutes east of UTC."""
    tz = device.get("timezone", "+0530")
    sign = -1 if tz[0] == "-" else 1
    return sign * (int(tz[1:3]) * 60 + int(tz[3:5]))


def tz_label(device):
    return device.get("timezone", "+0530")


def device_to_params(device=None):
    """The Adjust wire fields that come from the device (not from the
    request: no timestamps, no app identity)."""
    d = device or DEVICE
    dm = d.get("display_metrics", {})
    res = str(d.get("resolution", "")).split("x")
    net = str(d.get("network", "")).lower()
    params = {
        "api_level": d.get("sdk", "31"),
        "os_version": d.get("os_version", "12"),
        "device_name": d.get("model", ""),
        # genuine bodies send the lower-case brand
        "device_manufacturer": str(d.get("manufacturer", "")).lower(),
        # genuine captures: hardware_name == os_build (the display id) --
        # moto oracle S2SE32.28-28-4, yamistar booking BP1A.250405.007.D1
        "hardware_name": d.get("display", "") or d.get("build", ""),
        "os_build": d.get("build", ""),
        "language": d.get("locale", {}).get("language", "en"),
        "country": d.get("locale", {}).get("country", "IN"),
        "display_width": res[0] if len(res) == 2 else dm.get("xpx", ""),
        "display_height": res[1] if len(res) == 2 else dm.get("ypx", ""),
        "screen_density": screen_density(dm.get("density_dpi") or d.get("dpi")),
        "screen_size": dm.get("screen_layout_name", "normal"),
        "screen_format": dm.get("screen_layout_format", "long"),
        "cpu_type": d.get("cpu_abi", "arm64-v8a"),
        # 1 on wifi or mobile data; 0 only with no network at all.  (The
        # team's penti body sent 0 while claiming WiFi -- a fraud tell.)
        "connectivity_type": "0" if net in ("", "none") else "1",
    }
    # mcc / mnc are deliberately NOT included: genuine bodies carry neither.
    return params


def device_headers(device=None):
    """UA string for the wire (Dalvik form, as the SDK sends it)."""
    d = device or DEVICE
    return ("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)"
            % (d.get("os_version", "12"), d.get("model", ""),
               d.get("build", "")))


def browser_ua(device=None):
    """UA for fetching the click link as a browser would."""
    d = device or DEVICE
    return d.get("User-Agent",
                 "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")


if __name__ == "__main__":
    import json
    print(json.dumps(device_to_params(), indent=2, sort_keys=True))
    print(device_headers())
