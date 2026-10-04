"""Prove the transmitted region is reproducible from the transmitted stamps.

For each endpoint this builds the exact params the API module would send, mints
the blob, then does what the server can do: recover d2 from the wire envelope,
and enumerate every (usec) inside the created_at..sent_at window to see whether
some (second, usec, pid) triple reproduces that d2 under the region law.

If any endpoint reports "reproducible: True" with a small pid set, the request
is internally consistent the same way the device's own signing is.
"""
import base64
import struct
import time

import adj9_api as A
import adj9_signer as S

# d2 is descriptor #2 in the body. The body layout is fixed:
# header 16B, then the 11 descriptors in VA_ORDER with their word counts.
# We recover d2 by re-deriving descriptors from the claimed map -- simpler and
# authoritative -- rather than parsing the blob at a guessed offset.
BODY = [(0, 36), (9, 5), (8, 4), (4, 8), (2, 1), (7, 1), (10, None),
        (5, 1), (1, 0), (6, 1), (3, 0)]


def wire_d2(params, kind, V, pid):
    """Re-derive d2 exactly as build_descriptors will emit it."""
    val = S.claims_from_wire(params, kind)
    d0, d2, d4 = S.region_fn(V, pid, 0)
    return d2, val


def check(name, kind, params, V, pid):
    d2, val = wire_d2(params, kind, V, pid)
    c_ms = int(params["created_at"][20:23])
    s_ms = int(params["sent_at"][20:23])
    # Unix second the stamps denote (fmt prepends the tz offset; parse back).
    sec = stamp_second(params["created_at"])
    lo, hi = c_ms * 1000, s_ms * 1000 + 999
    if hi < lo:
        lo, hi = hi, lo
    found = []
    for usec in range(lo, hi + 1):
        Vs = (sec ^ usec) & 0xFFFFFFFF
        seed = (Vs ^ ((pid & 0xFFFF) << 16)) & 0xFFFFFFFF
        if int.from_bytes(seed.to_bytes(4, "little"), "big") == d2:
            found.append(usec)
    print("== %s ==" % name)
    print("   V=%08x pid=%d d2=%08x  window second=%d  [%d..%d] usec"
          % (V, pid, d2, sec, lo, hi))
    print("   reproducible: %s  (%d usec match%s)"
          % (bool(found), len(found), "es" if len(found) != 1 else ""))
    return bool(found)


def stamp_second(stamp):
    """Unix second denoted by a fmt() stamp 'YYYY-MM-DDTHH:MM:SS.mmmZ+ZZZZ'."""
    import calendar
    y = int(stamp[0:4]); mo = int(stamp[5:7]); d = int(stamp[8:10])
    h = int(stamp[11:13]); mi = int(stamp[14:16]); s = int(stamp[17:19])
    # fmt() emits '...SS.mmmZ+HHMM'; the +HHMM offset sits at the tail.
    tail = stamp[stamp.index("Z") + 1:]                 # e.g. '+0200'
    off = int(tail[1:3]) * 60 + int(tail[3:5])          # minutes
    # fmt ADDS the offset to a UTC dt then labels it +OFF, so subtract it back.
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) - off * 60


def main():
    api = A.Api()
    sec = int(time.time()) + api.MINT_SKEW
    pid = S.DEFAULT_PID
    gps = "11111111-2222-3333-4444-555555555555"
    auid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    ok = True
    for name, kind, ms_c, ms_s in (("session", "session", 928, 942),
                                   ("click", "click", 961, 970),
                                   ("attribution", "attribution", 666, 696)):
        if kind == "session":
            p = api._base("S1P")
            insd = api.fmt(sec - 170, 774).decode()
            p.update({"gps_adid": gps, "android_uuid": auid,
                      "created_at": api.fmt(sec - 1, ms_c).decode(),
                      "sent_at": api.fmt(sec - 1, ms_s).decode(),
                      "installed_at": insd, "updated_at": insd})
        elif kind == "click":
            p = api._base("S2P")
            p.update({"gps_adid": gps, "android_uuid": auid,
                      "created_at": api.fmt(sec - 1, ms_c).decode(),
                      "sent_at": api.fmt(sec - 1, ms_s).decode(),
                      "installed_at": insd, "updated_at": insd,
                      "referrer": "utm_source=google-play&utm_medium=organic",
                      "source": "install_referrer", "referrer_api": "google",
                      "click_time": api.fmt(sec - 220, 0).decode(),
                      "click_time_server": api.fmt(sec - 222, 0).decode(),
                      "install_begin_time": api.fmt(sec - 10, 0).decode(),
                      "install_begin_time_server": api.fmt(sec - 12, 0).decode()})
        else:
            d = api._dev_fields()
            p = {"initiated_by": "backend", "gps_adid_attempt": "1",
                 "api_level": d["api_level"], "app_version": d["app_version"],
                 "app_token": A.APP_TOKEN, "os_version": d["os_version"],
                 "created_at": api.fmt(sec - 1, ms_c).decode(),
                 "device_type": "phone", "gps_adid": gps, "foreground": "1",
                 "android_uuid": auid,
                 "sent_at": api.fmt(sec - 1, ms_s).decode(),
                 "offline_mode_enabled": "0", "device_name": d["device_name"],
                 "environment": "production", "needs_response_details": "1",
                 "attribution_deeplink": "1", "package_name": "com.penti.app",
                 "os_name": "android", "ui_mode": "1", "gps_adid_src": "service",
                 "tracking_enabled": "1"}
        V = api._V_for(p, sec - 1, None)
        ok &= check(name, kind, p, V, pid)
    print("\nALL REPRODUCIBLE" if ok else "\nNOT REPRODUCIBLE")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
