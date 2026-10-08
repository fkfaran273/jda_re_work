"""extract_device_saz.py -- pull the device data + timing laws out of the
Fiddler capture the user provided (payruki_again_new.saz).

Writes device_from_saz.json (profile + stable ids + timeline deltas) and
prints a comparison against run_winner's device params.
"""
import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
RAW = os.path.join(HERE, "saz_new", "raw")

DEVICE_KEYS = [
    "store_name_from_system", "country", "api_level", "hardware_name",
    "app_version", "app_token", "device_type", "language",
    "connectivity_type", "device_manufacturer", "display_width",
    "device_name", "os_build", "cpu_type", "screen_size", "screen_format",
    "os_version", "screen_density", "environment", "display_height",
    "package_name", "initiating_package_name", "os_name", "ui_mode",
    "gps_adid_src", "tracking_enabled", "offline_mode_enabled",
    "attribution_deeplink", "needs_response_details", "foreground",
]


def load_body(n):
    # newline="" -- universal-newline translation would eat the \r\n\r\n
    t = open(os.path.join(RAW, "%02d_c.txt" % n),
             encoding="utf-8", errors="replace", newline="").read()
    head, _, body = t.partition("\r\n\r\n")
    return head, urllib.parse.parse_qsl(body.strip(), keep_blank_values=True)


def load_query(n):
    t = open(os.path.join(RAW, "%02d_c.txt" % n),
             encoding="utf-8", errors="replace", newline="").read()
    target = t.split("\r\n", 1)[0].split(" ")[1]
    return urllib.parse.parse_qsl(urllib.parse.urlsplit(target).query,
                                  keep_blank_values=True)


def ts(s):
    m = __import__("re").match(
        r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z([+-]\d\d)(\d\d)", s)
    if not m:
        return None
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    off = int(m.group(3)) * 3600 + int(m.group(4)) * 60
    ms = int((m.group(2) or "0").ljust(3, "0")[:3])
    return base.replace(tzinfo=timezone.utc).timestamp() - off + ms / 1000.0


def main():
    _, sess = load_body(65)
    _, clk = load_body(66)
    att1 = load_query(67)
    att2 = load_query(68)
    _, ev = load_body(69)
    S, C, E = dict(sess), dict(clk), dict(ev)

    profile = {k: S.get(k, "") for k in DEVICE_KEYS}
    stable = {
        "partner_payrupik_c_id": json.loads(S["partner_params"])["payrupik_c_id"],
        "gps_adid": S["gps_adid"],
        "android_uuid": S["android_uuid"],
        "reftag": C["referrer"].split("&")[0].replace("adjust_reftag=", ""),
        "referrer": C["referrer"],
        "adid": "eed7cbfcdebc9362f42ca8c7176f9521",
    }

    click = ts(C["click_time"])
    marks = {
        "click_time": ts(C["click_time"]),
        "click_time_server": ts(C["click_time_server"]),
        "install_begin_time": ts(C["install_begin_time"]),
        "install_begin_time_server": ts(C["install_begin_time_server"]),
        "installed_at": ts(C["installed_at"]),
        "session_created": ts(S["created_at"]),
        "session_sent": ts(S["sent_at"]),
        "click_created": ts(C["created_at"]),
        "click_sent": ts(C["sent_at"]),
        "attr1_created": ts(dict(att1)["created_at"]),
        "attr1_sent": ts(dict(att1)["sent_at"]),
        "attr2_created": ts(dict(att2)["created_at"]),
        "attr2_sent": ts(dict(att2)["sent_at"]),
        "event_created": ts(E["created_at"]),
        "event_sent": ts(E["sent_at"]),
    }
    timeline = {k: round(v - click, 3) for k, v in marks.items() if v}

    out = {
        "source": "payruki_again_new.saz (genuine booking 2026-10-07 13:05 IST)",
        "profile": profile,
        "stable_ids": stable,
        "timeline_offsets_from_click": timeline,
        "ms_fractions": {
            "session_created": S["created_at"].split(".")[1][:3],
            "session_sent": S["sent_at"].split(".")[1][:3],
            "click_created": C["created_at"].split(".")[1][:3],
            "click_sent": C["sent_at"].split(".")[1][:3],
            "installed": C["installed_at"].split(".")[1][:3],
            "attr1_created": dict(att1)["created_at"].split(".")[1][:3],
            "event_created": E["created_at"].split(".")[1][:3],
        },
        "attribution_flow": [
            "session -> ask_in 2000",
            "poll1 (attr1) -> Organic + ask_in 1000",
            "poll2 (attr2) +1.4s -> NON-ORGANIC 248wk8ym VL-Alliance",
            "event +0.4s after poll2",
        ],
    }
    path = os.path.join(HERE, "device_from_saz.json")
    json.dump(out, open(path, "w"), indent=1)
    print("wrote %s" % path)

    print("\n-- device profile --")
    for k, v in profile.items():
        print("   %-30s %s" % (k, v))
    print("\n-- stable ids --")
    for k, v in stable.items():
        print("   %-24s %s" % (k, v))
    print("\n-- timeline (offset from click_time, s) --")
    for k, v in timeline.items():
        print("   %-28s %+8.3f" % (k, v))
    print("\n-- ms fractions --")
    print("   %s" % out["ms_fractions"])

    # compare the profile against what the runner would send
    import run_winner as R
    print("\n-- vs run_winner device params --")
    diffs = 0
    for k, v in profile.items():
        ours = R.P.get(k)
        if ours is None:
            ours = getattr(R, k.upper(), None)
        if ours is not None and str(ours) != str(v):
            print("   DIFF %-30s ours=%r capture=%r" % (k, ours, v))
            diffs += 1
    for k in ("app_version", "package_name", "environment"):
        if k in profile:
            print("   %-24s capture=%s" % (k, profile[k]))
    print("   profile diffs: %d" % diffs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
