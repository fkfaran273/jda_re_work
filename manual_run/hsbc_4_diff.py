"""hsbc_4_diff.py -- tasks: adj_verification decode + bodies diff vs our
run_install builder (requests.post/get stubbed; nothing leaves the machine).

Diffs, per kind (session / sdk_click / attribution):
  - keys genuine-has-we-lack, we-have-genuine-lacks
  - value mismatches on shared keys (timing shapes)
  - Client-SDK / Authorization envelope differences
Offline only.
"""
import base64
import json
import re
import sys
import urllib.parse

import hsbc_lib as L
import run_install as R

SAZ = r"C:\Users\Apps\Downloads\com.penti.app\manual_run\hsbc_saz\raw"


# ---------------------------------------------------------------------------
# 0. the adj_verification values, decoded
# ---------------------------------------------------------------------------
def dump_adj_verification():
    seen = {}
    for sid in ("07", "08", "09"):
        e = L.parse_entry(sid)
        seen[e["env"]["adj_verification"]] = e["kind"]
    for v, kinds in reversed(seen.items() if False else sorted(
            seen.items(), key=lambda kv: len(kv[0]))):
        raw = base64.b64decode(v)
        print("adj_verification %s (kind %s): %d b64 chars -> %s" %
              (v, kinds, len(v), raw.hex()))


# ---------------------------------------------------------------------------
# 1. capture the genuine bodies
# ---------------------------------------------------------------------------
GEN = {}
for sid in ("07", "08", "09"):
    e = L.parse_entry(sid)
    GEN[e["kind"]] = e

# ---------------------------------------------------------------------------
# 2. run our builder with requests stubbed out
# ---------------------------------------------------------------------------
CAPTURED = []


class FakeResp:
    content = b"{}"
    status_code = 200

    def json(self):
        return {"attribution": {"network": "STUB"}}


def _stub_post(url, data=None, headers=None, timeout=None, proxies=None):
    CAPTURED.append({"method": "POST", "url": url, "data": dict(data),
                     "headers": dict(headers)})
    return FakeResp()


def _stub_get(url, params=None, headers=None, timeout=None, proxies=None):
    q = urllib.parse.urlencode(params or {})
    CAPTURED.append({"method": "GET", "url": url + "?" + q,
                     "data": dict(params or {}), "headers": dict(headers)})
    return FakeResp()


# ---------------------------------------------------------------------------
# 3. the HSBC campaign dict + device from the capture
# ---------------------------------------------------------------------------
CAMP = {
    "app_name": "HSBC Turkey",
    "package_name": "tr.com.hsbc.hsbcturkey",
    "app_version_name": "1.8.6",
    "adjust": {"app_token": "y5qirhnmpxj4", "sdk": "android5.0.0"},
    "cert_sha1": "5f432709857de074ed38f2e7acb57e3363579910",
    "adj_signing_id": "1500000",
    "headers_id": "11",
    "native_version": "5.5.0",
    "head_phase": (0x40,),
    "poll_delays": [3, 8, 20],
}
DEV = {
    "api_level": "31", "os_version": "12", "device_name": "GM1901",
    "device_manufacturer": "OnePlus", "hardware_name": "GM1901_11_H.41",
    "os_build": "SKQ1.211113.001", "language": "en", "country": "US",
    "display_width": "1080", "display_height": "2215",
    "screen_density": "high", "screen_size": "normal", "screen_format": "long",
    "cpu_type": "arm64-v8a", "connectivity_type": "1",
    "timezone": "+0530",
    "enqueue_size": "0", "first_error": "0", "last_error": "0",
    "retry_count": "0", "wait_time": "0.0", "wait_total": "0.0",
}
# the genuine device has NO mcc/mnc keys (leave them out)


def main():
    dump_adj_verification()

    R.DRY_RUN = False
    R.GAP = 0
    R.requests.post = _stub_post
    R.requests.get = _stub_get
    R.RUN["gaid"] = GEN["session"]["fields"]["gps_adid"]
    R.RUN["android_uuid"] = GEN["session"]["fields"]["android_uuid"]
    R.RUN["t0"] = 0.0
    R.RUN["click_sec"] = L.ts_to_unix(GEN["click"]["fields"]["click_time"])
    R.RUN["referrer"] = GEN["click"]["fields"]["referrer"]
    print("\nstubbed run: gaid=%s referrer=%r click_sec=%d\n" %
          (R.RUN["gaid"], R.RUN["referrer"], R.RUN["click_sec"]))

    with_ver = dict(CAMP)
    with_ver["adj_verification"] = GEN["session"]["env"]["adj_verification"]
    R.session(with_ver, DEV)
    with_ver["adj_verification"] = GEN["click"]["env"]["adj_verification"]
    R.sdk_click(with_ver, DEV)
    R.attribution(with_ver, DEV)

    ours = {"session": CAPTURED[0], "click": CAPTURED[1],
            "attribution": CAPTURED[2]}

    # full Authorization strings side by side (for the envelope diff)
    for kind in ("session", "click", "attribution"):
        g, o = GEN[kind], ours[kind]
        print("=" * 72)
        print("--- %s ---------------------------------------------------------------" % kind)
        print("URL ours  : %s" % o["url"].split("?")[0])
        print("URL theirs: %s" % g["url"].split("?")[0])
        gh, oh = o["headers"], None
        # genuine headers, keyed case-insensitively
        genu = open("%s\\%s_c.txt" % (SAZ, g["sid"]), "rb").read().decode()
        gm = re.match(r"([^\r\n]+)\r\n(.*?)\r\n\r\n", genu, re.S)
        ghdr = {}
        for line in gm.group(2).split("\r\n"):
            k, _, v = line.partition(": ")
            ghdr[k.lower()] = v
        print("Client-SDK  ours=%r theirs=%r" %
              (gh.get("Client-SDK"), ghdr.get("client-sdk")))
        for piece in ("signature", "adj_signing_id", "algorithm", "headers_id",
                      "native_version", "adj_verification"):
            op = re.search(piece + r'="([^"]*)"' if piece != "signature"
                           else r'signature="([^"]+)"', gh.get("Authorization", ""))
            gp = re.search(piece + r'="([^"]*)"' if piece != "signature"
                           else r'signature="([^"]+)"',
                           ghdr.get("authorization", ""))
            ov, gv = (op.group(1) if op else "<absent>"), (gp.group(1) if gp else "<absent>")
            if piece == "signature":
                ov = "len=%d" % len(ov)
                gv = "len=%d" % len(gv)
            flag = "" if ov == gv else "   <-- DIFFERS"
            print("  %-15s ours=%-18s theirs=%s%s" % (piece, ov, gv, flag))

        gk, ok = set(g["fields"]), set(o["data"])
        only_g = sorted(gk - ok)
        only_o = sorted(ok - gk)
        print("  keys genuine-has-we-lack (%d): %s" % (len(only_g), only_g))
        print("  keys we-have-genuine-lacks (%d): %s" % (len(only_o), only_o))
        diffvals = []
        for k in sorted(gk & ok):
            if g["fields"][k] != o["data"][k]:
                if k in ("created_at", "sent_at", "updated_at", "installed_at"):
                    # same tz label + format?
                    f = lambda s: re.sub(r"^\d{2}:\d{2}:\d{2}", "HH:MM:SS", s)
                    same = (f(g["fields"][k]) == f(o["data"][k])
                            and len(g["fields"][k]) == len(o["data"][k]))
                    diffvals.append((k, g["fields"][k], o["data"][k],
                                     "format" + ("" if same else "+SHAPE DIFF")))
                else:
                    diffvals.append((k, g["fields"][k], o["data"][k], "value"))
        for k, gv2, ov2, tag in diffvals:
            if tag.startswith("format"):
                tag = "format (both HH:MM:SS-exp) OK" if "form OK" in tag else tag
            print("  value diff %-24s theirs=%r ours=%r  %s" % (k, gv2, ov2, tag))

    # timeline of the genuine capture, for the record
    print("=" * 72)
    print("genuine timeline (tz +0530):")
    cf = GEN["click"]["fields"]
    sf = GEN["session"]["fields"]
    print("  click_time            %s   click_time_server %s" %
          (cf.get("click_time"), cf.get("click_time_server")))
    print("  install_begin_time    %s   begin_time_server  %s" %
          (cf.get("install_begin_time"), cf.get("install_begin_time_server")))
    print("  installed_at click   %s" % cf.get("installed_at"))
    print("  installed_at session %s" % sf.get("installed_at"))
    print("  session created_at   %s   sent_at %s" %
          (sf.get("created_at"), sf.get("sent_at")))
    print("  click created_at     %s   sent_at %s" %
          (cf.get("created_at"), cf.get("sent_at")))
    print("  attr created_at      %s   sent_at %s" %
          (GEN["attribution"]["fields"].get("created_at"),
           GEN["attribution"]["fields"].get("sent_at")))


if __name__ == "__main__":
    main()
