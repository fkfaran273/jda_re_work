# py_dev_test.py - the user's request: run OUR Python logic on THEIR click + device
# data. GAID e53f99b7-… with the already-minted referrer, and the Samsung SM-S906B
# (Android 16) device data mapped into our desc10 claim law.
#
#   ARM R : their real GAID e53f99b7-…, their referrer, crafted /session + /sdk_click
#           (reads the record BEFORE touching it, so we can see what was there)
#   ARM F : fresh uuid4 GAID + fresh click from Python, SAME Samsung claim values
#           (control: is the verdict about the identity or about our bytes?)
#
# Note: ARM R writes a crafted install record onto the user's own GAID. The read
# before/after is printed so it is clear whether a record pre-existed and what
# installed_at our session stamped.
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_forge as F
import farm_win as fw
import py_book_test as pb

OUT = os.path.join(HERE, "py_dev_result.json")
GAID = "e53f99b7-dbe3-4e87-825f-9ac8a9321ae2"
REF = ("adjust_reftag=caqYoINlmNv2Y&utm_source=VKM+Digital+Yeni&utm_campaign=AH"
       "&utm_content=vkm_0926_36&utm_term=penti_generic")

# ---- their device data -> our claim keys -----------------------------------
SAMSUNG = {
    "device_name": "SM-S906B",                      # model
    "device_type": "phone",
    "device_manufacturer": "samsung",               # manufacturer
    "os_name": "android",
    "os_version": "16",                             # os_version
    "api_level": "36",                              # sdk
    "os_build": "BP2A.250605.031.A3",               # build
    "hardware_name": "BP2A.250605.031.A3.S906BXXUIGYI7",   # display
    "display_width": "1080", "display_height": "2340",     # resolution
    "screen_size": "large",                 # display_metrics.screen_layout_name
    "screen_format": "long",                # display_metrics.screen_layout_format
    "screen_density": "xxhdpi",             # display_metrics.density_dpi
    "cpu_type": "arm64-v8a",                # cpu_abi
    "language": "en",                       # locale.language
    "connectivity_type": "1",               # network WiFi
}


def build_val(gps, auid, now):
    val = pb.sdk_map()
    val.update(SAMSUNG)
    val.update({"gps_adid": gps, "android_uuid": auid,
                "created_at": pb.plus0530(now, 100),
                "sent_at": pb.plus0530(now, 130),
                "installed_at": pb.plus0530(now - 2, 200),
                "updated_at": pb.plus0530(now - 2, 200),
                "session_count": "1", "activity_kind": "session",
                "gps_adid_attempt": "1", "gps_adid_src": "service",
                "tracking_enabled": "1"})
    return val


def poll(val, tag):
    av = dict(val)
    av.update({"activity_kind": "attribution", "initiated_by": "backend"})
    for k in ("session_count", "installed_at", "updated_at", "hardware_name",
              "os_build", "initiating_package_name", "store_name_from_system"):
        av.pop(k, None)
    st, blob, _, n = F.make_signature_law(av, "attribution",
                                          second=int(time.time()))
    c, b = pb.send("GET", "/attribution", pb.wire(av), blob)
    a = pb.attr_of(b)
    print("[%s] http=%s network=%s creative=%s eng=%s inst=%s"
          % (tag, c, a.get("network"), a.get("creative"),
             (a.get("engagement_time") or "")[:19],
             (a.get("installed_at") or "")[:26]), flush=True)
    return {"http": c, "attr": a, "raw": b[:400]}


def arm(label, gps, ref, marker, fresh_click):
    now = time.time()
    auid = str(uuid.uuid4())
    rec = {"label": label, "gps": gps, "auid": auid, "marker": marker,
           "pre": None, "click": ref, "session": None, "sdk_click": None,
           "reads": []}
    print("\n=== %s  gps=%s" % (label, gps), flush=True)
    rec["pre"] = poll(build_val(gps, auid, now), label + "/pre")
    if fresh_click:
        code, ref, hops, url = fw.fire_click(gps, marker, None)
        rec["click_http"] = code
        rec["click"] = ref
        print("[%s] click http=%s reftag=%s"
              % (label, code, (ref or "").split("&")[0]), flush=True)
    val = build_val(gps, auid, now)
    st, blob, desc, unp = F.make_signature_law(val, "session", second=int(now))
    c, b = pb.send("POST", "/session", pb.wire(val), blob)
    rec["session"] = [c, b[:300]]
    print("[%s] session  %s http=%s %s" % (label, st, c, b[:140]), flush=True)
    cv = dict(val)
    cv.update({"activity_kind": "click", "google_play_instant": "0",
               "referrer": ref, "referrer_api": "google",
               "source": "install_referrer", "session_length": "0",
               "subsession_count": "1", "time_spent": "0",
               "click_time": pb.plus0530(now - 1, 100),
               "click_time_server": pb.plus0530(now - 1, 100),
               "install_begin_time": pb.plus0530(now - 1, 200),
               "install_begin_time_server": pb.plus0530(now - 1, 200)})
    st2, blob2, _, n2 = F.make_signature_law(cv, "click", second=int(now))
    c2, b2 = pb.send("POST", "/sdk_click", pb.wire(cv), blob2)
    rec["sdk_click"] = [c2, b2[:300]]
    print("[%s] sdk_click %s http=%s %s" % (label, st2, c2, b2[:140]), flush=True)
    for k in range(3):
        time.sleep(10 if k == 0 else 22)
        rec["reads"].append(poll(val, "%s/read%d" % (label, k)))
        a = rec["reads"][-1]["attr"]
        if a.get("creative") == marker or (a.get("network")
                                          not in (None, "Organic")
                                          and a.get("network")):
            print("[%s] *** JOINED / NON-ORGANIC ***" % label, flush=True)
            break
    json.dump(rec, open(os.path.join(HERE, "py_dev_%s.json" % label), "w"),
              indent=1)
    return rec


def main():
    out = [arm("R_real_gaid", GAID, REF, "cline_dev_R", False),
           arm("F_fresh_gaid", str(uuid.uuid4()), None, "cline_dev_F", True)]
    json.dump(out, open(OUT, "w"), indent=1)
    print("\n=== SUMMARY ===", flush=True)
    for r in out:
        a = (r["reads"][-1]["attr"] if r["reads"] else {})
        print("  %-13s gps=%s pre=%s net=%s creative=%s inst=%s"
              % (r["label"], r["gps"][:8],
                 (r["pre"] or {}).get("attr", {}).get("network"),
                 a.get("network"), a.get("creative"),
                 (a.get("installed_at") or "")[:26]), flush=True)
    print("saved %s" % OUT, flush=True)


if __name__ == "__main__":
    main()