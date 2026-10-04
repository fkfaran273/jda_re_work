"""Offline Pixel 7 Pro DEV/UA and descriptor #10 profile analysis.

Uses the preflight_arm_c.py stubbing pattern. It makes no network request and
runs no Unicorn signer or device command. New analysis file; px7_ prefix.
"""
import json
import os
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mint_pipeline as M
import run_funnel as RF
import adj9_full_chain as FC

PX_REF = (
    "adjust_reftag=cBY97SSI6u6Kx&utm_source=VKM+Digital+Yeni"
    "&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic"
)
MOTO_REF = "utm_source=(not%20set)&utm_medium=(not%20set)"
CAPTURED = []


def fake_send(url, p, blob, method="POST"):
    CAPTURED.append((url, method, dict(p)))
    return 200, b'{"fake":"offline"}'


def fake_mint(val, second, V=None, pid=None, tid=None, kind=None,
              max_steps=40_000_000):
    # The #10 claim map is already available here. Keep the real region
    # machinery as in preflight_arm_c.py, but never enter Unicorn.
    from mint_pipeline import make_V, resolve_region, build_descriptors
    V = make_V(second) if V is None else V
    pid = os.getpid() if pid is None else pid
    d0, d2, d4 = resolve_region(V, pid, tid or 0, None)
    _descs, meta = build_descriptors(val, kind, d0, d2, d4)
    return b"\x00" * 192, {
        "status": "STUB", "steps": 0,
        "desc10_padded": meta["desc10_padded"],
        "desc10_unpadded": meta["desc10_unpadded"],
        "region_src": "F.py [REAL]", "V": V, "pid": pid,
    }


def fake_mint_call(label, created_ms, gps, auid, installed=None, ims=774):
    # adj9_full_chain.api_attribution uses this helper, not mint_blob_ex.
    return int(time.time()) + FC.MINT_SKEW, b"\x00" * 192


M.mint_blob_ex = fake_mint
FC.mint_call = fake_mint_call
FC.send = fake_send
# Avoid importing the device/ADB helper module. The eight-slot contract is
# fixed by mint_pipeline._funnel_imports, and only FC is used by these builders.
M._funnel_imports = lambda: (FC, None, None, None, None, None, None, None)


def set_profile(dev, ua, off_minutes, off_label, add_idfa=False):
    FC.DEV = dict(dev)
    FC.UA = ua
    FC.OFF_MINUTES = off_minutes
    FC.OFF_LABEL = off_label
    FC.ADD_IDFA = add_idfa


def collect(dev, ua, off_minutes, off_label, ref):
    set_profile(dev, ua, off_minutes, off_label)
    CAPTURED.clear()
    gps = "8e39efb6-5260-435d-9d08-2e81b3817698"
    # Match preflight_arm_c.py's two 36-character UUID identities. The
    # Pixel JSON's android_id is only 16 characters and is not the SDK's
    # android_uuid identity field.
    auid = "11111111-2222-4333-8444-555555555555"
    t_track = int(time.time())
    ins = FC.fmt(int(t_track) + 217, 431)
    M.api_session_mint(gps, auid, ins)
    M.api_sdk_click_mint(gps, auid, ref, t_track, t_track + 210, ins)
    FC.api_attribution(gps, auid, "offline-ptoken")

    out = {}
    by_ep = {}
    for url, method, params in CAPTURED:
        ep = url.rsplit("/", 1)[-1]
        by_ep[ep] = params
    for ep, kind in (("session", "session"), ("sdk_click", "click"),
                     ("attribution", "attribution")):
        val = M.claims_from_wire(by_ep[ep], kind)
        _padded, length = M.claims_for_law(val, kind)
        out[kind] = {"params": by_ep[ep], "claims": val, "length": length}
    return out


def print_diff(name, baseline, pixel):
    print("\n%s per-claim differences" % name)
    for key in sorted(set(baseline["claims"]) | set(pixel["claims"])):
        bv = baseline["claims"].get(key)
        pv = pixel["claims"].get(key)
        if bv == pv:
            continue
        if bv is None or pv is None:
            print("  %-24s absent/present" % key)
            continue
        print("  %-24s %3d -> %3d  delta=%+d  %r -> %r"
              % (key, len(bv), len(pv), len(pv) - len(bv), bv, pv))


def main():
    px = json.load(open(os.path.join(HERE, "px7_device.json"), encoding="utf-8"))
    moto = json.load(open(os.path.join(HERE, "moto_g42_profile.json"),
                          encoding="utf-8"))
    px_dev = RF.dev_from_json(px)
    px_ua = RF.ua_from_json(px)
    print("PX_DEV=" + json.dumps(px_dev, ensure_ascii=False, sort_keys=True))
    print("PX_UA=" + px_ua)
    print("PX_REFERER_LEN=%d" % len(PX_REF))
    print("MOTO_REFERER_LEN=%d" % len(MOTO_REF))

    baseline = collect(moto["DEV"], moto["UA"], moto["OFF_MINUTES"],
                       moto["OFF_LABEL"], MOTO_REF)
    pixel = collect(px_dev, px_ua, 120, "+0200", PX_REF)

    for kind in ("session", "click", "attribution"):
        print("LENGTH %-12s moto=%d pixel=%d delta=%+d"
              % (kind, baseline[kind]["length"], pixel[kind]["length"],
                 pixel[kind]["length"] - baseline[kind]["length"]))
        print_diff(kind, baseline[kind], pixel[kind])

    # Isolate the real referrer change from the Pixel profile change.
    pixel_placeholder = collect(px_dev, px_ua, 120, "+0200", MOTO_REF)
    print("\nPIXEL_CLICK_WITH_MOTO_PLACEHOLDER=%d"
          % pixel_placeholder["click"]["length"])

    watched = ["screen_size", "screen_format", "cpu_type", "connectivity_type",
               "network_band", "carrier"]
    all_claims = set()
    for kind in ("session", "click", "attribution"):
        all_claims.update(pixel[kind]["claims"])
    wire_keys = set()
    for kind in ("session", "click", "attribution"):
        wire_keys.update(pixel[kind]["params"])
    print("\nWATCHED_FIELD_CLASSIFICATION")
    for key in watched:
        in_claims = key in all_claims
        in_wire = key in wire_keys
        print("  %-20s claim=%-5s wire=%-5s" % (key, in_claims, in_wire))

    extra = ["language", "mcc", "mnc", "display_width", "display_height",
             "screen_density", "device_manufacturer"]
    print("\nDEV_FIELD_CLAIM_IMPACT")
    for key in extra:
        print("  %-20s claim=%s" % (key, key in all_claims))


if __name__ == "__main__":
    main()
