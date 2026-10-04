"""_sub_ios_claims_probe.py — TASK 1: verify the claims law on iOS against
the decrypted record BLOCK field (@46..77) for all 30 captured requests.

Read-only w.r.t. adj9_signer.py and the capture.

BLOCK recipe (Android): sha256_iv2(D9 || 00 08 || head16 || LE32(S) ||
SHA256("") || TAIL || claims) with TAIL = 01 || 00*16.  On iOS the record
carries 0x02 @112 and the device name @114..129, so the tail may be
record-derived: 02 || device_name_field.  We try both.

Claims candidates: the Android desc10 law with iOS body params (presence-
filtered), where values not in the body come from the request itself
(client_sdk = Client-Sdk header, adj_verification = Authorization header,
adj_signing_id pinned).  Event tail derived empirically.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import sys
import zipfile
from urllib.parse import urlsplit, parse_qsl, unquote, unquote_plus, \
    unquote_to_bytes


def parse_pairs(raw):
    """urlencoded pairs -> dict, values as the exact bytes the client held
    (percent-decoded bytes, re-encoded latin-1)."""
    d = {}
    for kv in raw.split("&"):
        if not kv:
            continue
        k, _, v = kv.partition("=")
        d[unquote_plus(k)] = unquote_to_bytes(v).decode("latin1")
    return d

import adj9_signer as sg
from _sub_unseal_core import whiten_inverse

HERE = os.path.dirname(os.path.abspath(__file__))
SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"

# ---------------------------------------------------------------- capture
def load_requests():
    """The 30 signed requests: params, path kind, header constants, blob."""
    z = zipfile.ZipFile(SAZ)
    out = []
    for name in sorted(z.namelist()):
        if not re.fullmatch(r"raw/\d+_c\.txt", name):
            continue
        txt = z.read(name).decode("latin1")
        m = re.search(r'signature="([A-Za-z0-9+/=]+)"', txt)
        if not m:
            continue
        blob = base64.b64decode(m.group(1))
        head, _, body = txt.partition("\r\n\r\n")
        line1 = head.split("\r\n")[0]
        method, target = line1.split(" ")[0], line1.split(" ")[1]
        p = urlsplit(target)
        q = parse_pairs(p.query)
        b = parse_pairs(body)
        val = dict(q)
        val.update(b)
        sdk = re.search(r"(?im)^Client-Sdk:\s*(\S+)", head)
        avs = re.search(r'adj_verification="([A-Za-z0-9+/=]+)"', head)
        out.append({
            "file": os.path.basename(name),
            "method": method,
            "path": p.path,
            "kind": p.path.lstrip("/").replace("sdk_click", "click"),
            "client_sdk": sdk.group(1) if sdk else None,
            "adj_verification": avs.group(1) if avs else None,
            "val": val,
            "blob": blob,
        })
    return out


# ------------------------------------------------------- claims machinery
PROFILE = list(sg.PROFILE)                      # android profile keys
PROFILE_IOS_EXTRA = ["bundle_id", "idfa", "idfv"]   # ios-named profile keys
SESSION_TAIL = list(sg.SESSION_TAIL)
CLICK_TAIL = list(sg.CLICK_TAIL)
ATTR_TAIL = list(sg.ATTR_TAIL)
EVENT_TAIL = ["callback_params", "event_count", "event_token", "seq"]
EVENT_TAIL_ALT = ["event_token", "callback_params", "event_count", "seq"]
BLOCK2 = list(sg.BLOCK2)
PINNED = sg.PINNED

TAILS = {
    "android_const": b"\x01" + b"\x00" * 16,          # BLOCK_TAIL as-is
    "record_derived": None,                            # rec[112] + rec[114:130]
    "variant_zero": None,                              # rec[112] + 00*16
}


def build_claims_candidates(val, kind, extra_vals, profile_keys, tail_keys):
    """Presence-filtered law exactly like sg.desc10_keys/build_claims, but
    with configurable key lists and an extra value map (header constants).
    Returns the claims bytes."""
    keys = [k for k in sorted(profile_keys) if val.get(k)]
    keys.append(PINNED)
    keys += [k for k in sorted(tail_keys) if val.get(k)]
    keys += [k for k in BLOCK2 if extra_vals.get(k)]
    parts = []
    for k in keys:
        v = val.get(k) or extra_vals.get(k)
        if k == PINNED and not v:
            v = "1500000"
        if not v:
            return None
        parts.append(v)
    return "".join(str(x) for x in parts).encode("latin1")


def block_for(rec, S, head16, claims, d9, tail_mode):
    if tail_mode == "android_const":
        tail = b"\x01" + b"\x00" * 16
    elif tail_mode == "record_derived":
        tail = bytes([rec[112]]) + rec[114:130]
    elif tail_mode == "variant_zero":
        tail = bytes([rec[112]]) + b"\x00" * 16
    else:
        raise ValueError(tail_mode)
    msg = (bytes(d9) + b"\x00\x08" + bytes(head16)
           + struct.pack("<I", S & 0xFFFFFFFF) + sg.SHA0 + tail
           + bytes(claims))
    return sg.sha256_iv2(msg)


# ------------------------------------------------------------------- main
def main():
    reqs = load_requests()
    print("[probe] %d signed requests" % len(reqs))
    kinds = {}
    for r in reqs:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print("[probe] kinds: %s" % kinds)

    # unseal each record
    for r in reqs:
        blob = r["blob"]
        header, body = blob[:16], blob[16:160]
        rec = whiten_inverse(body, header)
        r["rec"] = rec
        r["S"] = int.from_bytes(rec[20:24], "big")
        r["head16"] = rec[3:19]
        r["BLOCK"] = rec[46:78]
        r["d9"] = rec[25:45]
        assert r["d9"] == b"\x00" * 20, r["file"]

    d9 = b"\x00" * 20

    # --- base profile variants to test --------------------------------
    prof_android = [k for k in PROFILE]                      # android names only
    prof_ios = [k for k in PROFILE if k not in
                ("android_uuid", "gps_adid", "package_name")] + PROFILE_IOS_EXTRA

    profile_variants = {
        "android_names": prof_android,
        "ios_names": prof_ios,
    }
    tail_variants = {
        "click": {"android": CLICK_TAIL},
        "session": {"android": SESSION_TAIL},
        "attribution": {"android": ATTR_TAIL},
        "event": {"event_sorted": sorted(EVENT_TAIL),
                  "event_hint": list(EVENT_TAIL_ALT)},
    }

    for tail_mode in ("android_const", "record_derived", "variant_zero"):
        print("\n=== BLOCK tail mode: %s ===" % tail_mode)
        for pv_name, prof in profile_variants.items():
            for kind in ("session", "click", "attribution", "event"):
                tv = tail_variants[kind]
                for tv_name, tail_keys in tv.items():
                    hits = []
                    for r in reqs:
                        if r["kind"] != kind:
                            continue
                        extra = {"client_sdk": r["client_sdk"],
                                 "headers_id": "10",
                                 "native_version": "5.0.0",
                                 "adj_verification": r["adj_verification"]}
                        claims = build_claims_candidates(
                            r["val"], kind, extra, prof, tail_keys)
                        if claims is None:
                            continue
                        blk = block_for(r["rec"], r["S"], r["head16"],
                                        claims, d9, tail_mode)
                        if blk == r["BLOCK"]:
                            hits.append(r["file"])
                    if hits:
                        print("  prof=%-13s tail=%-13s kind=%-11s -> %d/%d  %s"
                              % (pv_name, tv_name, kind, len(hits),
                                 sum(1 for r in reqs if r["kind"] == kind),
                                 hits[:4]))

    # dump one sample claims string for inspection
    r = reqs[0]
    extra = {"client_sdk": r["client_sdk"], "headers_id": "10",
             "native_version": "5.0.0", "adj_verification": r["adj_verification"]}
    cl = build_claims_candidates(r["val"], r["kind"], extra,
                                 profile_variants["ios_names"], CLICK_TAIL)
    print("\n[probe] sample %s (%s) claims (%d B): %r"
          % (r["file"], r["kind"], len(cl), cl[:120]))

    return 0


if __name__ == "__main__":
    sys.exit(main())
