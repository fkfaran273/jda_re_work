"""_sub_ios_framescan2.py — frame scan round 2.

New axes beyond round 1:
  S-slot  : LE32(S) | BE32(S) | LE32(second) | BE32(second) |
            LE32(x=second mod (2^31-1)) | BE32(x)      [seconds recovered]
  TAIL    : round-1 set + long tails (const||dev16, dev after const)
  SUFFIX  : none | dev16 appended after claims
Claims: frozen candidates (android/ios/canon name laws x value forms).
"""
from __future__ import annotations

import base64
import json
import re
import struct
import sys
import zipfile
from urllib.parse import urlsplit, unquote, unquote_plus

import adj9_signer as sg
from _sub_unseal_core import whiten_inverse
from _sub_ios_header import make_ios_header, minstd_state

SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
SECONDS = json.load(open(r"C:/Users/Apps/Downloads/com.penti.app/adj9sign/"
                         r"one_click_run/_sub_ios_seconds.json"))


def load_all():
    z = zipfile.ZipFile(SAZ)
    sec = {r["file"]: r["signing_second"] for r in SECONDS}
    out = []
    for name in sorted(z.namelist()):
        if not re.fullmatch(r"raw/\d+_c\.txt", name):
            continue
        txt = z.read(name).decode("latin1")
        m = re.search(r'signature="([A-Za-z0-9+/=]+)"', txt)
        if not m:
            continue
        blob = base64.b64decode(m.group(1))
        rec = whiten_inverse(blob[16:160], blob[:16])
        head, _, body = txt.partition("\r\n\r\n")
        target = head.split("\r\n")[0].split(" ")[1]
        p = urlsplit(target)
        raw = (p.query.split("&") if p.query else []) + body.split("&")
        dec, wire = {}, {}
        for kv in raw:
            k, _, v = kv.partition("=")
            k = unquote_plus(k)
            dec[k] = unquote(v)
            wire[k] = v.replace("+", "%20")
        sdk = re.search(r"(?im)^Client-Sdk:\s*(\S+)", head)
        avs = re.search(r'adj_verification="([A-Za-z0-9+/=]+)"', head)
        out.append({
            "file": name.split("/")[-1],
            "kind": p.path.lstrip("/").replace("sdk_click", "click"),
            "dec": dec, "wire": wire, "rec": rec,
            "S": int.from_bytes(rec[20:24], "big"),
            "second": sec[name.split("/")[-1]],
            "client_sdk": sdk.group(1) if sdk else "ios5.8.0",
            "av": avs.group(1) if avs else None,
            "BLOCK": rec[46:78],
        })
    return out


AK = ["app_token", "app_version", "created_at", "device_name",
      "device_type", "environment", "installed_at", "os_name", "os_version"]
IOS_EXTRA = ["bundle_id", "idfa", "idfv"]
TAILS_BY_KIND = {
    "session": ["session_count", "session_length", "subsession_count",
                "time_spent"],
    "click": ["session_count", "session_length", "source",
              "subsession_count", "time_spent"],
    "attribution": ["tracking_enabled"],
    "event": ["session_count", "session_length", "subsession_count",
              "time_spent"],
}
EVENT_KEYS = ["callback_params", "event_count", "event_token", "seq"]


def claims_candidates(r):
    kind = r["kind"]
    out = []
    for vname, val in (("dec", r["dec"]), ("wire", r["wire"])):
        android = [k for k in AK if val.get(k)]
        tail_pool = [k for k in TAILS_BY_KIND[kind] if val.get(k)]
        if kind == "event":
            tail_pool = sorted(tail_pool + [k for k in EVENT_KEYS
                                            if val.get(k)])
        for pname, keys in (("an", android),
                            ("ios", sorted(android + [k for k in IOS_EXTRA
                                                      if val.get(k)]))):
            c = "".join(val[k] for k in keys)
            tk = "".join(val[k] for k in tail_pool)
            out.append(("%s/%s" % (vname, pname), c))
            out.append(("%s/%s+pin" % (vname, pname), c + "1500000"))
            out.append(("%s/%s+pin+tail" % (vname, pname), c + "1500000" + tk))
            out.append(("%s/%s+pin+tail+b2" % (vname, pname),
                        c + "1500000" + tk + "ios5.8.0" + "10" + "5.0.0"))
            out.append(("%s/%s+pin+tail+akb2" % (vname, pname),
                        c + "1500000" + tk + kind + "ios5.8.0" + "10"
                        + "5.0.0"))
            out.append(("%s/av+%s+pin+tail+akb2" % (vname, pname),
                        r["av"] + c + "1500000" + tk + kind + "ios5.8.0"
                        + "10" + "5.0.0"))
            # canon translation
            canon = dict(val)
            if val.get("idfv"):
                canon["android_uuid"] = val["idfv"]
            if val.get("idfa"):
                canon["gps_adid"] = val["idfa"]
            if val.get("bundle_id"):
                canon["package_name"] = val["bundle_id"]
            prof = [k for k in sorted(AK) if canon.get(k)]
            cc = "".join(canon[k] for k in prof)
            out.append(("%s/canon+pin+tail" % vname, cc + "1500000" + tk))
            out.append(("%s/canon+pin+tail+b2" % vname,
                        cc + "1500000" + tk + "ios5.8.0" + "10" + "5.0.0"))
    return [(n, c.encode("latin1")) for n, c in out if c]


def tail_variants(rec):
    dev = rec[114:130]
    return {
        "01z": b"\x01" + b"\x00" * 16,
        "02dev": bytes([rec[112]]) + dev,
        "02z": bytes([rec[112]]) + b"\x00" * 16,
        "01dev": b"\x01" + dev,
        "rec111_19": rec[111:130],
        "rec112_18": rec[112:130],
        "01z+dev": b"\x01" + b"\x00" * 16 + dev,
        "02z+dev": bytes([rec[112]]) + b"\x00" * 16 + dev,
        "02+dev10z6": bytes([rec[112]]) + b"iPhone13,2" + b"\x00" * 6,
    }


def s_slot_variants(r):
    S = r["S"]
    sec = r["second"]
    x = minstd_state(sec)
    return {
        "S_le": struct.pack("<I", S),
        "S_be": struct.pack(">I", S),
        "sec_le": struct.pack("<I", sec & 0xFFFFFFFF),
        "sec_be": struct.pack(">I", sec & 0xFFFFFFFF),
        "x_le": struct.pack("<I", x),
        "x_be": struct.pack(">I", x),
    }


def main():
    reqs = load_all()
    targets = {}
    for r in reqs:
        targets.setdefault(r["kind"], r)
    for kind, r in targets.items():
        rec = r["rec"]
        cands = claims_candidates(r)
        tails = tail_variants(rec)
        s_slots = s_slot_variants(r)
        magics = {"rec13": rec[1:3], "rec03": rec[0:3], "rec02": rec[0:2]}
        d9ins = {"zeros20": b"\x00" * 20, "empty": b""}
        n = 0
        hits = []
        for d9n, d9in in d9ins.items():
            for mn, magic in magics.items():
                for sn, s4 in s_slots.items():
                    for tn, tail in tails.items():
                        prefix = d9in + magic + rec[3:19] + s4 + sg.SHA0 + tail
                        for cn, c in cands:
                            n += 1
                            if sg.sha256_iv2(prefix + c) == r["BLOCK"]:
                                hits.append((d9n, mn, sn, tn, cn))
                            # suffix variants
                            for sfxn, sfx in (("dev16", rec[114:130]),):
                                n += 1
                                if sg.sha256_iv2(prefix + c + sfx) == \
                                        r["BLOCK"]:
                                    hits.append((d9n, mn, sn, tn, cn,
                                                 "suffix=" + sfxn))
        print("%-11s %s: %d claims x %d frames = %d -> %s"
              % (kind, r["file"], len(cands),
                 len(d9ins) * len(magics) * len(s_slots) * len(tails), n,
                 hits or "NO HIT"))
        for h in hits:
            print("   HIT:", h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
