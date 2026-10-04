"""_sub_ios_claims_quick.py — quick one-off claims hypotheses (wire order,
minimal laws) against the record BLOCK, all tail x S-enc frames."""
from __future__ import annotations

import base64
import os
import re
import struct
import sys
import zipfile
from urllib.parse import urlsplit, unquote_plus, unquote_to_bytes

import adj9_signer as sg
from _sub_unseal_core import whiten_inverse

HERE = os.path.dirname(os.path.abspath(__file__))
SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"


def parse_pairs_ordered(raw):
    d = {}
    for kv in raw.split("&"):
        if not kv:
            continue
        k, _, v = kv.partition("=")
        k = unquote_plus(k)
        d[k] = unquote_to_bytes(v).decode("latin1")
    return d


def load_requests():
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
        target = head.split("\r\n")[0].split(" ")[1]
        p = urlsplit(target)
        val = parse_pairs_ordered(p.query)
        val.update(parse_pairs_ordered(body))
        wire_order = [kv.partition("=")[0] for kv in
                      (p.query.split("&") if p.query else [])]
        wire_order += [kv.partition("=")[0] for kv in body.split("&") if kv]
        sdk = re.search(r"(?im)^Client-Sdk:\s*(\S+)", head)
        avs = re.search(r'adj_verification="([A-Za-z0-9+/=]+)"', head)
        out.append({
            "file": os.path.basename(name),
            "kind": p.path.lstrip("/").replace("sdk_click", "click"),
            "client_sdk": sdk.group(1) if sdk else None,
            "adj_verification": avs.group(1) if avs else None,
            "val": val,
            "wire_order": wire_order,
            "blob": blob,
        })
    return out


TAIL_MODES = {
    "const01z": lambda rec: b"\x01" + b"\x00" * 16,
    "recvar_dev": lambda rec: bytes([rec[112]]) + rec[114:130],
    "recvar_z": lambda rec: bytes([rec[112]]) + b"\x00" * 16,
    "const01_dev": lambda rec: b"\x01" + rec[114:130],
    "recvar_dev10": lambda rec: bytes([rec[112]]) + b"iPhone13,2",
}


def block_of(r, claims, tail17, s_enc):
    if isinstance(claims, str):
        claims = claims.encode("latin1")
    S = r["S"]
    sbytes = struct.pack("<I" if s_enc == "le" else ">I", S & 0xFFFFFFFF)
    rec = r["rec"]
    msg = rec[25:45] + rec[1:3] + rec[3:19] + sbytes + sg.SHA0 + tail17 \
        + claims
    return sg.sha256_iv2(msg)


def main():
    reqs = load_requests()
    for r in reqs:
        rec = whiten_inverse(r["blob"][16:160], r["blob"][:16])
        r["rec"] = rec
        r["S"] = int.from_bytes(rec[20:24], "big")
        r["BLOCK"] = rec[46:78]

    by_kind = {}
    for r in reqs:
        by_kind.setdefault(r["kind"], []).append(r)

    # per-kind single target record for the quick pass
    for kind in ("session", "click", "attribution", "event"):
        r = by_kind[kind][0]
        val = r["val"]
        syn = {"client_sdk": r["client_sdk"], "headers_id": "10",
               "native_version": "5.0.0",
               "adj_verification": r["adj_verification"]}
        cands = []

        # 1. wire-order: all body values, then with pinned at several spots
        wo = r["wire_order"]
        cands.append(("wire_all", "".join(val[k] for k in wo if val.get(k))))
        cands.append(("wire_all+pinned_end",
                      "".join(val[k] for k in wo if val.get(k)) + "1500000"))
        cands.append(("wire_all+pinned_start",
                      "1500000" + "".join(val[k] for k in wo if val.get(k))))
        # 2. sorted all incl synthesized
        m = dict(val); m["adj_signing_id"] = "1500000"
        m.update({k: v for k, v in syn.items() if v})
        cands.append(("sorted_all_synth",
                      "".join(m[k] for k in sorted(m) if m[k])))
        del m["adj_signing_id"]
        cands.append(("sorted_all_synth_nopin",
                      "".join(m[k] for k in sorted(m) if m[k])))
        # 3. minimal laws
        core = ["app_token", "app_version", "bundle_id", "created_at",
                "device_name", "device_type", "environment", "idfa", "idfv",
                "installed_at", "os_name", "os_version"]
        present = [k for k in core if val.get(k)]
        cands.append(("core_only", "".join(val[k] for k in present)))
        cands.append(("core+pin",
                      "".join(val[k] for k in present) + "1500000"))
        tails = {
            "session": ["session_count", "session_length",
                        "subsession_count", "time_spent"],
            "click": ["session_count", "session_length", "source",
                      "subsession_count", "time_spent"],
            "attribution": ["tracking_enabled"],
            "event": ["callback_params", "event_count", "event_token",
                      "seq", "session_count", "session_length",
                      "subsession_count", "time_spent"],
        }
        tk = [k for k in tails[kind] if val.get(k)]
        cands.append(("core+pin+tail",
                      "".join(val[k] for k in present) + "1500000"
                      + "".join(val[k] for k in tk)))
        cands.append(("core+pin+tail+b2",
                      "".join(val[k] for k in present) + "1500000"
                      + "".join(val[k] for k in tk)
                      + syn["client_sdk"] + "10" + "5.0.0"))
        cands.append(("av+core+pin+tail+b2",
                      syn["adj_verification"]
                      + "".join(val[k] for k in present) + "1500000"
                      + "".join(val[k] for k in tk)
                      + syn["client_sdk"] + "10" + "5.0.0"))
        # 4. android-names-only law (no ios-named keys)
        ak = [k for k in ["app_token", "app_version", "created_at",
                          "device_name", "device_type", "environment",
                          "installed_at", "os_name", "os_version"]
              if val.get(k)]
        tk2 = [k for k in tails[kind] if val.get(k)]
        cands.append(("androidnames+pin+tail",
                      "".join(val[k] for k in ak) + "1500000"
                      + "".join(val[k] for k in tk2)))
        cands.append(("androidnames+pin+tail+b2",
                      "".join(val[k] for k in ak) + "1500000"
                      + "".join(val[k] for k in tk2)
                      + syn["client_sdk"] + "10" + "5.0.0"))
        cands.append(("av+androidnames+pin+tail+b2",
                      syn["adj_verification"]
                      + "".join(val[k] for k in ak) + "1500000"
                      + "".join(val[k] for k in tk2)
                      + syn["client_sdk"] + "10" + "5.0.0"))

        print("=== %s %s: %d candidates x %d tails x 2 senc"
              % (kind, r["file"], len(cands), len(TAIL_MODES)))
        for cname, c in cands:
            for tname, tf in TAIL_MODES.items():
                t17 = tf(r["rec"])
                for se in ("le", "be"):
                    if block_of(r, c, t17, se) == r["BLOCK"]:
                        print("   !!! HIT: %s tail=%s s=%s len=%d"
                              % (cname, tname, se, len(c)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
