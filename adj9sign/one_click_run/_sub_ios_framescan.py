"""_sub_ios_framescan.py — freeze claims candidates, scan the FRAME space.

Message model: D9in || MAGIC || HEAD16 || S32 || SHA0 || TAIL || claims.
Axes:
  D9in   : 20 zero bytes | empty
  MAGIC  : rec[1:3] | rec[0:2] | rec[0:3] | b'\x00\x08' | b'\x01\x00'
  HEAD16 : rec[3:19] | pairwise-swapped | byte-reversed | BE d0 words
  S32    : LE | BE
  SHA0   : fixed rec[79:111]
  TAIL   : every plausible constant/record-derived slice (15 variants)
Claims candidates per record: ~12 laws (android-names, ios-names, with/without
block2/ak/av, wire-vs-decoded values).
"""
from __future__ import annotations

import base64
import itertools
import re
import struct
import sys
import zipfile
from urllib.parse import urlsplit, unquote, unquote_plus

import adj9_signer as sg
from _sub_unseal_core import whiten_inverse

SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"


def load_one(fname):
    z = zipfile.ZipFile(SAZ)
    txt = z.read(fname).decode("latin1")
    head, _, body = txt.partition("\r\n\r\n")
    m = re.search(r'signature="([A-Za-z0-9+/=]+)"', txt)
    blob = base64.b64decode(m.group(1))
    rec = whiten_inverse(blob[16:160], blob[:16])
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
    kind = p.path.lstrip("/").replace("sdk_click", "click")
    return {"kind": kind, "dec": dec, "wire": wire, "rec": rec,
            "S": int.from_bytes(rec[20:24], "big"),
            "client_sdk": sdk.group(1) if sdk else "ios5.8.0",
            "av": avs.group(1) if avs else None,
            "BLOCK": rec[46:78]}


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
EVENT_PART = ["callback_params", "event_count", "event_token", "seq"]


def claims_candidates(r):
    val_d, val_w = r["dec"], r["wire"]
    kind = r["kind"]
    syn = {"client_sdk": r["client_sdk"], "headers_id": "10",
           "native_version": "5.0.0", "adj_verification": r["av"]}
    out = []
    for vname, val in (("dec", val_d), ("wire", val_w)):
        android = [k for k in AK if val.get(k)]
        ios = sorted([k for k in AK + IOS_EXTRA if val.get(k)])
        tail_pool = [k for k in TAILS_BY_KIND[kind] if val.get(k)]
        tail_ev = sorted(tail_pool + [k for k in EVENT_PART if val.get(k)])
        tk = tail_ev if kind == "event" else tail_pool
        for pname, keys in (("an", android), ("ios", ios)):
            c = "".join(val[k] for k in keys)
            out.append(("%s/%s" % (vname, pname), c))
            out.append(("%s/%s+pin" % (vname, pname), c + "1500000"))
            out.append(("%s/%s+pin+tail" % (vname, pname),
                        c + "1500000" + "".join(val[k] for k in tk)))
            out.append(("%s/%s+pin+tail+b2" % (vname, pname),
                        c + "1500000" + "".join(val[k] for k in tk)
                        + "ios5.8.0" + "10" + "5.0.0"))
            out.append(("%s/%s+pin+tail+akb2" % (vname, pname),
                        c + "1500000" + "".join(val[k] for k in tk)
                        + kind + "ios5.8.0" + "10" + "5.0.0"))
            out.append(("%s/av+%s+pin+tail+b2" % (vname, pname),
                        r["av"] + c + "1500000"
                        + "".join(val[k] for k in tk)
                        + "ios5.8.0" + "10" + "5.0.0"))
        # canonical-name translation: android_uuid=idfv, gps_adid=idfa,
        # package_name=bundle_id
        canon = dict(val)
        if val.get("idfv"):
            canon["android_uuid"] = val["idfv"]
        if val.get("idfa"):
            canon["gps_adid"] = val["idfa"]
        if val.get("bundle_id"):
            canon["package_name"] = val["bundle_id"]
        profile = [k for k in sorted(
            ["adj_verification", "android_uuid", "api_level", "app_token",
             "app_version", "country", "created_at", "device_name",
             "device_type", "environment", "gps_adid", "gps_adid_src",
             "hardware_name", "installed_at", "os_build", "os_name",
             "os_version", "package_name"]) if canon.get(k)]
        cc = "".join(canon[k] for k in profile)
        out.append(("%s/canon+pin+tail" % vname,
                    cc + "1500000" + "".join(canon[k] for k in tk)))
        out.append(("%s/canon+pin+tail+b2" % vname,
                    cc + "1500000" + "".join(canon[k] for k in tk)
                    + "ios5.8.0" + "10" + "5.0.0"))
    return [(n, c.encode("latin1")) for n, c in out if c]


D9INS = {"zeros20": b"\x00" * 20, "empty": b""}
MAGICS = {"rec13": None, "rec02": None, "rec03": None, "lit0008": b"\x00\x08",
          "lit0100": b"\x01\x00"}


def head16_variants(rec):
    h = rec[3:19]
    swapped = b"".join(h[i:i + 2][::-1] for i in range(0, 16, 2))
    rev = h[::-1]
    d0w = sg._d0_words(sg._d4_words(int.from_bytes(rec[20:24], "big")),
                       head=(0x40,))[:4]
    be_words = b"".join(struct.pack(">I", w) for w in d0w)
    le_words = b"".join(struct.pack("<I", w) for w in d0w)
    return {"rec": h, "swap2": swapped, "rev": rev,
            "d0be": be_words, "d0le": le_words}


def tail_variants(rec):
    dev = rec[114:130]
    dev10 = b"iPhone13,2"
    return {
        "01z": b"\x01" + b"\x00" * 16,
        "02dev": bytes([rec[112]]) + dev,
        "02z": bytes([rec[112]]) + b"\x00" * 16,
        "01dev": b"\x01" + dev,
        "02dev10": bytes([rec[112]]) + dev10,
        "01dev10": b"\x01" + dev10,
        "rec111_19": rec[111:130],
        "rec112_18": rec[112:130],
        "06dev": b"\x06" + dev,
        "07dev": b"\x07" + dev,
        "0602dev": rec[111:113] + dev,
        "dev16": dev,
        "devz16": dev[:10] + b"\x00" * 6,
        "0107dev16": b"\x01\x07" + dev,
        "0207z": b"\x02\x07" + b"\x00" * 15,
    }


def build_msg(rec, d9in, magic, head16, sbytes, tail):
    return d9in + magic + head16 + sbytes + sg.SHA0 + tail


def main():
    targets = {"session": "raw/0144_c.txt", "click": "raw/0142_c.txt",
               "attribution": "raw/0170_c.txt",
               "event": "raw/0157_c.txt"}
    for kind, fname in targets.items():
        r = load_one(fname)
        rec = r["rec"]
        S = r["S"]
        cands = claims_candidates(r)
        heads = head16_variants(rec)
        tails = tail_variants(rec)
        magics = {"rec13": rec[1:3], "rec02": rec[0:2], "rec03": rec[0:3],
                  "lit0008": b"\x00\x08", "lit0100": b"\x01\x00"}
        n = 0
        hits = []
        for d9n, d9in in D9INS.items():
            for mn, magic in magics.items():
                for hn, head16 in heads.items():
                    for sen in ("le", "be"):
                        sbytes = struct.pack("<I" if sen == "le" else ">I", S)
                        for tn, tail in tails.items():
                            prefix = build_msg(rec, d9in, magic, head16,
                                               sbytes, tail)
                            for cn, c in cands:
                                n += 1
                                if sg.sha256_iv2(prefix + c) == r["BLOCK"]:
                                    hits.append((d9n, mn, hn, sen, tn, cn,
                                                 len(c)))
        print("%-11s %s: %d claims x 300 frames = %d tests -> %s"
              % (kind, fname, len(cands), n, hits or "NO HIT"))
        for h in hits:
            print("   HIT:", h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
