"""_sub_ios_bigsearch.py — definitive claims search on one record per kind.

Space:
  frames : d9in {zeros20, empty} x senc {le, be} x tail {02dev, 01z, 02z,
           01dev}                          (16)
  claims : profile = 8 core (fixed) + 13 toggles {installed_at, avs, bundle,
           ids(idfa+idfv), att_status, fb_anon_id, last_skan_update,
           primary_dedupe_token, skadn_registered_at, av, hw(=device_name),
           track('1'), country('US')} sorted, x appv swap {body, short}
           x pinned {on after-profile, on at-end, off}
           x tail = sorted subsets of session-tail-present x track-syn
           x b2 in {[], [cs,hi,nv], [ak,cs,hi,nv], [hi,nv]}
Batched through the numpy sha256_iv2 oracle.
"""
from __future__ import annotations

import base64
import itertools
import json
import re
import struct
import sys
import time
import zipfile
from urllib.parse import urlsplit, unquote, unquote_plus

import numpy as np

import adj9_signer as sg
from _sub_unseal_core import whiten_inverse
import _sub_np_sha256 as npsh

SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
AV = "KlcAG2cbAAsKSl1KXiwSRT5bBSQZDhxXB0Mb"

CORE = ["app_token", "app_version", "created_at", "device_name",
        "device_type", "environment", "os_name", "os_version"]
TOGGLES = ["installed_at", "avs", "bundle", "ids", "att", "fb", "lskan",
           "pdt", "skadn", "av", "hw", "countryUS"]
TOGGLE_KEYS = {
    "installed_at": ["installed_at"],
    "avs": ["app_version_short"],
    "bundle": ["bundle_id"],
    "ids": ["idfa", "idfv"],
    "att": ["att_status"],
    "fb": ["fb_anon_id"],
    "lskan": ["last_skan_update"],
    "pdt": ["primary_dedupe_token"],
    "skadn": ["skadn_registered_at"],
    "av": ["adj_verification"],
    "hw": ["hardware_name"],
    "countryUS": ["country"],
}
SESSION_TAIL = ["session_count", "session_length", "subsession_count",
                "time_spent"]
CLICK_TAIL = ["session_count", "session_length", "source",
              "subsession_count", "time_spent"]
EVENT_PROF = ["callback_params", "event_count", "event_token"]
EVENT_TAIL = ["seq"]
B2S = [[], ["client_sdk", "headers_id", "native_version"],
       ["activity_kind", "client_sdk", "headers_id", "native_version"],
       ["headers_id", "native_version"]]


def load_one(fname):
    z = zipfile.ZipFile(SAZ)
    txt = z.read("raw/" + fname).decode("latin1")
    head, _, body = txt.partition("\r\n\r\n")
    blob = base64.b64decode(
        re.search(r'signature="([A-Za-z0-9+/=]+)"', txt).group(1))
    rec = whiten_inverse(blob[16:160], blob[:16])
    target = head.split("\r\n")[0].split(" ")[1]
    p = urlsplit(target)
    dec = {}
    order = []
    for kv in (p.query.split("&") if p.query else []) + body.split("&"):
        k, _, v = kv.partition("=")
        k = unquote_plus(k)
        if k not in dec:
            order.append(k)
        dec[k] = unquote(v)
    return {"kind": p.path.strip("/").replace("sdk_click", "click"),
            "val": dec, "order": order, "rec": rec,
            "S": int.from_bytes(rec[20:24], "big"), "blob": blob,
            "BLOCK": rec[46:78]}


def build_claims(val, kind, bits, appv_short, pin, b2i, tail_sel, track_syn):
    keys = list(CORE)
    for i, t in enumerate(TOGGLES):
        if not (bits >> i) & 1:
            continue
        keys += TOGGLE_KEYS[t]
    if kind == "event":
        keys += EVENT_PROF
    keys = sorted(set(keys))
    # rename hw/country to their synthesized names in sort
    def sk(k):
        return k
    prof_vals = []
    for k in keys:
        if k == "hardware_name":
            v = val.get("device_name")
        elif k == "country":
            v = "US"
        elif k == "adj_verification":
            v = AV
        elif k == "app_version" and appv_short:
            v = val.get("app_version_short") or val.get("app_version")
        elif k == "bundle_id" and not val.get("bundle_id"):
            v = None
        else:
            v = val.get(k)
        if not v:
            return None
        prof_vals.append(v)
    tl_pool = SESSION_TAIL if kind in ("session", "event") else CLICK_TAIL
    if kind == "attribution":
        tl_pool = ["tracking_enabled"]
    tl = [k for k in tl_pool if tail_sel.get(k, False)]
    if track_syn:
        if "tracking_enabled" not in tl:
            tl = tl + ["tracking_enabled"]
    if kind == "event":
        tl = tl + ([EVENT_TAIL[0]] if val.get("seq") else [])
    tl = sorted(set(tl))
    tail_vals = []
    for k in tl:
        v = val.get(k) or ("1" if k == "tracking_enabled" else None)
        if not v:
            return None
        tail_vals.append(v)
    b2 = B2S[b2i]
    b2_vals = []
    for k in b2:
        v = {"client_sdk": "ios5.8.0", "headers_id": "10",
             "native_version": "5.0.0",
             "activity_kind": kind}.get(k)
        if not v:
            return None
        b2_vals.append(v)
    seq = prof_vals + tail_vals + b2_vals
    if pin == 1:
        seq = seq + ["1500000"]
    elif pin == 0:
        seq = seq[:len(prof_vals)] + ["1500000"] + seq[len(prof_vals):]
    # pin==2 -> omitted
    return "".join(seq).encode("latin1")


def tails_for(rec):
    dev = rec[114:130]
    return {"02dev": bytes([rec[112]]) + dev,
            "01z": b"\x01" + b"\x00" * 16,
            "02z": bytes([rec[112]]) + b"\x00" * 16,
            "01dev": b"\x01" + dev}


def search(r, verbose=True):
    val = r["val"]
    kind = r["kind"]
    rec = r["rec"]
    target = np.frombuffer(r["BLOCK"], ">u4").astype(np.uint32)
    tails = tails_for(rec)
    n_tail_keys = len(SESSION_TAIL) if kind in ("session", "event") else \
        len(CLICK_TAIL)
    if kind == "attribution":
        n_tail_keys = 1
    total = 0
    t0 = time.time()
    for d9in in (b"\x00" * 20, b""):
        for senc in ("le", "be"):
            s4 = struct.pack("<I" if senc == "le" else ">I", r["S"])
            for tn, tail in tails.items():
                msg_prefix = d9in + rec[1:3] + rec[3:19] + s4 + sg.SHA0 + tail
                prefix64 = msg_prefix[:64]
                fixed = msg_prefix[64:]
                buckets = {}
                for bits in range(1 << len(TOGGLES)):
                    for appv_short in (False, True):
                        if appv_short and not val.get("app_version_short"):
                            continue
                        for pin in (0, 1, 2):
                            for b2i in range(len(B2S)):
                                for tmask in range(1 << n_tail_keys):
                                    tail_sel = {k: (tmask >> i) & 1
                                                for i, k in enumerate(
                                                    (SESSION_TAIL if
                                                     kind in ("session",
                                                              "event")
                                                     else CLICK_TAIL if
                                                     kind == "click"
                                                     else ["tracking_enabled"]))}
                                    for track in ((0, 1) if
                                                  not tail_sel.get(
                                                      "tracking_enabled")
                                                  else (0,)):
                                        c = build_claims(
                                            val, kind, bits, appv_short, pin,
                                            b2i, tail_sel, track)
                                        if c is None:
                                            continue
                                        buckets.setdefault(len(c), []).append(
                                            (c, (bits, appv_short, pin, b2i,
                                                 tmask, track)))
                for L, cands in buckets.items():
                    total_len = 64 + len(fixed) + L
                    pad = b"\x80" + b"\x00" * ((55 - total_len) % 64) + \
                        struct.pack(">Q", total_len * 8)
                    row = len(fixed) + L + len(pad)
                    n = len(cands)
                    arr = np.zeros((n, row), dtype=np.uint8)
                    arr[:, :len(fixed)] = np.frombuffer(fixed, np.uint8)
                    arr[:, row - len(pad):] = np.frombuffer(pad, np.uint8)
                    for i, (c, _m) in enumerate(cands):
                        arr[i, len(fixed):len(fixed) + L] = \
                            np.frombuffer(c, np.uint8)
                    out = npsh.batch_digests(prefix64, arr)
                    hits = np.nonzero(np.all(out == target, axis=1))[0]
                    for h in hits:
                        meta = cands[int(h)][1]
                        print("\n!!! HIT %s %s frame d9in=%s senc=%s "
                              "tail=%s meta=%s len=%d"
                              % (r["file"], kind,
                                 "zeros" if d9in else "empty", senc, tn,
                                 meta, L), flush=True)
                        return (d9in, senc, tn, meta, L)
                total += sum(len(v) for v in buckets.values())
            if verbose:
                print("  d9in=%s senc=%s done cumulative=%d (%.0f s)"
                      % ("zeros" if d9in else "empty", senc, total,
                         time.time() - t0), flush=True)
    print("[bigsearch] %s: NO HIT (%d candidates)" % (kind, total))
    return None


def main():
    targets = {"session": "0144_c.txt", "click": "0142_c.txt",
               "attribution": "0170_c.txt", "event": "0157_c.txt"}
    kinds = sys.argv[1:] or ["session"]
    for k in kinds:
        r = load_one(targets[k])
        hit = search(r)
        if hit:
            with open("_sub_ios_bigsearch_hit.json", "w") as f:
                json.dump({"kind": k, "hit": [x if not isinstance(x, bytes)
                                              else "zeros20/empty"
                                              for x in hit[:3]] +
                           [list(hit[3]), hit[4]]}, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
