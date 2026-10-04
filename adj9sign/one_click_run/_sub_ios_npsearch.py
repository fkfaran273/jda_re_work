"""_sub_ios_npsearch.py — exhaustive structured search for the iOS claims law.

For each kind (session/click/attribution/event) search one representative
record over:
  frames    : d9in {zeros20, empty} x S-encoding {le, be} x 7 TAIL variants
  claims    : profile (core8 + installed_at toggle + optional adds, sorted
              with name aliases) [+ pinned at after_profile|end] + tail part
              (presence subsets) + block2 (subsets of client_sdk/headers_id/
              native_version [+ activity_kind])
Hashing via numpy-vectorized sha256_iv2 (_sub_np_sha256), batched.

On a hit: verify the winning hypothesis on EVERY record of that kind.
"""
from __future__ import annotations

import base64
import itertools
import json
import multiprocessing as mp
import os
import re
import struct
import sys
import time
import zipfile
from urllib.parse import urlsplit, unquote_plus, unquote_to_bytes

import numpy as np

import adj9_signer as sg
from _sub_unseal_core import whiten_inverse
import _sub_np_sha256 as npsh

HERE = os.path.dirname(os.path.abspath(__file__))
SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"

CORE = ["app_token", "app_version", "created_at", "device_name",
        "device_type", "environment", "os_name", "os_version"]
INST = "installed_at"
ADD_NAMES = ["avs", "bundle", "ids", "av", "hw", "sent", "started"]
ADD_KEYS = {"avs": ["app_version_short"], "bundle": ["bundle_id"],
            "ids": ["idfa", "idfv"], "av": ["adj_verification"],
            "hw": ["hardware_name"], "sent": ["sent_at"],
            "started": ["started_at"]}
TAIL_POOLS = {
    "session": ["session_count", "session_length", "subsession_count",
                "time_spent"],
    "click": ["session_count", "session_length", "source",
              "subsession_count", "time_spent"],
    "attribution": [],
    "event": None,           # special
}
EVENT_PART = ["callback_params", "event_count", "event_token", "seq"]
BLOCK2 = ["client_sdk", "headers_id", "native_version"]

TAILS = [
    ("const01z", lambda rec: b"\x01" + b"\x00" * 16),
    ("recvar_dev", lambda rec: bytes([rec[112]]) + rec[114:130]),
    ("recvar_z", lambda rec: bytes([rec[112]]) + b"\x00" * 16),
    ("const01_dev", lambda rec: b"\x01" + rec[114:130]),
    ("recvar_dev10", lambda rec: bytes([rec[112]]) + b"iPhone13,2"),
    ("rec111_19", lambda rec: rec[111:130]),
    ("rec112_18", lambda rec: rec[112:130]),
]


def parse_pairs_ordered(raw):
    d = {}
    order = []
    for kv in raw.split("&"):
        if not kv:
            continue
        k, _, v = kv.partition("=")
        k = unquote_plus(k)
        if k not in d:
            order.append(k)
        d[k] = unquote_to_bytes(v).decode("latin1")
    return d, order


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
        q, qo = parse_pairs_ordered(p.query)
        b, bo = parse_pairs_ordered(body)
        val = dict(q)
        val.update(b)
        sdk = re.search(r"(?im)^Client-Sdk:\s*(\S+)", head)
        avs = re.search(r'adj_verification="([A-Za-z0-9+/=]+)"', head)
        out.append({
            "file": os.path.basename(name),
            "kind": p.path.lstrip("/").replace("sdk_click", "click"),
            "client_sdk": sdk.group(1) if sdk else None,
            "adj_verification": avs.group(1) if avs else None,
            "val": val,
            "wire_order": qo + bo,
            "blob": blob,
        })
    return out


def prepare(r):
    rec = whiten_inverse(r["blob"][16:160], r["blob"][:16])
    r["rec"] = rec
    r["S"] = int.from_bytes(rec[20:24], "big")
    r["BLOCK"] = rec[46:78]
    return r


# ------------------------------------------------------------ compositions
def sort_key_factory(alias_bundle, alias_idfv):
    ren = {"bundle_id": alias_bundle, "idfv": alias_idfv}
    return lambda k: ren.get(k, k)


def profile_keys(val, kind, inst_in, adds, alias_b, alias_ivf):
    keys = list(CORE)
    if inst_in:
        keys.append(INST)
    if kind == "attribution":
        # android drops installed_at for attribution; the toggle covers it
        pass
    for name in ADD_NAMES:
        if adds.get(name):
            keys += ADD_KEYS[name]
    sk = sort_key_factory(alias_b, alias_ivf)
    present = []
    for k in keys:
        v = val.get(k)
        if v:
            present.append(k)
        elif k == "hardware_name" and adds.get("hw") and val.get("device_name"):
            present.append(k)          # synthesized value
        elif k == "adj_verification" and adds.get("av"):
            present.append(k)
    present.sort(key=sk)
    return present


def tail_keys(val, kind, tail_variant, track_syn):
    """returns ordered tail key list for this record"""
    if kind == "event":
        s_keys = [k for k in ["session_count", "session_length",
                              "subsession_count", "time_spent"]
                  if val.get(k)]
        e_keys = [k for k in EVENT_PART if val.get(k)]
        if tail_variant == "all":
            e_sel = list(e_keys)
        else:  # 'all-minus-i'
            i = int(tail_variant.split("-")[1])
            e_sel = [k for j, k in enumerate(e_keys) if j != i]
        return ("merged_sorted", s_keys, e_sel)
    pool = TAIL_POOLS[kind]
    keys = [k for k in pool if val.get(k)]
    if tail_variant == "all":
        sel = list(keys)
    elif tail_variant == "all+track":
        sel = list(keys) + (["tracking_enabled"] if track_syn else [])
    else:  # 'minus-i'
        i = int(tail_variant.split("-")[1])
        sel = [k for j, k in enumerate(keys) if j != i]
    return ("sorted", sel, [])


def tail_variants(kind):
    if kind == "event":
        return ["all"] + ["minus-%d" % i for i in range(4)]
    pool = TAIL_POOLS[kind]
    vs = ["all"] + ["minus-%d" % i for i in range(len(pool))]
    if kind in ("session", "click"):
        vs += ["all+track"]
    return vs


def build_claims(val, kind, syn, inst_in, adds, alias_b, alias_ivf,
                 pinned, pin_pos, b2_sel, ak, tvar, track_syn):
    p_keys = profile_keys(val, kind, inst_in, adds, alias_b, alias_ivf)
    parts = []
    for k in p_keys:
        v = val.get(k)
        if not v and k == "hardware_name":
            v = val.get("device_name")
        if not v and k == "adj_verification":
            v = syn["adj_verification"]
        if not v:
            return None
        parts.append(v)
    mode, s_sel, e_sel = tail_keys(val, kind, tvar, track_syn)
    tail_parts = []
    if mode == "merged_sorted":
        merged = sorted(s_sel + e_sel)
        for k in merged:
            v = val.get(k) or ("1" if (k == "tracking_enabled" and track_syn)
                               else None)
            if not v:
                return None
            tail_parts.append(v)
    else:
        for k in s_sel:
            v = val.get(k) or ("1" if (k == "tracking_enabled" and track_syn)
                               else None)
            if not v:
                return None
            tail_parts.append(v)
        for k in e_sel:
            v = val.get(k)
            if not v:
                return None
            tail_parts.append(v)
    pinned_v = "1500000" if pinned else None
    b2_parts = []
    order = (["activity_kind"] if ak else []) + \
            [k for k in BLOCK2 if k in b2_sel]
    for k in order:
        v = kind if k == "activity_kind" else syn[k]
        if not v:
            return None
        b2_parts.append(v)
    if pin_pos == "after_profile":
        seq = parts + ([pinned_v] if pinned else []) + tail_parts + b2_parts
    else:  # end
        seq = parts + tail_parts + b2_parts + ([pinned_v] if pinned else [])
    if not seq:
        return None
    return "".join(seq).encode("latin1")


# ------------------------------------------------------------------ frames
def frame_msg_parts(r, d9in, senc, tname):
    rec = r["rec"]
    tail = TAILS[[t[0] for t in TAILS].index(tname)][1](rec)
    sbytes = struct.pack("<I" if senc == "le" else ">I", r["S"])
    head = d9in + rec[1:3] + rec[3:19] + sbytes + sg.SHA0
    return head, tail


def search_record(r, verbose=True):
    val = r["val"]
    kind = r["kind"]
    syn = {"client_sdk": r["client_sdk"], "headers_id": "10",
           "native_version": "5.0.0",
           "adj_verification": r["adj_verification"]}
    target_words = np.frombuffer(r["BLOCK"], ">u4").astype(np.uint32)

    inst_opts = [True, False] if kind == "attribution" else [True]
    add_opts = []
    n_add = len(ADD_NAMES) + (1 if kind == "attribution" else 0)
    add_names = ADD_NAMES + (["init"] if kind == "attribution" else [])
    if kind == "attribution":
        ADD_KEYS["init"] = ["initiated_by"]
    for bits in itertools.product([0, 1], repeat=n_add):
        add_opts.append(dict(zip(add_names, map(bool, bits))))
    b2_opts = []
    for n in range(len(BLOCK2) + 1):
        for sub in itertools.combinations(BLOCK2, n):
            b2_opts.append(set(sub))
    b2_opts_all = [(b2, ak) for b2 in b2_opts for ak in (False, True)]

    tvars = tail_variants(kind)
    total = 0
    t_start = time.time()
    for d9in in (b"\x00" * 20, b""):
        for senc in ("le", "be"):
            for tname, _ in TAILS:
                head, tail = frame_msg_parts(r, d9in, senc, tname)
                msg_prefix = head + tail          # constant up to claims
                prefix64 = msg_prefix[:64]
                fixed = msg_prefix[64:]           # msg[64:claims_start]
                # composition loop, bucketed by claims length
                buckets = {}
                for inst_in in inst_opts:
                    for adds in add_opts:
                        for alias_b in ("bundle_id", "package_name"):
                            if not adds.get("bundle") and \
                                    alias_b != "bundle_id":
                                continue
                            for alias_ivf in ("idfv", "android_uuid"):
                                if not adds.get("ids") and \
                                        alias_ivf != "idfv":
                                    continue
                                for pinned in (True, False):
                                    for pin_pos in ("after_profile", "end"):
                                        if not pinned and \
                                                pin_pos != "after_profile":
                                            continue
                                        for b2, ak in b2_opts_all:
                                            for tvar in tvars:
                                                for track in ((False, True)
                                                              if "track"
                                                              in tvar else
                                                              (False,)):
                                                    c = build_claims(
                                                        val, kind, syn,
                                                        inst_in, adds,
                                                        alias_b, alias_ivf,
                                                        pinned, pin_pos, b2,
                                                        ak, tvar, track)
                                                    if c is None:
                                                        continue
                                                    buckets.setdefault(
                                                        len(c), []).append(
                                                        (c, (inst_in, adds,
                                                             alias_b,
                                                             alias_ivf,
                                                             pinned,
                                                             pin_pos, b2, ak,
                                                             tvar, track)))
                # hash each bucket
                for L, cands in buckets.items():
                    rest_fixed = fixed
                    total_len = 64 + len(rest_fixed) + L
                    padded_tail = b"\x80" + b"\x00" * \
                        ((55 - total_len) % 64) + \
                        struct.pack(">Q", total_len * 8)
                    row_len = len(rest_fixed) + L + len(padded_tail)
                    assert row_len % 64 == 0
                    n = len(cands)
                    arr = np.zeros((n, row_len), dtype=np.uint8)
                    fx = np.frombuffer(rest_fixed, np.uint8)
                    arr[:, :len(rest_fixed)] = fx
                    pt = np.frombuffer(padded_tail, np.uint8)
                    arr[:, row_len - len(padded_tail):] = pt
                    for i, (c, _meta) in enumerate(cands):
                        arr[i, len(rest_fixed):len(rest_fixed) + L] = \
                            np.frombuffer(c, np.uint8)
                    out = npsh.batch_digests(prefix64, arr)
                    hits = np.nonzero(np.all(out == target_words, axis=1))[0]
                    for h in hits:
                        meta = cands[int(h)][1]
                        print("\n!!! HIT kind=%s record=%s frame d9in=%s "
                              "senc=%s tail=%s" % (kind, r["file"],
                                                   "zeros" if d9in else
                                                   "empty", senc, tname))
                        print("    composition: inst=%s adds=%s alias_b=%s "
                              "alias_ivf=%s pinned=%s pin_pos=%s b2=%s ak=%s "
                              "tvar=%s track=%s claims_len=%d"
                              % meta + (L,))
                        return (d9in, senc, tname, meta, L)
                total += sum(len(v) for v in buckets.values())
                if verbose:
                    print("   frame d9in=%s senc=%s tail=%-12s done "
                          "(%d total, %.0f s)"
                          % ("zeros" if d9in else "empty", senc, tname,
                             total, time.time() - t_start), flush=True)
    return None


def verify_kind(reqs, kind, hit):
    d9in, senc, tname, meta, L = hit
    (inst_in, adds, alias_b, alias_ivf, pinned, pin_pos, b2, ak, tvar,
     track) = meta
    ok = 0
    n = 0
    for r in reqs:
        if r["kind"] != kind:
            continue
        n += 1
        val = r["val"]
        syn = {"client_sdk": r["client_sdk"], "headers_id": "10",
               "native_version": "5.0.0",
               "adj_verification": r["adj_verification"]}
        c = build_claims(val, kind, syn, inst_in, adds, alias_b, alias_ivf,
                         pinned, pin_pos, b2, ak, tvar, track)
        if c is None:
            continue
        head, tail = frame_msg_parts(r, d9in, senc, tname)
        msg = head + tail + c
        if sg.sha256_iv2(msg) == r["BLOCK"]:
            ok += 1
    return ok, n


def worker(args):
    kind, reqs = args
    r = [x for x in reqs if x["kind"] == kind][0]
    hit = search_record(r)
    if hit is None:
        return (kind, None)
    ok, n = verify_kind(reqs, kind, hit)
    return (kind, hit, ok, n)


def main():
    reqs = load_requests()
    for r in reqs:
        prepare(r)
    kinds = ["session", "click", "attribution", "event"]
    if len(sys.argv) > 1:
        kinds = sys.argv[1:]
    if len(kinds) == 1:
        res = worker((kinds[0], reqs))
        print(res)
        return 0
    with mp.Pool(len(kinds)) as pool:
        for res in pool.imap_unordered(worker, [(k, reqs) for k in kinds]):
            kind = res[0]
            if res[1] is None:
                print("[RESULT] %-11s NO HIT" % kind, flush=True)
            else:
                print("[RESULT] %-11s HIT %s  verify %d/%d"
                      % (kind, str(res[1])[:200], res[2], res[3]),
                      flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
