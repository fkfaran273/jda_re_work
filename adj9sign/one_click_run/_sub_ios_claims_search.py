"""_sub_ios_claims_search.py — find the iOS claims law via BLOCK equality.

BLOCK = sha256_iv2(D9 || 00 08 || head16 || S32 || SHA256("") || TAIL17 ||
claims).  D9 = 20 zero bytes (iOS); head16/S from the record; TAIL17 and the
claims composition are the unknowns.

Phase 1: cheap high-priority hypotheses (presence-filter law with/without
header-derived keys, all-params-sorted, ...) x 4 TAIL17 modes x 2 S encodings.
"""
from __future__ import annotations

import base64
import itertools
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

PINNED = "adj_signing_id"
PINNED_V = "1500000"


def parse_pairs(raw):
    d = {}
    for kv in raw.split("&"):
        if not kv:
            continue
        k, _, v = kv.partition("=")
        d[unquote_plus(k)] = unquote_to_bytes(v).decode("latin1")
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
        val = parse_pairs(p.query)
        val.update(parse_pairs(body))
        sdk = re.search(r"(?im)^Client-Sdk:\s*(\S+)", head)
        avs = re.search(r'adj_verification="([A-Za-z0-9+/=]+)"', head)
        out.append({
            "file": os.path.basename(name),
            "path": p.path,
            "kind": p.path.lstrip("/").replace("sdk_click", "click"),
            "client_sdk": sdk.group(1) if sdk else None,
            "adj_verification": avs.group(1) if avs else None,
            "val": val,
            "blob": blob,
        })
    return out


# ------------------------------------------------------------ claims laws
PROFILE_IOS = ["adj_verification", "app_token", "app_version",
               "app_version_short", "bundle_id", "created_at", "device_name",
               "device_type", "environment", "idfa", "idfv", "installed_at",
               "os_name", "os_version"]
SESSION_TAIL = ["session_count", "session_length", "subsession_count",
                "time_spent"]
CLICK_TAIL = ["session_count", "session_length", "source",
              "subsession_count", "time_spent"]
ATTR_TAIL = ["tracking_enabled"]
EVENT_TAIL_SORTED = ["callback_params", "event_count", "event_token", "seq",
                     "session_count", "session_length", "subsession_count",
                     "time_spent"]
EVENT_TAIL_HINT = ["session_count", "session_length", "subsession_count",
                   "time_spent", "event_token", "callback_params", "seq",
                   "event_count"]
EVENT_TAIL_HINT2 = ["event_token", "callback_params", "seq", "event_count",
                    "session_count", "session_length", "subsession_count",
                    "time_spent"]

TAILS = {
    "session": SESSION_TAIL,
    "click": CLICK_TAIL,
    "attribution": ATTR_TAIL,
    "event": EVENT_TAIL_SORTED,
}
TAIL_ALTS = {"event": {"hint": EVENT_TAIL_HINT, "hint2": EVENT_TAIL_HINT2}}


def law_presence(val, kind, tail_keys, opts):
    """Android-shape presence law with toggles:
    opts: dict with keys av, b2, pinned, bundle_sort, tail_name"""
    prof = [k for k in PROFILE_IOS if val.get(k) and opts.get("prof", True)]
    if not opts.get("av", False):
        prof = [k for k in prof if k != "adj_verification"]
    if not opts.get("idfa", True):
        prof = [k for k in prof if k not in ("idfa", "idfv")]
    if opts.get("drop_installed"):
        prof = [k for k in prof if k != "installed_at"]
    bsort = opts.get("bundle_sort", "bundle_id")
    # rename for sorting only
    sname = {k: ("package_name" if (k == "bundle_id" and bsort == "package_name")
                 else k) for k in prof}
    prof_sorted = sorted(prof, key=lambda k: sname[k])
    keys = prof_sorted
    if opts.get("pinned", True):
        keys = keys + [PINNED]
    keys += [k for k in tail_keys if val.get(k)]
    if opts.get("b2", False):
        keys += [k for k in ("activity_kind", "client_sdk", "headers_id",
                             "native_version")
                 if (val.get(k) or k == "activity_kind"
                     and opts.get("activity_kind")
                     or opts.get(k))]
    # value lookup: body first, then synthesized
    syn = dict(opts.get("syn", {}))
    parts = []
    for k in keys:
        v = val.get(k) or syn.get(k)
        if k == PINNED:
            v = PINNED_V
        if not v:
            return None
        parts.append(v)
    return "".join(parts).encode("latin1")


def law_all_sorted(val, kind, opts):
    """Every present param value, sorted by key; synthesized keys optionally
    merged in."""
    m = dict(val)
    syn = dict(opts.get("syn", {}))
    if opts.get("pinned", True):
        m[PINNED] = PINNED_V
    if opts.get("av", False):
        m.setdefault("adj_verification", syn.get("adj_verification"))
    if opts.get("b2", False):
        m.setdefault("client_sdk", syn.get("client_sdk"))
        m.setdefault("headers_id", syn.get("headers_id"))
        m.setdefault("native_version", syn.get("native_version"))
    if opts.get("activity_kind"):
        m.setdefault("activity_kind", kind)
    m = {k: v for k, v in m.items() if v}
    return "".join(m[k] for k in sorted(m)).encode("latin1")


# ---------------------------------------------------------------- runner
TAIL_MODES = {
    "const01z": lambda rec: b"\x01" + b"\x00" * 16,
    "recvar_dev": lambda rec: bytes([rec[112]]) + rec[114:130],
    "recvar_z": lambda rec: bytes([rec[112]]) + b"\x00" * 16,
    "const01_dev": lambda rec: b"\x01" + rec[114:130],
}


def iv2_rest(rest):
    total = 64 + len(rest)
    m = rest + b"\x80" + b"\x00" * ((55 - total) % 64) \
        + struct.pack(">Q", total * 8)
    st = None
    return m


def block_of(r, claims, tail17, s_enc):
    S = r["S"]
    sbytes = struct.pack("<I" if s_enc == "le" else ">I", S & 0xFFFFFFFF)
    rec = r["rec"]
    msg = rec[25:45] + rec[1:3] + rec[3:19] + sbytes + sg.SHA0 + tail17 \
        + claims
    return sg.sha256_iv2(msg)


def hypotheses(r):
    """(name, claims_bytes) candidates for one record."""
    kind = r["kind"]
    val = r["val"]
    syn = {"client_sdk": r["client_sdk"],
           "headers_id": "10",
           "native_version": "5.0.0",
           "adj_verification": r["adj_verification"]}
    out = []
    tail_names = ["sorted"] + list(TAIL_ALTS.get(kind, {}))
    for tname in tail_names:
        tkeys = TAILS[kind] if tname == "sorted" else TAIL_ALTS[kind][tname]
        for av in (False, True):
            for b2 in (False, True):
                for ak in (False, True):
                    if ak and not b2:
                        continue
                    for pinned in (True, False):
                        for bsort in ("bundle_id", "package_name"):
                            opts = {"av": av, "b2": b2,
                                    "activity_kind": ak,
                                    "pinned": pinned,
                                    "bundle_sort": bsort,
                                    "syn": syn}
                            c = law_presence(val, kind, tkeys, opts)
                            if c:
                                out.append((
                                    "presence[%s av=%d b2=%d ak=%d pin=%d "
                                    "bs=%s]" % (tname, av, b2, ak, pinned,
                                                bsort), c))
                        for av2 in (False,):
                            pass
        # all-sorted variants
        for av in (False, True):
            for b2 in (False, True):
                for ak in (False, True):
                    for pinned in (True, False):
                        opts = {"av": av, "b2": b2, "activity_kind": ak,
                                "pinned": pinned, "syn": syn}
                        c = law_all_sorted(val, kind, opts)
                        if c:
                            out.append(("allsorted av=%d b2=%d ak=%d pin=%d"
                                        % (av, b2, ak, pinned), c))
    return out


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
    targets = {k: v[0] for k, v in by_kind.items()}

    for kind, r in targets.items():
        print("\n=== kind %-11s record %s  S=%u ===" % (kind, r["file"], r["S"]))
        cands = hypotheses(r)
        print("   %d composition hypotheses x %d tails x 2 S-enc ..."
              % (len(cands), len(TAIL_MODES)))
        n = 0
        found = []
        for tname, tf in TAIL_MODES.items():
            tail17 = tf(r["rec"])
            for s_enc in ("le", "be"):
                for name, c in cands:
                    n += 1
                    if block_of(r, c, tail17, s_enc) == r["BLOCK"]:
                        found.append((name, tname, s_enc, len(c)))
        print("   tested %d -> hits: %s" % (n, found or "NONE"))
        for f in found:
            print("   HIT:", f)

    return 0


if __name__ == "__main__":
    sys.exit(main())
