"""_sub_ios_claims2_oracle.py — BLOCK-oracle harness for the iOS claims hunt.

Loads the 30 signed Cainiao iOS requests, unseals the records, and batch-tests
claims-string candidates against the BLOCK commitment

    rec[46:78] == sha256_iv2(D9 || 00 08 || head16 || LE32(S) || sha256("")
                             || variant(02) || device_field(16) || claims)

using the validated numpy batch hash (_sub_np_sha256).

NEW structural knowledge baked in (from the Adjust iOS SDK v5.8.0 source,
public repo): the native signer input is

    mergedParameters = activityPackage.parameters + sendingParameters
                       (= the wire body params, minus exceptionKeys)
    extraParams      = {client_sdk: <Client-Sdk header>,
                        activity_kind: <"session"|"click"|"event"|"attribution">,
                        endpoint: <base url, e.g. "https://consent.adjust.io">}
                       + control_params (empty in this capture)

so the claims key pool is the wire params PLUS "endpoint" — a key no earlier
candidate ever carried.  The endpoint value for each request is observable:
"https://" + the request's Host header (the SDK signs the base URL it is
about to use).
"""
import base64
import hashlib
import json
import os
import re
import struct
import sys
import zipfile

import numpy as np
from urllib.parse import urlsplit, unquote_to_bytes, unquote_plus

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_signer as sg
import _sub_np_sha256 as npsha
from _sub_unseal_core import whiten_inverse

SAZ = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"

ADJ_SIGNING_ID = "1500000"
CLIENT_SDK = "ios5.8.0"
HEADERS_ID = "10"
NATIVE_VERSION = "5.0.0"
SHA0 = hashlib.sha256(b"").digest()


# ----------------------------------------------------------------------
# corpus
# ----------------------------------------------------------------------
def load_corpus():
    """The 30 signed requests with params, kind, host, unsealed record."""
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
        host = re.search(r"^Host: ([^\r\n]+)", head, re.M).group(1)
        p = urlsplit(head.split("\r\n")[0].split(" ")[1])
        val = {}
        for kv in (p.query.split("&") if p.query else []) + body.split("&"):
            k, _, v = kv.partition("=")
            k2 = unquote_plus(k)
            v2 = unquote_to_bytes(unquote_plus(v)).decode("latin1")
            if k2 in val and val[k2] != v2:
                raise ValueError("dup key %r" % k2)
            val[k2] = v2
        out.append({
            "file": os.path.basename(name),
            "sid": os.path.basename(name).split("_")[0],
            "kind": p.path.strip("/").replace("sdk_click", "click"),
            "host": host,
            "val": val,
            "blob": blob,
            "rec": whiten_inverse(blob[16:160], blob[:16]),
        })
    for r in out:
        rec = r["rec"]
        r["S"] = int.from_bytes(rec[20:24], "big")
        r["head16"] = rec[3:19]
        r["block"] = rec[46:78]
        r["dev"] = rec[114:130]
    return out


# ----------------------------------------------------------------------
# oracle — batch sha256_iv2 over the fixed frame prefix
# ----------------------------------------------------------------------
def frame_prefix64(rec):
    """First 64 bytes of the block message for one record."""
    msg_head = (b"\x00" * 20 + b"\x00\x08" + rec["head16"]
                + struct.pack("<I", rec["S"]) + SHA0)
    assert len(msg_head) == 74
    return msg_head[:64], msg_head[64:]


def oracle_batch(rec, claims_list):
    """claims_list: list[bytes] -> np.bool_ array (block match)."""
    pref, rest0 = frame_prefix64(rec)
    target = np.frombuffer(rec["block"], ">u4").astype(np.uint32)
    claims_list = [bytes(c) if isinstance(c, str) else c for c in claims_list]
    L0 = 74 + 17            # fixed bytes before the claims
    rows = []
    for c in claims_list:
        total = L0 + len(c)
        tail = rest0 + bytes([0x02]) + rec["dev"] + c
        tail = tail + b"\x80" + b"\x00" * ((55 - total) % 64) \
            + struct.pack(">Q", total * 8)
        rows.append(np.frombuffer(tail, np.uint8))
    T = max(len(r) for r in rows)
    if T % 64:
        T += 64 - T % 64
    rests = np.zeros((len(rows), T), dtype=np.uint8)
    for i, r in enumerate(rows):
        rests[i, :len(r)] = r
    words = npsha.batch_digests(pref, rests)
    return (words == target).all(axis=1)


def oracle_single(rec, claims):
    return bool(oracle_batch(rec, [claims])[0])


# ----------------------------------------------------------------------
# claims builders
# ----------------------------------------------------------------------
KIND_STR = {"session": "session", "click": "click", "event": "event",
            "attribution": "attribution"}


def block2(kind_str, client_sdk=CLIENT_SDK):
    return kind_str + client_sdk + HEADERS_ID + NATIVE_VERSION


def build_claims(val, profile_keys, tail_keys, kind_str,
                 pinned=ADJ_SIGNING_ID, pinned_first=False):
    """desc10-style: sorted present profile values || pinned || sorted present
    tail values || BLOCK2(kind, client_sdk, 10, 5.0.0)."""
    parts = []
    for k in sorted(profile_keys):
        v = val.get(k)
        if v:
            parts.append(v)
    if pinned:
        if pinned_first:
            parts.insert(0, pinned)
        else:
            parts.append(pinned)
    for k in sorted(tail_keys):
        v = val.get(k)
        if v:
            parts.append(v)
    parts.append(block2(kind_str))
    return "".join(parts).encode("latin1")


# ----------------------------------------------------------------------
# self-validation on the Android gold vectors
# ----------------------------------------------------------------------
def validate_on_android_golds():
    """The same frame/oracle code must reproduce the 9 Android gold blocks."""
    ok = 0
    for g in sg.GOLD_VECTORS:
        # reconstruct the record fields from the gold blob
        blob = bytes.fromhex(g["blob_hex"])
        recb = whiten_inverse(blob[16:160], blob[:16])
        S = int.from_bytes(recb[20:24], "big")
        r = {"S": S, "head16": recb[3:19], "block": recb[46:78],
             "dev": recb[114:130]}
        claims = sg.build_claims(g["map"], g["kind"], signing_id="1500000")
        if g["kind"] == "event":
            # proven event law: extras in profile, seq in tail
            val = dict(g["map"])
            prof = [k for k in sg.PROFILE + ["event_count", "event_token",
                                             "partner_params"] if val.get(k)]
            tail = [k for k in sg.SESSION_TAIL + ["seq"] if val.get(k)]
            parts = [val[k] for k in sorted(prof)] + ["1500000"] \
                + [val[k] for k in sorted(tail)] + [block2("event", val["client_sdk"])]
            claims = "".join(parts).encode("latin1")
        elif g["kind"] != "session":
            claims = sg.build_claims(g["map"], g["kind"], signing_id="1500000")
        # Android frame: real D9 = APK cert SHA-1, BLOCK_TAIL = 01 || 00*16
        d9 = bytes.fromhex(g["d9_hex"])
        msg = (d9 + b"\x00\x08" + recb[3:19]
               + struct.pack("<I", S) + SHA0 + b"\x01" + b"\x00" * 16 + claims)
        ok += int(sg.sha256_iv2(msg) == recb[46:78])
    return ok, len(sg.GOLD_VECTORS)


if __name__ == "__main__":
    corpus = load_corpus()
    print("corpus: %d signed requests" % len(corpus))
    ok, n = validate_on_android_golds()
    print("android gold block reproduction via this harness: %d/%d" % (ok, n))
    for r in corpus[:6]:
        print(" ", r["file"], r["kind"], r["host"], "nparams", len(r["val"]))
