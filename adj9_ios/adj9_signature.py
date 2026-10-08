# -*- coding: utf-8 -*-
"""_sub_ios_mint.py — the iOS adj9 signature minter (one-click, self-contained
given adj9_signer.py for the shared cipher primitives, which it imports
read-only and does not modify).

    blob(192) = header(16) || whiten(record(144), header) || digest(32)

THE iOS LAW (verified against the Cainiao iOS capture, 30/30 unless noted):

  header   Apple MINSTD (Park-Miller), NOT the Android bionic law:
             x = unix_sec mod (2^31-1);  if x == 0: x = 1
             d[k] = 16807*d[k-1] mod (2^31-1), k = 1..8, d[0] = x
             w_i = d[2i] ^ d[2i+1]  (i = 0..3, over the 8 POST-STEP draws)
             header = BE32(w0) || BE32(w1) || BE32(w2) || BE32(w3)
           Injective per second (no collisions outside the 1970/2038 epoch
           edges); verified 28/28 distinct capture headers + 30/30 mints.
  region   shared with Android: d0/d2/d4 = region(S); the iOS d0 selector
           head phase is (0x40,) — the pure cycle entered at index 0
           (Android used (0x2B,)); head16_for(S,(0x40,)) == rec[3:19] 30/30.
  record   01 00 08 | head16 | 02 | BE32(S) | 03 | D9 | 04 | BLOCK |
           05 | sha256("") | 06 02 07 | device_name+00*pad | 0000 | 0e*14
           Three iOS deviations vs Android:
             1. descriptor-6 variant byte @112 = 0x02 (Android 0x01)
             2. D9 (cert SHA-1) = 20 zero bytes (iOS builds carry no APK
                cert); constant across all 30 capture records
             3. the 16-B descriptor-7 field @114..129 carries the device
                name ("iPhone13,2", zero padded) — Android has 16 zeros
  BLOCK    sha256 with the custom IV2 over
             D9 || 00 08 || head16 || LE32(S) || sha256("") ||
             variant(02) || device_field(16) || claims
           — the Android-verified recipe with the two iOS payload
             substitutions (variant byte, device field), record-sourced.
  digest   shared: sha256((K^opad)||opad||sha256((K^ipad)||ipad||body))
  claims   Android presence law (sorted profile + pinned "1500000" + sorted
           tail + block2) over the request params; /event extends the pools
           per _sub_android_event_RESULT.md.  **The iOS capture's BLOCK does
           not verify under any tested claims composition** — see
           _sub_ios_mint_RESULT.md §claims for the exhaustive negative
           results.  `claims=` override is accepted so the caller can mint
           byte-exact blobs once the iOS claims string is pinned down.

USE:
    import _sub_ios_mint as m
    blob, auth = m.mint_ios("event", params, unix_sec=..., S=...)
    python _sub_ios_mint.py --selftest
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import time

import adj9_signer as sg          # shared cipher primitives (read-only)

HERE = os.path.dirname(os.path.abspath(__file__))

# ======================================================================
# iOS header — Apple MINSTD (Park–Miller), pair-XORed big-endian words
# ======================================================================
MINSTD_P = (1 << 31) - 1
MINSTD_A = 16807


def minstd_state(unix_sec):
    x = unix_sec % MINSTD_P
    return 1 if x == 0 else x


def minstd_draws(unix_sec, n=8):
    x = minstd_state(unix_sec)
    out = []
    for _ in range(n):
        x = (MINSTD_A * x) % MINSTD_P
        out.append(x)
    return out


def make_ios_header(unix_sec):
    """The 16-byte header (whitening IV) an iOS device mints for a second."""
    d = minstd_draws(unix_sec, 8)
    words = [(d[2 * i] ^ d[2 * i + 1]) & 0xFFFFFFFF for i in range(4)]
    return b"".join(struct.pack(">I", w) for w in words)


def invert_ios_header(header, center_sec, radius=900):
    """The unique signing second in [center-radius, center+radius]."""
    target = header if isinstance(header, bytes) else bytes.fromhex(header)
    return [s for s in range(center_sec - radius, center_sec + radius + 1)
            if make_ios_header(s) == target]


# ======================================================================
# adj_verification — BASE64(KEY_cycle XOR b'{"os_name":"<os>"}')
# ======================================================================
ADJ_V_KEY = b"Quoh8uafohgh7CahM2h"          # 19-byte effective pad (cycled)


def make_adj_verification(os_name="ios", key=ADJ_V_KEY):
    plain = json.dumps({"os_name": os_name}, separators=(",", ":")).encode()
    return base64.b64encode(bytes(b ^ key[i % len(key)]
                                  for i, b in enumerate(plain))).decode()


# ======================================================================
# claims — Android presence law (+ the proven /event extension)
# ======================================================================
PROFILE = list(sg.PROFILE)                  # android-SDK key names
SESSION_EXTRA = list(sg.SESSION_EXTRA)
CLICK_EXTRA = list(sg.CLICK_EXTRA)
ATTR_DROP = list(sg.ATTR_DROP)
ATTR_EXTRA = list(sg.ATTR_EXTRA)
SESSION_TAIL = list(sg.SESSION_TAIL)
CLICK_TAIL = list(sg.CLICK_TAIL)
ATTR_TAIL = list(sg.ATTR_TAIL)
EVENT_PROFILE_EXTRA = ["event_count", "event_token", "partner_params",
                       "callback_params"]
EVENT_TAIL_EXTRA = ["seq"]
BLOCK2 = list(sg.BLOCK2)
PINNED = sg.PINNED
ADJ_SIGNING_ID = "1500000"


def desc10_keys_ios(val, kind):
    """Emission key order (presence-filtered) for one activity kind."""
    if kind == "session":
        profile, tail = PROFILE + SESSION_EXTRA, SESSION_TAIL
    elif kind == "click":
        profile, tail = PROFILE + CLICK_EXTRA, CLICK_TAIL
    elif kind == "attribution":
        profile = [k for k in PROFILE if k not in ATTR_DROP] + ATTR_EXTRA
        tail = ATTR_TAIL
    elif kind == "event":
        profile = PROFILE + EVENT_PROFILE_EXTRA
        tail = SESSION_TAIL + EVENT_TAIL_EXTRA
    else:
        raise ValueError("kind must be session|click|attribution|event")
    keys = [k for k in sorted(profile) if val.get(k)]
    keys.append(PINNED)
    keys += [k for k in sorted(tail) if val.get(k)]
    keys += [k for k in BLOCK2 if val.get(k)]
    return keys


def build_claims_ios(val, kind, signing_id=ADJ_SIGNING_ID, client_sdk=None,
                     headers_id="10", native_version="5.0.0",
                     activity_kind=True):
    """The unpadded descriptor-#10 payload for iOS params.

    val    : dict key->str (the request's decoded wire params).  Keys NOT in
             the law are ignored; the pinned adj_signing_id always emits.
    client_sdk : value for the client_sdk claim (e.g. 'ios5.8.0'); None =
             omit the claim (the iOS wire body does not carry these values —
             on Android the map carries them, so passing them reproduces the
             Android behaviour exactly).
    """
    val = dict(val)
    val.setdefault("adj_signing_id", signing_id)
    if client_sdk is not None:
        val.setdefault("client_sdk", client_sdk)
        val.setdefault("headers_id", headers_id)
        val.setdefault("native_version", native_version)
        if activity_kind and kind not in val:
            val["activity_kind"] = kind
    parts = []
    for k in desc10_keys_ios(val, kind):
        v = val.get(k)
        if k == PINNED and not v:
            v = signing_id
        if not v:
            raise KeyError("missing claims value for %r" % k)
        parts.append(v)
    return "".join(parts).encode("latin1")


# ======================================================================
# record — iOS deviations inside the shared container
# ======================================================================
def build_record_ios(S, head16, claims, device_name="iPhone13,2",
                     variant=0x02, d9=b"\x00" * 20):
    """The 144-B iOS record.  Android = build_record(S, head16, claims, d9);
    the three iOS deviations are the variant byte, the device-name field and
    the all-zero cert."""
    head16 = bytes(head16)
    d9 = bytes(d9)
    if len(head16) != 16:
        raise ValueError("head16 must be 16 bytes")
    if len(d9) != 20:
        raise ValueError("d9 must be 20 bytes")
    dev = device_name.encode("latin1")[:16]
    dev = dev + b"\x00" * (16 - len(dev))
    block = predict_block_ios(S, head16, claims, d9, variant, dev)
    out = bytearray(144)
    out[0:3] = b"\x01\x00\x08"
    out[3:19] = head16
    out[19] = 0x02
    out[20:24] = struct.pack(">I", S & 0xFFFFFFFF)
    out[24] = 0x03
    out[25:45] = d9
    out[45] = 0x04
    out[46:78] = block
    out[78] = 0x05
    out[79:111] = sg.SHA0
    out[111:114] = b"\x06" + bytes([variant]) + b"\x07"
    out[114:130] = dev
    out[130:144] = b"\x0e" * 14
    return bytes(out)


def block_message_ios(S, head16, claims, d9, variant, dev):
    """sha256-IV2 message: D9 || 00 08 || head16 || LE32(S) || sha256("") ||
    variant || device_field(16) || claims  (the Android-verified recipe with
    the record-sourced iOS descriptor-6/7 payloads)."""
    return (bytes(d9) + b"\x00\x08" + bytes(head16)
            + struct.pack("<I", S & 0xFFFFFFFF) + sg.SHA0
            + bytes([variant]) + bytes(dev) + bytes(claims))


def predict_block_ios(S, head16, claims, d9, variant=0x02,
                      dev=b"iPhone13,2" + b"\x00" * 6):
    return sg.sha256_iv2(block_message_ios(S, head16, claims, d9, variant,
                                           dev))


# ======================================================================
# one-click mint
# ======================================================================
IOS_HEAD_PHASE = (0x40,)          # the pure d0 selector cycle, index 0


def mint_ios(kind, params, unix_sec=None, S=None, device_name="iPhone13,2",
             os_name="ios", claims=None, head=IOS_HEAD_PHASE, variant=0x02,
             d9=b"\x00" * 20, client_sdk=None, signing_id=ADJ_SIGNING_ID):
    """Mint one 192-byte adj9 signature for an iOS request.

    kind   : session | click | attribution | event
    params : dict of the request's decoded wire fields
    unix_sec : signing second (default now) — seeds the MINSTD header
    S      : 32-bit fill seed (default random)
    claims : explicit claims payload (bytes/str) — overrides the law
    returns (blob192, auth_header_string)
    """
    if kind not in ("session", "click", "attribution", "event"):
        raise ValueError("bad kind %r" % kind)
    second = int(unix_sec if unix_sec is not None else time.time())
    seed = int.from_bytes(os.urandom(4), "big") if S is None else int(S)
    cb = (claims.encode("latin1") if isinstance(claims, str)
          else bytes(claims) if claims is not None
          else build_claims_ios(params, kind, signing_id=signing_id,
                                client_sdk=client_sdk))
    head16 = sg.head16_for(seed, head)
    record = build_record_ios(seed, head16, cb, device_name=device_name,
                              variant=variant, d9=d9)
    header = make_ios_header(second)
    body = sg.whiten_forward(record, header)
    blob = header + body + sg.predict_digest(body)
    auth = ios_auth_header(blob, os_name=os_name, signing_id=signing_id)
    return blob, auth


def ios_auth_header(blob, os_name="ios", signing_id=ADJ_SIGNING_ID,
                    headers_id="10", native_version="5.0.0"):
    return ('Signature signature="%s",adj_signing_id="%s",algorithm="adj9",'
            'headers_id="%s",native_version="%s",adj_verification="%s"'
            % (base64.b64encode(blob).decode(), signing_id, headers_id,
               native_version, make_adj_verification(os_name)))


# ======================================================================
# self-test
# ======================================================================
import re as _re
from urllib.parse import urlsplit as _urlsplit, unquote_to_bytes as _u2b, \
    unquote_plus as _unquote_plus

_CRLF = "\r\n"


def _load_capture():
    """The 30 signed iOS requests from the capture."""
    import base64
    import zipfile
    saz = r"C:/Users/Apps/Downloads/cainiaot1iosmodd_24aug26_ios12_install_login_explore.saz"
    z = zipfile.ZipFile(saz)
    from _sub_unseal_core import whiten_inverse
    out = []
    for name in sorted(z.namelist()):
        if not _re.fullmatch(r"raw/\d+_c\.txt", name):
            continue
        txt = z.read(name).decode("latin1")
        m = _re.search(r'signature="([A-Za-z0-9+/=]+)"', txt)
        if not m:
            continue
        blob = base64.b64decode(m.group(1))
        head, _, body = txt.partition(_CRLF * 2)
        p = _urlsplit(head.split(_CRLF)[0].split(" ")[1])
        val = {}
        for kv in (p.query.split("&") if p.query else []) + body.split("&"):
            k, _, v = kv.partition("=")
            val[_unquote_plus(k)] = _u2b(v).decode("latin1")
        out.append({
            "file": os.path.basename(name),
            "kind": p.path.strip("/").replace("sdk_click", "click"),
            "val": val,
            "blob": blob,
            "rec": whiten_inverse(blob[16:160], blob[:16]),
        })
    return out


def selftest(verbose=True):
    """Verify every proven component; report the claims-law state."""
    ok = True
    lines = []

    # 1. the shared pipeline reproduces all 9 Android gold blobs byte-exact
    gold_ok = sum(
        1 for g in sg.GOLD_VECTORS
        if sg.sign_pure(g["second"], g["S"], g["map"],
                        d9_hex=g["d9_hex"], kind=g["kind"],
                        head=tuple(g["head"])) == bytes.fromhex(g["blob_hex"]))
    ok &= gold_ok == len(sg.GOLD_VECTORS)
    lines.append("android gold full-blob mints (shared pipeline): %d/%d"
                 % (gold_ok, len(sg.GOLD_VECTORS)))

    # 2. iOS header law at the recovered signing seconds
    with open(os.path.join(HERE, "_sub_ios_seconds.json")) as f:
        secs = {r["file"]: r["signing_second"] for r in json.load(f)}
    reqs = _load_capture()
    hdr_ok = dig_ok = d0_ok = rec_ok = 0
    prefix_scores = {}
    for r in reqs:
        blob, rec = r["blob"], r["rec"]
        header, body = blob[:16], blob[16:160]
        second = secs[r["file"]]
        hdr_ok += make_ios_header(second) == header
        dig_ok += sg.predict_digest(body) == blob[160:192]
        S = int.from_bytes(rec[20:24], "big")
        d0_ok += sg.head16_for(S, IOS_HEAD_PHASE) == rec[3:19]
        claims = build_claims_ios(r["val"], r["kind"])
        rec2 = build_record_ios(S, rec[3:19], claims,
                                device_name=rec[114:124].decode("latin1"))
        # every non-claims record field must match the captured record
        same = (rec2[:46] == rec[:46] and rec2[78:] == rec[78:]
                and rec2[111:114] == rec[111:114]
                and rec2[114:130] == rec[114:130])
        rec_ok += same
        body2 = sg.whiten_forward(rec2, header)
        minted = header + body2 + sg.predict_digest(body2)
        same_n = sum(1 for a, b in zip(minted, blob) if a == b)
        prefix_scores[r["file"]] = same_n
    n = len(reqs)
    ok &= hdr_ok == n and dig_ok == n and d0_ok == n
    lines.append("iOS capture headers reproduced at recovered seconds: %d/%d"
                 % (hdr_ok, n))
    lines.append("iOS capture digest MAC (shared K): %d/%d" % (dig_ok, n))
    lines.append("iOS d0 head == region(S, phase (0x40,)): %d/%d"
                 % (d0_ok, n))
    lines.append("iOS record rebuild, non-claims fields byte-exact: %d/%d"
                 % (rec_ok, n))
    if prefix_scores:
        best = max(prefix_scores.values())
        lines.append("iOS full-blob mint: best %d/192 bytes byte-exact "
                     "(%d/30 full) — BLOCK claims law unverified"
                     % (best, sum(1 for v in prefix_scores.values()
                                  if v == 192)))

    if verbose:
        for ln in lines:
            print("[mint] " + ln)
    return ok


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _ok = selftest()
        print("[mint] selftest -> %s" % ("OK" if _ok else "FAIL"))
        sys.exit(0 if _ok else 1)
    print(__doc__)
