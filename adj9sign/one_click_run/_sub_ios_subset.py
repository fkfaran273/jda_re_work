"""_sub_ios_subset.py — FINAL comprehensive subset search for the iOS session
record's claims, under the canonical frame family:
  msg = rec[25:45] || rec[1:3] || rec[3:19] || S32(le|be) || SHA0 ||
        TAIL(02dev|01z) || claims
  claims = ''.join(sorted subset of PROFILE-POOL values present)
           + ['1500000']? + ''.join(sorted subset of TAIL-POOL present)
           + b2? (ios5.8.0 / 10 / 5.0.0 [+ activity_kind])
PROFILE-POOL = 14 body identity keys + adj_verification + started_at + sent_at
TAIL-POOL = session_count, session_length, subsession_count, time_spent (+track)
"""
from __future__ import annotations

import base64
import itertools
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

POOL = ["app_token", "app_version", "app_version_short", "att_status",
        "bundle_id", "created_at", "device_name", "environment", "idfa",
        "idfv", "installed_at", "os_name", "os_version",
        "primary_dedupe_token", "fb_anon_id", "started_at", "sent_at",
        "adj_verification"]
TAILP = ["session_count", "session_length", "subsession_count",
         "time_spent"]


def load(f):
    z = zipfile.ZipFile(SAZ)
    txt = z.read("raw/" + f).decode("latin1")
    head, _, body = txt.partition("\r\n\r\n")
    blob = base64.b64decode(
        re.search(r'signature="([A-Za-z0-9+/=]+)"', txt).group(1))
    rec = whiten_inverse(blob[16:160], blob[:16])
    p = urlsplit(head.split("\r\n")[0].split(" ")[1])
    dec = {}
    for kv in (p.query.split("&") if p.query else []) + body.split("&"):
        k, _, v = kv.partition("=")
        dec[unquote_plus(k)] = unquote(v)
    return rec, dec, blob


def val_of(k, dec):
    if k == "adj_verification":
        return AV
    return dec.get(k)


def main():
    rec, dec, blob = load("0144_c.txt")
    S = int.from_bytes(rec[20:24], "big")
    target = np.frombuffer(rec[46:78], ">u4").astype(np.uint32)
    dev = rec[114:130]
    tails = {"02dev": bytes([rec[112]]) + dev, "01z": b"\x01" + b"\x00" * 16}
    b2s = [b"", b"ios5.8.0" + b"10" + b"5.0.0",
           b"session" + b"ios5.8.0" + b"10" + b"5.0.0"]
    n = 0
    t0 = time.time()
    found = None
    for bits in range(1 << len(POOL)):
        vals = []
        ok = True
        for i, k in enumerate(POOL):
            if (bits >> i) & 1:
                v = val_of(k, dec)
                if not v:
                    ok = False
                    break
                vals.append(v)
        if not ok:
            continue
        base = "".join(vals)
        Lp = len(base)
        for tmask in range(1 << (len(TAILP) + 1)):
            tv = []
            for i, k in enumerate(TAILP):
                if (tmask >> i) & 1:
                    tv.append(dec[k])
            if (tmask >> len(TAILP)) & 1:
                tv.append("1")          # tracking_enabled synthesized
            tv.sort(key=lambda x: x)    # values sorted by value?? no — by key
            # NOTE: sorted by KEY:
            keys_sel = [k for i, k in enumerate(TAILP) if (tmask >> i) & 1]
            extra = (tmask >> len(TAILP)) & 1
            keys_sorted = sorted(keys_sel + (["tracking_enabled"] if extra
                                             else []))
            tv = [dec[k] for k in keys_sorted]
            if extra and not keys_sel:
                tv = ["1"]
            elif extra:
                tv = [dec[k] if k != "tracking_enabled" else "1"
                      for k in keys_sorted]
            tailvals = "".join(tv)
            for pin in (0, 1):
                for b2 in b2s:
                    c = (base + ("1500000" if pin else "") + tailvals
                         + b2).encode("latin1")
                    L = len(c)
                    for tn, tail in tails.items():
                        for senc in ("le", "be"):
                            s4 = struct.pack("<I" if senc == "le" else ">I", S)
                            msg_prefix = (rec[25:45] + rec[1:3] + rec[3:19]
                                          + s4 + sg.SHA0 + tail)
                            total_len = 64 + len(msg_prefix) - 64 + L
                            # msg = msg_prefix + c ; len(msg_prefix) may be <64
                            full_len = len(msg_prefix) + L
                            pad = b"\x80" + b"\x00" * ((55 - full_len) % 64) \
                                + struct.pack(">Q", full_len * 8)
                            data = msg_prefix + c + pad
                            # first block state
                            st = sg._compress(
                                list(struct.unpack(">8I", sg.IV2)),
                                list(struct.unpack(">16I", data[:64])))
                            rest = data[64:]
                            n += 1
                            dig = npsh_rest(st, rest)
                            if dig == rec[46:78]:
                                print("\n!!! HIT bits=%s tmask=%s pin=%d "
                                      "b2=%d tail=%s senc=%s len=%d"
                                      % (bin(bits), bin(tmask), pin, len(b2),
                                         tn, senc, L), flush=True)
                                print("claims:", c)
                                found = (bits, tmask, pin, b2, tn, senc)
                    if found:
                        break
                if found:
                    break
            if found:
                break
        if found:
            break
        if bits % 4096 == 0:
            print("  bits=%d/%d (%d hashes, %.0f s)"
                  % (bits, 1 << len(POOL), n, time.time() - t0), flush=True)
    if not found:
        print("NO HIT (%d hashes)" % n)
    return 0


def npsh_rest(st, rest):
    """sha256 from midstate st (list of 8 ints) over rest (already padded)."""
    state = list(st)
    for i in range(0, len(rest), 64):
        state = sg._compress(state,
                             list(struct.unpack(">16I", rest[i:i + 64])))
    return struct.pack(">8I", *state)


if __name__ == "__main__":
    sys.exit(main())
