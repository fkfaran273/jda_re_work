"""pure_signer.py — the adj9 signer with the VM replaced, except for block32.

Everything in the 192-byte envelope is now closed form:

    header      = make_header(second)                       [Random3 law]
    record      = assembled field by field                    [see build_record]
    body        = encrypt(record, header)             [14-round cipher]
    digest      = predict_digest(body)                       [two-pass SHA-256 MAC]

The ONE remaining unknown is `block32` = record[46:78], 32 bytes, which the
FinEx VM still computes. This module isolates it behind a single function so
that solving it is a one-line change, and so that everything around it is
already proven byte-exact.

HOW THIS IS VERIFIED (run `python pure_signer.py --verify`):
for each genuine capture we take the device's own block32, build every other
field from scratch via the closed-form laws, and require 192/192. That proves
the assembly, whitening and digest are right and that block32 is the only
input needed. A wrong claim shows up immediately as a body mismatch.
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adj9_signature as S   # noqa: E402  (tables + region + claims + whitening)

# --- the digest law (adj9/rev/algo_practice/digest_law/digest_law.py) --------
K = bytes.fromhex("690f60944dddd9847db55cd7d2d576b3"
                  "0451723fbcfa92df62b55f6fec60f2de")
IPAD = b"\x36" * 32
OPAD = b"\x5c" * 32
K_IPAD = bytes(a ^ b for a, b in zip(K, IPAD))
K_OPAD = bytes(a ^ b for a, b in zip(K, OPAD))

SHA0 = hashlib.sha256(b"").digest()          # sha256("") = the record's [79:111)
TAG = bytes.fromhex("060107")
MAGIC = bytes.fromhex("010008")


def predict_digest(body: bytes) -> bytes:
    """body = the whitened 144-B record -> the 32-B trailer."""
    inner = hashlib.sha256(K_IPAD + IPAD + body).digest()
    return hashlib.sha256(K_OPAD + OPAD + inner).digest()


# --- the block law (adj9/rev/algo_practice/block_law2/predict_block.py) -----
# Standard SHA-256, standard padding, standard round constants -- chained from
# a VM-hardcoded IV2 instead of the standard SHA-256 IV. That single deviation
# is why every off-the-shelf hash battery missed it.
IV2 = bytes.fromhex("eba2c4350f4002dc9fa8dac5127035ba"
                    "7a30ed9323473054bbe3cd00f1355ea5")
_M32 = 0xFFFFFFFF
_K256 = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2)


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


def _sha256_block(state, blk):
    w = list(blk)
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _M32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        t1 = (h + S1 + ((e & f) ^ (~e & g)) + _K256[i] + w[i]) & _M32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & _M32
        h, g, f, e, d, c, b, a = (g, f, e, (d + t1) & _M32, c, b, a,
                                  (t1 + t2) & _M32)
    return [(x + y) & _M32 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def sha256_iv2(msg: bytes) -> bytes:
    """SHA-256 with standard padding, chained from IV2 instead of the IV."""
    st = list(struct.unpack(">8I", IV2))
    m = (msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64)
         + struct.pack(">Q", len(msg) * 8))
    for i in range(0, len(m), 64):
        blk = [int.from_bytes(m[i + 4 * j:i + 4 * j + 4], "big")
               for j in range(16)]
        st = _sha256_block(st, blk)
    return struct.pack(">8I", *st)


def predict_block(head: bytes, seed: int, claims: bytes, d9: bytes) -> bytes:
    """record[46:78] — the 32-byte block. SOLVED.

    msg = D9 || 00 08 || head16 || LE32(S) || sha256("") || 01 00*16 || claims
    """
    msg = (d9 + b"\x00\x08" + head + struct.pack("<I", seed)
           + SHA0 + b"\x01" + b"\x00" * 16 + claims)
    return sha256_iv2(msg)


# ---------------------------------------------------------------------------
# block32 — SOLVED, no VM
# ---------------------------------------------------------------------------
def block32(head: bytes, seed: int, claims: bytes, d9: bytes) -> bytes:
    """record[46:78] — 32 bytes. Standard SHA-256 over a fixed message layout,
    chained from a VM-hardcoded IV2 instead of the standard SHA-256 IV.
    Verified 13/13 by the block_law2 gate (6 VM probes, 6 genuine penti wins,
    1 creditsea gold) plus 3 fresh-VM confirmations at claims lengths that are
    not multiples of 4."""
    return predict_block(head, seed, claims, d9)


# ---------------------------------------------------------------------------
# record assembly — every field except [46:78)
# ---------------------------------------------------------------------------
def build_record(head: bytes, seed: int, cert_sha1: bytes, claims: bytes,
                 bl32: bytes) -> bytes:
    """Assemble the 144-byte plaintext record.

    Layout (all offsets verified against every genuine capture):
        [0:3)    magic 010008
        [3:19)   head = head_words(d0[:4])
        [19]     flag 02
        [20:24)  seed S, big-endian
        [24]     03
        [25:45)  APK certificate SHA-1
        [45]     04
        [46:78)  block32            <- the only unknown
        [78]     05
        [79:111) sha256("")
        [111:114) 060107
        [114:128) 14 zero bytes
        [128:130) tail2 0000
        [130:144) 0x0e x 14
    """
    if len(bl32) != 32:
        raise ValueError("block32 must be 32 bytes, got %d" % len(bl32))
    rec = bytearray(144)
    rec[0:3] = MAGIC
    rec[3:19] = head
    rec[19] = 0x02
    rec[20:24] = struct.pack(">I", seed)
    rec[24] = 0x03
    rec[25:45] = cert_sha1
    rec[45] = 0x04
    rec[46:78] = bl32
    rec[78] = 0x05
    rec[79:111] = SHA0
    rec[111:114] = TAG
    rec[114:128] = b"\x00" * 14
    rec[128:130] = b"\x00\x00"
    rec[130:144] = b"\x0e" * 14
    return bytes(rec)


def sign(second: int, seed: int, cert_sha1: bytes, claims: bytes,
         head_phase=None) -> bytes:
    """The whole envelope. Returns the 192-byte blob."""
    phase = head_phase if head_phase is not None else S.HEAD_PHASE_DEFAULT
    d0w, _d2w, _d4w = S.region(seed, 0, 0, head=phase)
    head = S.head_words(d0w)
    bl32 = block32(head, seed, claims, cert_sha1)
    record = build_record(head, seed, cert_sha1, claims, bl32)
    header = S.make_header(int(second))
    body = S.encrypt(record, header)
    return header + body + predict_digest(body)


# ---------------------------------------------------------------------------
# verification against the genuine captures
# ---------------------------------------------------------------------------
def _genuine():
    """Yield (label, blob192, record144) for every genuine capture we hold."""
    import json
    import glob
    for path in (os.path.join(os.path.dirname(HERE), "block32_work",
                              "genuine.json"),):
        if not os.path.exists(path):
            continue
        for i, s in enumerate(json.load(open(path))):
            blob = bytes.fromhex(s["blob"])
            yield ("%s#%d" % (os.path.basename(path), i), blob,
                   S.whiten_body_inverse(blob[16:160], blob[:16]))


def _win_inputs():
    """(label, blob, claims_bytes) for the 6 genuine penti winning signings.

    The claims are rebuilt from the capture's own sign_input map_order, under
    both the 5.7 and the 5.8 claims laws (we try both; only one can be right).
    """
    import base64
    import re
    sys.path.insert(0, os.path.join(HERE, "..", "adj9", "rev"))
    sys.path.insert(0, os.path.join(HERE, "..", "adj9", "rev", "creditsea"))
    from desc10_law import claims_unpadded
    try:
        from desc10_58 import claims_unpadded_58
    except ImportError:
        claims_unpadded_58 = None

    log = os.path.join(HERE, "..", "adj9", "rev", "win_capture",
                       "module_win_capture.log")
    lines = open(log, encoding="utf-8", errors="replace").read().split("\n")
    si = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=sign_input")]
    ah = [i for i, l in enumerate(lines)
          if l.startswith("###ADJ9_BEGIN type=authorization_header")]
    out = []
    for n, (i, j) in enumerate(zip(si, ah)):
        v = {}
        for k in range(i, i + 10):
            if lines[k].startswith("map_order="):
                for p in lines[k][len("map_order="):].split("\x02"):
                    if "\x01" in p:
                        kk, vv = p.split("\x01", 1)
                        v[kk] = vv
                break
        blob = base64.b64decode(
            re.search(r'signature="([A-Za-z0-9+/=]+)"', lines[j + 2]).group(1))
        kind = v.get("activity_kind", "session")
        cands = []
        for fn in (claims_unpadded, claims_unpadded_58):
            if fn is None:
                continue
            try:
                r = fn(v, kind)
                cands.append(r.encode("latin1") if isinstance(r, str) else r)
            except KeyError:
                pass
        out.append(("win%d" % n, blob, cands))
    return out


def verify():
    """Rebuild each genuine 192-B blob from scratch. NO VM anywhere.

    Everything is recomputed: header, d0 head, seed, block, whitening, digest.
    The only inputs are the capture's own claims and its signing second.
    """
    n = ok = 0
    for label, blob, cands in _win_inputs():
        rec = S.whiten_body_inverse(blob[16:160], blob[:16])
        head, seed, cert = rec[3:19], int.from_bytes(rec[20:24], "big"), rec[25:45]
        phase = _phase_of(head, seed)
        second = _second_from_header(blob[:16])
        best = 0
        for cb in cands:
            got = sign(second, seed, cert, cb, head_phase=phase)
            best = max(best, sum(a == b for a, b in zip(got, blob)))
        ok += best == 192
        n += 1
        print("%-8s sec=%-11d %3d/192 %s"
              % (label, second, best, "EXACT" if best == 192 else "MISMATCH"))
    print("\n%d/%d genuine blobs reproduced 192/192 with NO VM" % (ok, n))
    return ok, n


# --- helpers to recover the second and the head phase from a genuine blob ---
_MKH = {}


def _second_from_header(header):
    """Invert make_header by brute force over a plausible epoch window."""
    if not _MKH:
        return 0
    return _MKH.get(header, 0)


_KNOWN_PHASES = ((0x2B,), (0x2B, 0x48), (0x22, 0x2E), (0x2B, 0x07, 0x22, 0x2E))


def _phase_of(head, seed=None):
    """Recover the d0 head phase that produces this 16-byte head.

    `seed` is the record's seed; when it is known we can search exhaustively.
    Guessing from a fixed list is NOT safe: within one capture the same app
    signs both kinds, and a wrong phase still yields a well-formed record that
    is simply wrong in 2-6 head bytes. Always search.
    """
    if seed is not None:
        import itertools
        for n in (1, 2, 3):
            for ph in itertools.permutations(range(0x20, 0x50), n):
                try:
                    d0w, _, _ = S.region(seed, 0, 0, head=ph)
                except Exception:                    # noqa: BLE001
                    continue
                if S.head_words(d0w) == head:
                    return ph
        return S.HEAD_PHASE_DEFAULT
    for ph in _KNOWN_PHASES:
        try:
            d0w, _, _ = S.region(0, 0, 0, head=ph)
            if S.head_words(d0w) == head:
                return ph
        except Exception:                            # noqa: BLE001
            pass
    return S.HEAD_PHASE_DEFAULT


def build_header_index(lo=1789000000, hi=1791000000):
    _MKH.update({S.make_header(t): t for t in range(lo, hi)})
    return len(_MKH)


if __name__ == "__main__":
    import time
    t0 = time.time()
    n = build_header_index()
    print("header index: %d seconds indexed in %.1fs" % (n, time.time() - t0))
    verify()