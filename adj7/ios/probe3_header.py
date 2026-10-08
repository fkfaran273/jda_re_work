# -*- coding: utf-8 -*-
"""probe3_header.py -- crack the iOS 16-byte header.

The Android header = 8 draws of bionic rand() seeded with the signing second,
pair-XORed, big-endian.  On iOS the SDK links against Darwin libc, so the
candidates are: bionic rand, Darwin rand (BSD additive LCG with the 3-value
copy-in head), and raw MINSTD -- each with a few draw/endianness variants.

Brute force: headers depend only on (variant, second), so enumerate seconds
in a window around the capture timestamps once and match all 6 blob headers
against the table.
"""
import json
import os
import re
import sys
import zipfile
from calendar import timegm
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from adj7_pure import BionicRand  # proven Android law

M = 2147483647
A = 16807


def minstd_next(x):
    return (A * x) % M


def darwin_state(seed):
    """BSD/Darwin rand() state: MINSTD fill, then 3 copies, then additive."""
    r = [0] * (34 + 320)
    r[0] = seed & 0xFFFFFFFF or 1
    if r[0] > M:
        pass  # keep as-is; MINSTD mod handles it
    x = r[0] % M or 1
    for i in range(1, 31):
        x = minstd_next(x)
        r[i] = x
    for i in range(31, 34):
        r[i] = r[i - 31]
    for i in range(34, len(r)):
        r[i] = (r[i - 31] + r[i - 3]) & 0xFFFFFFFF
    return r


def v_darwin_8xor(seed):
    r = darwin_state(seed)
    d = [(r[i] >> 1) & 0x7FFFFFFF for i in range(344, 352)]
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(v.to_bytes(4, "big") for v in w)


def v_darwin_4be(seed):
    r = darwin_state(seed)
    d = [(r[i] >> 1) & 0x7FFFFFFF for i in range(344, 348)]
    return b"".join(v.to_bytes(4, "big") for v in d)


def v_darwin_8xor_d0(seed):
    """No 310-discard variant (output straight after the copy-in)."""
    r = [0] * 60
    r[0] = seed & 0xFFFFFFFF or 1
    x = r[0] % M or 1
    for i in range(1, 31):
        x = minstd_next(x)
        r[i] = x
    for i in range(31, 34):
        r[i] = r[i - 31]
    for i in range(34, len(r)):
        r[i] = (r[i - 31] + r[i - 3]) & 0xFFFFFFFF
    d = [(r[i] >> 1) & 0x7FFFFFFF for i in range(34, 42)]
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(v.to_bytes(4, "big") for v in w)


def v_bionic_8xor(seed):
    return BionicRand(seed) and _draws(BionicRand(seed), 8, xor=True)


def _draws(R, n, xor):
    d = [R.next() for _ in range(n)]
    if xor:
        w = [d[2 * i] ^ d[2 * i + 1] for i in range(n // 2)]
    else:
        w = d
    return b"".join(v.to_bytes(4, "big") for v in w)


def v_bionic_4be(seed):
    return _draws(BionicRand(seed), 4, xor=False)


def v_minstd_8xor(seed):
    x = seed % M or 1
    d = []
    for _ in range(8):
        x = minstd_next(x)
        d.append(x)
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(v.to_bytes(4, "big") for v in w)


def v_minstd_4be(seed):
    x = seed % M or 1
    w = []
    for _ in range(4):
        x = minstd_next(x)
        w.append(x)
    return b"".join(v.to_bytes(4, "big") for v in w)


def v_minstd310_8xor(seed):
    x = seed % M or 1
    for _ in range(310):
        x = minstd_next(x)
    d = []
    for _ in range(8):
        x = minstd_next(x)
        d.append(x)
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(v.to_bytes(4, "big") for v in w)


def v_darwin_le(seed):
    r = darwin_state(seed)
    d = [(r[i] >> 1) & 0x7FFFFFFF for i in range(344, 352)]
    w = [d[2 * i] ^ d[2 * i + 1] for i in range(4)]
    return b"".join(v.to_bytes(4, "little") for v in w)


VARIANTS = [
    ("bionic310_8xor (Android law)", v_bionic_8xor),
    ("bionic310_4be", v_bionic_4be),
    ("darwin_8xor", v_darwin_8xor),
    ("darwin_4be", v_darwin_4be),
    ("darwin_8xor_nodiscard", v_darwin_8xor_d0),
    ("darwin_8xor_le", v_darwin_le),
    ("minstd_8xor", v_minstd_8xor),
    ("minstd_4be", v_minstd_4be),
    ("minstd310_8xor", v_minstd310_8xor),
]

CIPHER_RE = re.compile(r'signature="([^"]+)"')


def parse_iso_z0530(s):
    """'2026-09-08T11:11:09.477Z+0530' -> epoch seconds (UTC)."""
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", s)
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    return timegm(base.timetuple()) - 5 * 3600 - 30 * 60


def parse_iso_offset(s):
    """'2026-09-08T11:11:00.0829129+05:30' -> epoch seconds (UTC)."""
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", s)
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    t = timegm(base.timetuple())
    moff = re.search(r"([+-])(\d{2}):(\d{2})$", s)
    if moff:
        off = int(moff.group(2)) * 3600 + int(moff.group(3)) * 60
        t = t - off if moff.group(1) == "+" else t + off
    return t


def main():
    jf = os.path.join(HERE, "nirio_08Sep",
                      "nirioiosauto_08Sep_ios_CT_adjust.json")
    recs = json.load(open(jf, encoding="utf-8"))
    saz = os.path.join(HERE, "nirioiosauto_08Sep_ios_CT.saz")
    z = zipfile.ZipFile(saz)
    begins = {}
    for n in z.namelist():
        m = re.match(r"raw/(\d+)_m\.xml$", n)
        if not m:
            continue
        xml = z.open(n).read().decode("utf-8", "replace")
        mm = re.search(r'ClientBeginRequest="([^"]+)"', xml)
        if mm:
            begins[m.group(1)] = parse_iso_offset(mm.group(1))
    blobs = []
    for r in recs:
        auth = next((v for k, v in r["request_headers"]
                     if k.lower() == "authorization"), "")
        blob = bytes.fromhex(CIPHER_RE.search(auth).group(1))
        body_map = r["body"] if isinstance(r["body"], dict) else {}
        t_created = (parse_iso_z0530(body_map["created_at"])
                     if "created_at" in body_map else None)
        t_begin = begins.get(r["sid"])
        blobs.append((r["sid"], blob[:16], t_created, t_begin))
        print(f"sid {r['sid']}: header={blob[:16].hex()} "
              f"t_created={t_created} t_begin={t_begin}")

    # window: cover both anchors generously
    lo = min(min(t for t in (tc, tb) if t is not None)
             for _, _, tc, tb in blobs) - 900
    hi = max(max(t for t in (tc, tb) if t is not None)
             for _, _, tc, tb in blobs) + 900
    targets = {}
    for sid, h, _, _ in blobs:
        targets.setdefault(h, []).append(sid)
    print(f"\nwindow {lo}..{hi} ({hi - lo} s), "
          f"{len(targets)} distinct target headers\n")

    for vname, fn in VARIANTS:
        hits = {}
        for sec in range(lo, hi + 1):
            try:
                h = fn(sec)
            except Exception:
                continue
            if h in targets:
                hits.setdefault(h, []).append(sec)
        n = sum(len(v) for v in hits.values())
        if n:
            print(f"[HIT] {vname}:")
            for h, secs in hits.items():
                print(f"    {'/'.join(targets[h])}: sec={secs}")
        else:
            print(f"[   ] {vname}")


if __name__ == "__main__":
    main()
