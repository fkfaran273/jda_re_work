# -*- coding: utf-8 -*-
"""offline_berain.py -- offline byte-exact mint check for every carved blob
in the berain capture (adj7 iOS, ios5.5.2 / 3.62.0 / hid 8).

Fixes applied from the lululemon run:
  * timezone offset parsed out of sent_at (Turkey +0300 style frames)
  * sdk_click -> activity_kind "click", sdk_info -> "info"
"""
import os
import re
import struct
import sys
import urllib.parse
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adj7ios_pure as sg  # noqa: E402

RAW = os.path.join(HERE, "saz_berain", "raw")
SDK = "ios5.5.2"
HID, NV = "8", "3.62.0"
ENDPOINTS = {17: "session", 44: "event", 45: "sdk_click",
             46: "attribution", 75: "event"}
KIND = {"session": "session", "event": "event", "sdk_click": "click",
        "attribution": "attribution", "sdk_info": "info"}

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def carve(n):
    t = open(os.path.join(RAW, "%03d_c.txt" % n), encoding="utf-8",
             errors="replace", newline="").read()
    head, _, body = t.partition("\r\n\r\n")
    line0 = t.split("\r\n", 1)[0]
    auth = [l.split(": ", 1)[1] for l in head.split("\r\n")
            if l.startswith("Authorization")][0]
    if line0.startswith("GET") and "?" in line0:
        q = line0.split(" ", 2)[1].split("?", 1)[1].rsplit(" ", 1)[0]
        params = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
    else:
        params = dict(urllib.parse.parse_qsl(body.strip(),
                                             keep_blank_values=True))
    sig = re.search(r'signature="([0-9A-Fa-f]+)"', auth).group(1).upper()
    return params, sig, line0.split(" ")[0]


def sent_second(sent):
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?Z([+-]\d\d)(\d\d)",
                 sent)
    if not m:
        return int(datetime.strptime(sent[:19], "%Y-%m-%dT%H:%M:%S")
                   .replace(tzinfo=timezone.utc).timestamp())
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(
        tzinfo=timezone.utc).timestamp()
    return int(base - int(m.group(2)) * 3600 - int(m.group(3)) * 60)


ok = 0
for n, ep in ENDPOINTS.items():
    params, sig, method = carve(n)
    blob = bytes.fromhex(sig)
    dec = Cipher(algorithms.AES(sg.SEED), modes.CBC(blob[:16])).decryptor()
    rec = dec.update(blob[16:272]) + dec.finalize()
    s = rec.split(b"\x00")[0].decode("latin1")
    ra = re.search(r'"a":\s*"?(\d+)"?', s).group(1)
    rd = re.search(r'"d":\s*"([0-9A-Fa-f]+)"', s).group(1)
    nonce12 = struct.pack("<Q", int(ra.strip())) + bytes.fromhex(rd)
    sent = params.get("sent_at")
    base = sent_second(sent) if sent else None
    kind = KIND[ep]
    hit = None
    for d in range(-300, 301):
        try:
            _a, b2 = sg.sign_request(params, kind, second=base + d,
                                     nonce12=nonce12, client_sdk=SDK,
                                     headers_id=HID, native_version=NV)
        except Exception as e:
            print("  %-11s sign error %r" % (kind, e)); break
        if b2.hex().upper() == sig:
            hit = base + d
            break
    print("  row %-3d %-11s kind=%-11s %s (sent %s, delta %s)"
          % (n, ep, kind, "BYTE-EXACT" if hit is not None else "MISMATCH",
             sent, (hit - base) if hit else None))
    if hit is not None:
        ok += 1
print("byte-exact: %d/%d" % (ok, len(ENDPOINTS)))
