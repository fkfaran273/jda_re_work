"""adj9_signer.py — the adj9 signature algorithm in closed form.

One stdlib-only file.  One signing ~3 ms, byte-exact against genuine device
captures (--selftest).

    blob(192) = header(16) || whiten(record(144), header) || digest(32)

  header   bionic srand(second): MINSTD rand, 310 warm-up draws, then 8
           draws XORed in pairs, big-endian.
  region   seed S -> d0/d2/d4: shuffle + bit-transpose; d0 = selector
           halfwords (head phase + the 0x40|(i&7) cycle); d2 = BE32(S).
  record   01 00 08 | head16 | 02 | BE32(S) | 03 | D9 | 04 | BLOCK |
           05 | sha256("") | 06 01 07 | 00*14 | 0000 | 0e*14
  BLOCK    SHA-256 (standard padding and constants, custom IV2) over
           D9 || 00 08 || head16 || LE32(S) || sha256("") || 01 || 00*16
           || claims(unpadded).
  whiten   14-round SPN, CBC-chained from the header: S-box = the AES
           S-box (generated), round keys KB, PI = 4x4 rows rotated right
           by row index (generated), F = AES-xtime byte-circulant
           (generated).
  digest   sha256((K^opad) || opad || sha256((K^ipad) || ipad || body))
           — pads hashed twice, NOT standard HMAC.
  claims   one presence-filtered law for SDK 5.7.0 and 5.8.0: sorted
           profile keys + pinned '1500000' + sorted tail + block2.

Stored values: only the cipher's three secrets (KB, IV2, K) — see PART 0.
Everything else is computed from logic.  App differences = campaign_data.json
(cert_sha1 is the only per-app secret).

LAYOUT:  PART 0 constants · PART 1 header · PART 2 region · PART 3 claims
         PART 4 block hash · PART 5 whitening · PART 6 digest · PART 7 signer
         PART 8 one-click API · PART 9 self-test

USE (the funnel calls exactly this):

    import adj9_signer as sg
    sg.configure(campaign_data)                    # once per app
    blob, second, info = sg.sign(params, kind)     # session|click|attribution
    auth = sg.auth_header(blob)

    python adj9_signer.py --selftest   # self-contained: 9 genuine captures inside
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import time
