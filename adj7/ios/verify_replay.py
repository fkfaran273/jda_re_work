# -*- coding: utf-8 -*-
"""verify_replay.py -- simulate the SERVER's replay check on the funnel's
own requests.

The server, on every signed request:
  1. verifies tag = HMAC(DK37, blob[16:272])            (integrity)
  2. decrypts body with SEED, parses the record         (structure)
  3. recomputes H from the RECEIVED wire map + record's
     nonce12 and compares with the record's b slot      (replay binding:
      the signature is bound to exactly the fields sent)
  4. checks the pin 1300000 / cert40 / algorithm pin

This script runs steps 1-4 against the requests run_install_ios.py builds
(the same code path a live run would send), plus one header-law probe.
"""
import hmac
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import run_install_ios as F                     # noqa: E402
from adj7_ios_pure import (DK37, RECORD_RE, build_claims, cbc_decrypt,  # noqa
                           commitment_digest, make_header)

AUTH_RE = re.compile(r'signature="([0-9A-Fa-f]{608})"')


def server_check(label, kind, fields, auth, sec):
    blob = bytes.fromhex(AUTH_RE.search(auth).group(1))
    header, body, tag = blob[:16], blob[16:272], blob[272:304]
    ok = {}
    # 1. integrity
    ok["tag"] = hmac.compare_digest(
        hmac.new(DK37, body, hashlib.sha256).digest(), tag)
    # 2. decrypt + parse
    rec = cbc_decrypt(body, header)
    m = re.match(RECORD_RE, rec)
    ok["record"] = bool(m)
    if not m:
        print(f"{label}: FAIL (record undecodable)"); return False
    nonce12 = (int(m.group(1).decode().strip()).to_bytes(8, "little")
               + bytes.fromhex(m.group(4).decode()))
    # 3. replay binding: H from the RECEIVED wire map.  The claims (with the
    #    1300000 pin) are bound INTO H -- the record plaintext carries only
    #    a/b/c/d/e, so the pin is checked on the claims string here.
    claims = build_claims(kind, fields, client_sdk=F.CLIENT_SDK,
                          include_block2=True)
    H = commitment_digest(claims, nonce12, b"0" * 40)
    ok["H==wire map"] = H.hex().upper() == m.group(2).decode()
    # 4. pins + header law
    ok["pin in claims"] = b"1300000" in claims
    ok["cert40=ascii0"] = m.group(3) == b"0" * 40
    ok["header(sec)"] = header == make_header(sec)
    # nonce <-> record d8/a round-trip (implicit in nonce12 above)
    good = all(ok.values())
    print(f"{label:26s} sec={sec}  " +
          "  ".join(f"{k}:{'OK' if v else 'FAIL'}" for k, v in ok.items())
          + ("   -> SERVER WOULD ACCEPT" if good else "   -> FAIL"))
    return good


def main():
    n_ok = 0
    n = 0
    # fresh funnel identities (no clicks fired here -- pure signing check)
    F._IDFA = F.new_idfa()
    F._IDFV = F.new_idfv()
    F._DEDUPE = F.new_dedupe()
    T0 = int(time.time())
    F._STARTED = T0 - 1020
    F._INSTALL = T0 - 29
    for kind, builder in (("third_party_sharing", F.build_tps_request),
                          ("session", F.build_session_request)):
        sec = int(time.time()) - 2
        fields = builder(sec)
        auth = F._sign(fields, kind, sec)
        n += 1
        n_ok += server_check(kind, kind, fields, auth, sec)
    for init_by in ("backend", "sdk"):
        sec = int(time.time()) - 2
        fields = F.build_attribution_request(sec, init_by)
        auth = F._sign(fields, "attribution", sec)
        n += 1
        n_ok += server_check("attribution(%s)" % init_by, "attribution",
                             fields, auth, sec)
    print(f"\n{n} requests, {n_ok} pass the full server replay check")
    raise SystemExit(0 if n_ok == n else 1)


if __name__ == "__main__":
    main()
