"""decode_signature.py — full decoding report for one adj9 signature.

Usage:
    python decode_signature.py "<base64 signature>"
    python decode_signature.py            (uses the default = the SAZ S1 one)

Shows everything recoverable from the signature alone + (if it is a known
capture) the request fields it was built from.
"""
import base64
import datetime
import json
import struct
import sys

M31 = 2147483647


class Random3:  # bionic random() TYPE_3 — the header law (proven 44/44)
    __slots__ = ("r", "f", "b")

    def __init__(self, seed):
        r = self.r = [0] * 31
        s = seed & 0xFFFFFFFF or 1
        w = s if s < 2 ** 31 else s - 2 ** 32
        r[0] = w
        for i in range(1, 31):
            hi, lo = divmod(w, 127773)
            w = 16807 * lo - 2836 * hi
            if w < 0:
                w += M31
            r[i] = w
        self.f, self.b = 3, 0
        for _ in range(310):
            self.next()

    def next(self):
        v = (self.r[self.f] + self.r[self.b]) & 0xFFFFFFFF
        self.r[self.f] = v if v < 2 ** 31 else v - 2 ** 32
        o = v >> 1
        self.f = (self.f + 1) % 31
        self.b = (self.b + 1) % 31
        return o


def header_second(hdr16, lo, hi):
    """brute-force the signing second: Random3(T) draws 1..8 XOR == header."""
    for T in range(lo, hi):
        R = Random3(T)
        d = [R.next() for _ in range(8)]
        if b"".join(struct.pack(">I", d[2 * i] ^ d[2 * i + 1])
                    for i in range(4)) == hdr16:
            return T
    return None


DEFAULT = ("QMgRTT9mxtofD3VyfhxE5s1jYqxb3XRxKZo988SMQaOuWQQfgYUsN1JK0QqRk7L5"
           "B6Te1pq+ltdKSmj8uG+6gaXboOKo5q+Lrm4pvjdw8w047bGpH2O4TfKLmKUgXv75"
           "iwrY3kxNTB7o93vEw9wC7YPpuD5ffEjIdbDsS5nonUQ4QQRXjhyXRVAEs8wlwwNa"
           "SqiKVLC/lRiEm5lfR88r2wMRsLKVZ5st267TQfQCKMY0unnK7uUl9r2QvMeNBNBQ")


def main():
    sig64 = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    blob = base64.b64decode(sig64)
    hdr, body = blob[:16], blob[16:]
    dws = struct.unpack(">44I", body)

    print("=" * 72)
    print("ADJ9 SIGNATURE DECODE")
    print("=" * 72)
    print("raw size        : %d bytes = 16-B header + 176-B body (44 dwords)"
          % len(blob))
    print("\n-- 1. 16-BYTE HEADER (clock stamp, no payload) --")
    print("   bytes   : %s" % hdr.hex())
    sec = header_second(hdr, 1786000000, 1793000000)
    if sec:
        ist = datetime.datetime.fromtimestamp(
            sec, datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
        print("   law     : Random3(%d) draws 1-8, pairwise XOR, 4x BE u32"
              % sec)
        print("   signed at: %s (IST)  — exact to the second, OFFLINE" % ist)
        print("   purpose : anti-replay clock bind; S1==S2 when same second")
    else:
        print("   law     : no match in search window")

    print("\n-- 2. BODY: 44 DWORDS (OUTPUT[4..48) of the signing VM) --")
    for i in range(0, 44, 4):
        print("   [%2d..%2d) %s" % (i, i + 4,
                                    " ".join("%08x" % v for v in dws[i:i + 4])))
    print("   content : the whitened record — cert-SHA1, TEE-HMAC tag (H),")
    print("             claim fields, env-verdict bits, timestamps. Each")
    print("             dword = input words mixed by the VM's position-")
    print("             arithmetic (hence full entropy, no plaintext visible).")

    print("\n-- 3. KNOWN FIELDS THIS SIGNATURE WHITENS --")
    print("   (from the matching captured request — the same fields the")
    print("    server reads back by re-running its VM copy)")
    try:
        sessions = json.load(open(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "saz_sessions.json")))
        for s in sessions:
            if s.get("sig_hex") == blob.hex():
                print("   endpoint : %s  (%s)" % (s["url"], s["status"]))
                print("   device   : %s %s, Android %s, app %s" % (
                    s["params"].get("device_manufacturer"),
                    s["params"].get("device_name"),
                    s["params"].get("os_version"),
                    s["params"].get("app_version")))
                print("   identity : gps_adid=%s" % s["params"].get("gps_adid"))
                print("             android_uuid=%s"
                      % s["params"].get("android_uuid"))
                print("             app_token=%s" % s["params"].get("app_token"))
                print("   created  : %s" % s["params"].get("created_at"))
                print("   claims   : %d fields total (see saz_sessions.json)"
                      % len(s["params"]))
                break
        else:
            print("   (signature not in the local corpus)")
    except Exception as e:
        print("   (corpus unavailable: %s)" % e)

    print("\n-- 4. OTHER AUTH FIELDS (decoded constants) --")
    print("   adj_signing_id = 1500000, algorithm = adj9, headers_id = 10,")
    print("   native_version = 5.0.0  (from the lib's decrypted string table)")
    print("   adj_verification:")
    s = b'{"os_name":"android"}'
    key = b"Quoh8uafohgh7CahM2h"
    import base64 as b64
    print("      %s = %s" % (b64.b64encode(
        bytes(c ^ key[i % 19] for i, c in enumerate(s))).decode(), s.decode()))
    print("\n-- 5. WHAT THE SERVER DOES WITH IT --")
    print("   1) header: regenerate Random3(now±window) -> match the second")
    print("   2) body  : re-run its copy of this VM program over the request's")
    print("      own fields -> compare; H (TEE-HMAC tag) is read from inside")
    print("      the record as a device-consistency signal, never decryptable")
    print("      server-side. No key, no cipher — clock + shared program.")
    print("=" * 72)


if __name__ == "__main__":
    import os
    main()
