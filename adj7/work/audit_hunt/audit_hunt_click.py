# -*- coding: utf-8 -*-
"""audit_hunt_click.py -- the sdk_click H (D655944D...) composition hunt.

Session and attribution already reproduce with:
    H = sha256_iv0( cert40 || nonce12 || sha0hex ||
                    claims(wire map as-is, decoded) + "1300000" +
                    activity_kind + client_sdk )
The sdk_click does NOT under that exact composition -- this script scans
single-field drops / value-encodings / referrer forms to find why.
"""
import urllib.parse
import audit_hunt as AH

WANT = "D655944DD773B56AC98EAE06004F1CC273186F5C1542F3C84D211771826EC873"
NONCE = bytes.fromhex("a15c3fb686aeb4e59cea7d49")

B2 = (("activity_kind", "click"), ("client_sdk", "android5.6.0"))


def try_claims(claims, label):
    got = AH.H_of(AH.CERT40, NONCE, AH.SHA0HEX.encode(), claims)
    if got.hex().upper() == WANT:
        print("HIT:", label)
        print("   claims[%d] = %s" % (len(claims), claims.decode("latin1")))
        return True
    return False


def main():
    base = AH.wire_maps()["sdk_click"]
    print("wire fields:", len(base))
    # 0. baseline
    try_claims(AH.build_claims(base, B2), "baseline as-is")

    # 1. referrer value forms
    ref = base["referrer"]
    for label, val in (
            ("decoded", ref),
            ("wire-encoded", "adjust_reftag%3DcmTHC4v8KOvVM%26utm_source%3D"
                             "VL-Alliance%26utm_campaign%3DHM2%26utm_content%3D"
                             "HM2_1722_"),
            ("quoted", urllib.parse.quote(ref, safe="")),
            ("no utm tail", ref.split("&utm_source")[0]),
            ("reftag only", "adjust_reftag=cmTHC4v8KOvVM"),
            ("double-decoded", urllib.parse.unquote(ref))):
        m = dict(base, referrer=val)
        try_claims(AH.build_claims(m, B2), "referrer=%s" % label)

    # 2. single-field drop
    for k in sorted(base):
        m = {kk: v for kk, v in base.items() if kk != k}
        try_claims(AH.build_claims(m, B2), "drop %s" % k)

    # 3. single-field url-encoded value (per field)
    for k in sorted(base):
        m = dict(base)
        m[k] = urllib.parse.quote(base[k], safe="")
        try_claims(AH.build_claims(m, B2), "quote %s" % k)

    # 4. block2 variants
    for label, b2 in (
            ("none", None),
            ("kind only", (("activity_kind", "click"),)),
            ("sdk only", (("client_sdk", "android5.6.0"),)),
            ("sdk empty", (("activity_kind", "click"), ("client_sdk", "")))):
        try_claims(AH.build_claims(base, b2), "block2 %s" % label)

    print("done")
    return False


if __name__ == "__main__":
    main()
