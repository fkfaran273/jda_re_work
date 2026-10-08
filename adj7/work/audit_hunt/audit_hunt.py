# -*- coding: utf-8 -*-
"""audit_hunt.py -- reproduce the genuine payrupi.chls attribution H.

Target (independently decrypted by audit_decrypt.py):
  nonce12 = bb3ee2370b1132b7cfdf8b39
  H       = CB16938EAFAE0E0184A8172DB52B669FA875EA611D6AE630135D681F2CF92851

Law under test (fresh implementation, nothing imported from adj7_pure):
  H = SHA-256(custom IV0) over  prefix || nonce12 || SHA0HEX || claims
  prefix = cert40 ASCII (real device) or 00*40 (no-cert path)
  claims = 97-key pool order over the wire map, present values bare,
           "1300000" pinned between profile(<session_count) and tail,
           activity_kind/client_sdk appended when carried.

The grid walks: prefix x anchor(X) x map variants x block2 variants x
wire-value encoding (decoded vs url-encoded), for all four chls kinds.
"""
import hashlib
import json
import re
import struct
import sys
import urllib.parse

SEED = bytes.fromhex(
    "f110fb41676dba311f38c652c8f951ec"
    "3db456c07b9166a509bef66cd870654b")
CERT40 = b"C1BFAFCAFFB84B805288B985FBE48E7F33D2C6DF"
IV0 = (0x16ba6d02, 0x11a298c2, 0x82187e46, 0x4c148c22,
       0x3a5cbc15, 0x06519f14, 0x97b9e370, 0x08ec3bec)
SHA0HEX = hashlib.sha256(b"").hexdigest().upper()
PIN = "1300000"

CLAIM_POOL = (
    "ad_impressions_count ad_revenue_network ad_revenue_placement "
    "ad_revenue_unit adgroup android_id android_uuid api_level "
    "app_secret app_token app_version app_version_short att_status "
    "bundle_id callback_params campaign click_time click_time_server "
    "country created_at creative currency deduplication_id "
    "default_tracker details device_known device_name device_type "
    "environment event_callback_id event_count event_token "
    "external_device_id fb_anon_id fb_id ff_app_set_id_disabled "
    "ff_att_disabled ff_idfv_disabled ff_odm_enabled fire_adid "
    "fire_tracking_enabled found_location google_play_instant gps_adid "
    "gps_adid_src granular_third_party_sharing_options hardware_name "
    "idfa idfv initiated_by initiating_package_name install_begin_time "
    "install_begin_time_server install_version installed_at "
    "last_skan_update mcc measurement mnc needs_cost odm_info order_id "
    "originating_package_name os_build os_name os_version package_name "
    "params partner_params partner_sharing_settings payload "
    "primary_dedupe_token purchase_time push_token referrer referrer_api "
    "reftag revenue sales_region secondary_dedupe_token secret_id seq "
    "session_count session_length sharing skadn_registered_at source "
    "started_at store_app_id_from_client store_name_from_client "
    "store_name_from_system subsession_count time_spent tracker "
    "tracking_enabled updated_at activity_kind client_sdk").split()

# ---- standard SHA-256 with custom IV (independent implementation) ----
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def sha256_iv(msg, iv):
    padded = (msg + b"\x80" + b"\x00" * ((55 - len(msg) % 64) % 64)
              + struct.pack(">Q", len(msg) * 8))
    st = list(iv)
    for i in range(0, len(padded), 64):
        w = list(struct.unpack(">16I", padded[i:i + 64]))
        for j in range(16, 64):
            x, y = w[j - 15], w[j - 2]
            s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
            s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
            w.append((w[j - 16] + s0 + w[j - 7] + s1) & M32)
        a, b, c, d, e, f, g, h = st
        for j in range(64):
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            t1 = (h + s1 + ((e & f) ^ (~e & g & M32)) + _K[j] + w[j]) & M32
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) & M32
            h, g, f = g, f, e
            e = (d + t1) & M32
            d, c, b = c, b, a
            a = (t1 + t2) & M32
        st = [(x + s) & M32 for x, s in zip((a, b, c, d, e, f, g, h), st)]
    return struct.pack(">8I", *st)


def build_claims(m, block2=None):
    m = dict(m)
    if block2:
        for k, v in block2:
            m.setdefault(k, v)
    split = CLAIM_POOL.index("session_count")
    profile, tail, b2 = CLAIM_POOL[:split], CLAIM_POOL[split:-2], CLAIM_POOL[-2:]
    parts = [str(m[k]) for k in profile if m.get(k) not in (None, "")]
    parts.append(PIN)
    parts += [str(m[k]) for k in tail if m.get(k) not in (None, "")]
    parts += [str(m[k]) for k in b2 if m.get(k) not in (None, "")]
    return "".join(parts).encode("latin1")


def H_of(prefix, nonce12, anchor, claims):
    msg = prefix + nonce12 + anchor + claims
    return sha256_iv(msg, IV0)


def wire_maps():
    """The four genuine payrupi.chls request maps (decoded)."""
    out = {}
    out["session"] = dict(urllib.parse.parse_qsl(
        "store_name_from_system=com.android.vending&gps_adid_attempt=1&country=AE&"
        "api_level=37&hardware_name=CP2A.260705.006&partner_params=%7B%22payrupik_c_id"
        "%22%3A%22f9a63983-c27d-33e2-a9bb-fc10b7e58a51%22%7D&app_version=3.0.4&"
        "app_token=smxi7gqwu39c&installed_at=2026-10-06T11%3A55%3A17.820Z%2B0530&"
        "created_at=2026-10-06T11%3A55%3A42.321Z%2B0530&wait_total=0.0&"
        "device_type=phone&language=en&gps_adid=39daafc6-f5c4-412d-bf0c-e4b9482547ca&"
        "foreground=1&connectivity_type=1&device_manufacturer=Google&display_width=1080&"
        "device_name=Pixel+6a&needs_response_details=1&os_build=CP2A.260705.006&"
        "updated_at=2026-10-06T11%3A55%3A17.820Z%2B0530&cpu_type=arm64-v8a&"
        "retry_count=0&screen_size=normal&screen_format=long&last_error=0&"
        "gps_adid_src=service&push_token=elO_UX5cR66PO8ev_8y9TV%3AAPA91bE3H2KMFD0rrse1-"
        "qJqYYLhT2Qz2ht0bO8RgzJytclm7LqYqZ9uVpSHFNrnK8GAVljnB4rQ-4KcTAZNfD7KdC-"
        "HoUGaPZPMd5kD0bBT1olptZpLalU&wait_time=0.0&os_version=17&first_error=0&"
        "android_uuid=d5c688a4-27a0-4218-af7e-2efb1a21d89e&"
        "sent_at=2026-10-06T11%3A55%3A42.356Z%2B0530&offline_mode_enabled=0&"
        "environment=production&screen_density=high&attribution_deeplink=1&"
        "session_count=1&display_height=2400&package_name=in.hanafintech&"
        "initiating_package_name=com.android.vending&os_name=android&ui_mode=1&"
        "enqueue_size=0&tracking_enabled=1", keep_blank_values=True))
    out["sdk_click"] = dict(urllib.parse.parse_qsl(
        "country=AE&api_level=37&hardware_name=CP2A.260705.006&app_version=3.0.4&"
        "partner_params=%7B%22payrupik_c_id%22%3A%22f9a63983-c27d-33e2-a9bb-"
        "fc10b7e58a51%22%7D&app_token=smxi7gqwu39c&"
        "installed_at=2026-10-06T11%3A55%3A17.820Z%2B0530&device_type=phone&"
        "language=en&gps_adid=39daafc6-f5c4-412d-bf0c-e4b9482547ca&"
        "source=install_referrer&foreground=1&connectivity_type=1&"
        "os_build=CP2A.260705.006&click_time=2026-10-06T11%3A54%3A14.000Z%2B0530&"
        "cpu_type=arm64-v8a&install_version=3.0.4&screen_size=normal&"
        "gps_adid_src=service&subsession_count=1&"
        "sent_at=2026-10-06T11%3A55%3A42.373Z%2B0530&offline_mode_enabled=0&"
        "screen_density=high&session_count=1&ui_mode=1&gps_adid_attempt=1&"
        "session_length=0&created_at=2026-10-06T11%3A55%3A42.370Z%2B0530&"
        "referrer_api=google&device_manufacturer=Google&display_width=1080&"
        "time_spent=0&device_name=Pixel+6a&needs_response_details=1&"
        "updated_at=2026-10-06T11%3A55%3A17.820Z%2B0530&screen_format=long&"
        "push_token=elO_UX5cR66PO8ev_8y9TV%3AAPA91bE3H2KMFD0rrse1-"
        "qJqYYLhT2Qz2ht0bO8RgzJytclm7LqYqZ9uVpSHFNrnK8GAVljnB4rQ-4KcTAZNfD7KdC-"
        "HoUGaPZPMd5kD0bBT1olptZpLalU&"
        "click_time_server=2026-10-06T11%3A54%3A13.000Z%2B0530&os_version=17&"
        "google_play_instant=0&"
        "install_begin_time_server=2026-10-06T11%3A54%3A15.000Z%2B0530&"
        "android_uuid=d5c688a4-27a0-4218-af7e-2efb1a21d89e&"
        "referrer=adjust_reftag%3DcmTHC4v8KOvVM%26utm_source%3DVL-Alliance%26"
        "utm_campaign%3DHM2%26utm_content%3DHM2_1722_&environment=production&"
        "attribution_deeplink=1&"
        "install_begin_time=2026-10-06T11%3A54%3A15.000Z%2B0530&"
        "display_height=2400&package_name=in.hanafintech&os_name=android&"
        "tracking_enabled=1", keep_blank_values=True))
    out["attribution"] = dict(urllib.parse.parse_qsl(
        "gps_adid_attempt=1&api_level=37&app_version=3.0.4&app_token=smxi7gqwu39c&"
        "created_at=2026-10-06T11%3A55%3A45.180Z%2B0530&device_type=phone&"
        "gps_adid=39daafc6-f5c4-412d-bf0c-e4b9482547ca&foreground=1&"
        "device_name=Pixel%206a&needs_response_details=1&gps_adid_src=service&"
        "push_token=elO_UX5cR66PO8ev_8y9TV%3AAPA91bE3H2KMFD0rrse1-"
        "qJqYYLhT2Qz2ht0bO8RgzJytclm7LqYqZ9uVpSHFNrnK8GAVljnB4rQ-4KcTAZNfD7KdC-"
        "HoUGaPZPMd5kD0bBT1olptZpLalU&initiated_by=backend&os_version=17&"
        "android_uuid=d5c688a4-27a0-4218-af7e-2efb1a21d89e&"
        "sent_at=2026-10-06T11%3A55%3A45.190Z%2B0530&offline_mode_enabled=0&"
        "environment=production&attribution_deeplink=1&"
        "package_name=in.hanafintech&os_name=android&ui_mode=1&"
        "tracking_enabled=1", keep_blank_values=True))
    return out


TARGETS = {
    # NOTE: the sdk_click request's activity_kind value on the wire is
    # "click" (not "sdk_click") -- the runner's sign(kind) already uses
    # "click"; this map keeps the record label separate from the kind.
    "session": ("b1df435ecc44611a930f1a77",
                "557BFFFD503A6721498736FE4D1A4159C341192FAE8925E7219872E28EF0D505"),
    "sdk_click": ("a15c3fb686aeb4e59cea7d49",
                  "D655944DD773B56AC98EAE06004F1CC273186F5C1542F3C84D211771826EC873"),
    "attribution": ("bb3ee2370b1132b7cfdf8b39",
                    "CB16938EAFAE0E0184A8172DB52B669FA875EA611D6AE630135D681F2CF92851"),
}

WIRE_KIND = {"session": "session", "sdk_click": "click",
             "attribution": "attribution"}


def main():
    maps = wire_maps()
    prefixes = [("cert40", CERT40), ("00*40", b"\x00" * 40)]
    anchors = [("sha0hex", SHA0HEX.encode())]
    kinds = ["session", "sdk_click", "attribution"]
    hits = []
    for kind in kinds:
        nonce12, want = TARGETS[kind]
        nonce12 = bytes.fromhex(nonce12)
        want = want.encode() if isinstance(want, str) else want
        base = maps[kind]
        mapvars = [("as-is", base),
                   ("minus push_token", {k: v for k, v in base.items()
                                         if k != "push_token"})]
        wirekind = WIRE_KIND[kind]
        b2vars = [("both", (("activity_kind", wirekind), ("client_sdk", "android5.6.0"))),
                  ("kind only", (("activity_kind", wirekind),)),
                  ("sdk only", (("client_sdk", "android5.6.0"),)),
                  ("none", None)]
        for plabel, prefix in prefixes:
            for xlabel, anchor in anchors:
                for mlabel, mv in mapvars:
                    for enc in ("decoded", "encoded"):
                        mm = mv if enc == "decoded" else {
                            k: urllib.parse.quote(v, safe="") for k, v in mv.items()}
                        for blabel, b2 in b2vars:
                            claims = build_claims(mm, b2)
                            got = H_of(prefix, nonce12, anchor, claims)
                            if got.hex().upper() == want.decode():
                                hits.append((kind, plabel, xlabel, mlabel,
                                             enc, blabel, claims.decode("latin1")))
                                print("HIT  %-12s prefix=%s anchor=%s map=%s "
                                      "enc=%s block2=%s" % (kind, plabel, xlabel,
                                                            mlabel, enc, blabel))
                                print("     claims[%d]=%s" % (len(claims), claims.decode("latin1")))
    if not hits:
        print("no composition reproduced the genuine H -- dumping diagnostics")
        # closest: try attribution with both block2 + cert40 and show H
        nonce12, want = TARGETS["attribution"]
        claims = build_claims(maps["attribution"],
                              (("activity_kind", "attribution"),
                               ("client_sdk", "android5.6.0")))
        got = H_of(CERT40, bytes.fromhex(nonce12), SHA0HEX.encode(), claims)
        print("  baseline H =", got.hex().upper())
        print("  target   H =", want)
    return hits


if __name__ == "__main__":
    main()
