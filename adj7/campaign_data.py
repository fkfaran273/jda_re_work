# -*- coding: utf-8 -*-
"""campaign_data.py -- niri campaign config in the AutoLabs backend's exact
shape (same nested layout as adj8/campaign_data.py).

The 'adjust' block also carries the signer parameters the backend's dict
omits (native_version, adj_signing_id, headers_id, algorithm).  The funnel
config (click link, timing) lives in apps.json; the device profile in
device_data.json.  Written 2/3-compatible.

adj7 = Adjust Signature SDK 3.6x:  adj_signing_id 1300000, headers_id 7 (3.61.0) / 8 (3.62.0),
native_version 3.62.0, 304-byte UPPER-HEX signature in the Authorization
header (blob = header(16) || body(256) || tag(32)).

Provenance: genuine capture adj7/cap/nirio_16Feb/nirio_16Feb_oneplus7_newapp_
adjust.json (OnePlus 7 GM1901, Android 10, 12 Adjust requests, 2026-02-16).
The capture device ran native 3.61.0/headers_id 7; the signer backend here is
the 3.62.0 lib (headers_id 8) -- same adj_signing_id 1300000, same claims law.
"""

# ==========================================================================
# ours: niri -- com.fdjservices.nirio (Adjust Signature SDK 3.62.0, adj7)
# ==========================================================================
NIRI = {
    'app_name': 'niri',
    'package_name': 'com.fdjservices.nirio',
    'app_size': 23,
    # app_version from the capture bodies ("14.4.8"); the code is not on the
    # adj7 wire -- 14408 is the conventional guess for the backend's format.
    'app_version_name': u'14.4.8',
    'app_version_code': u'14408',

    'tracker': 'adjust',
    'adjust': {
        "app_token": "cv4d2hlazp4w",
        "sdk": u'react-native5.4.4@android5.4.5',
        "native_version": "3.61.0",   # the genuine niri device (capture 16 Feb)
        "adj_signing_id": "1300000",
        "headers_id": "7",            # 3.61.0 -> headers_id 7 (3.62.0 -> 8)
        "algorithm": "adj7",
    },

    'supported_os': '8.0',

    # SHA-1 of the APK signing cert (adj7/apks/signer_v2_cert0.der).
    "cert_sha1": "0e11813dd360d8aac04b6db33293cfbc4d3f1370",
    # adj7 (3.x) has no adj_verification -- that field is 5.x only.
    "adj_verification": None,
}

HANAFINTECH = {
    "comment": "in.hanafintech -- the 2026-10-06 genuine capture (payrupi.chls): "
               "adj7 / 3.62.0 / headers_id 8, app_version 3.0.4, cert from the "
               "pulled APK == the record's \"c\" slot",
    "package_name": "in.hanafintech",
    "app_version_name": "3.0.4",
    "app_version_code": "86",
    "cert_sha1": "c1bfafcaffb84b805288b985fbe48e7f33d2c6df",
    "tracker": "adjust",
    "adjust": {
        "app_token": "smxi7gqwu39c",
        "sdk": "android5.6.0",
        "native_version": "3.62.0",
        "adj_signing_id": "1300000",
        "headers_id": "8",
        "algorithm": "adj7",
    },
    "supported_os": "8.0",
}

CAMPAIGNS = {"nirio": NIRI, "hanafintech": HANAFINTECH}


def get(name=None):
    """campaign dict by name; the default is ours."""
    return dict(CAMPAIGNS[name] if name else NIRI)


def signer_fields(campaign):
    """The signer-relevant subset, flattened out of the nested 'adjust'
    block.  mint_adj7(kind, params) itself only needs the wire map -- this is
    the config view for future backends (adj7_pure, py27 builds)."""
    a = campaign["adjust"]
    return {
        "app_token": a["app_token"],
        "client_sdk": a["sdk"],
        "package_name": campaign["package_name"],
        "app_version": campaign["app_version_name"],
        "cert_sha1": campaign.get("cert_sha1", ""),
        "native_version": a["native_version"],
        "adj_signing_id": a["adj_signing_id"],
        "headers_id": a["headers_id"],
        "algorithm": a["algorithm"],
    }


if __name__ == "__main__":
    import json
    print(json.dumps(signer_fields(get()), indent=2, sort_keys=True))
