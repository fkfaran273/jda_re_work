# -*- coding: utf-8 -*-
"""campaign_data.py -- campaign config in the AutoLabs backend's exact shape.

The 'adjust' block also carries the signer parameters the backend's dict
omits (native_version, adj_signing_id, headers_id, algorithm).  The funnel
config (click link, timing) lives in apps.json; the device profile in
device_data.py.  Written 2/3-compatible: used by run_install.py and
run_install_py27.py.
"""

# ==========================================================================
# reference: the team's Penti campaign, verbatim in their format (adj9)
# ==========================================================================
PENTI = {
    'app_name': 'Penti',
    'package_name': 'com.penti.app',
    'app_size': 23,
    'app_version_name': u'3.13.9',
    'app_version_code': u'31309',

    'tracker': 'adjust',
    'adjust': {
        "app_token": "jut9tib0eeps",
        "sdk": u'android5.7.0',
        "native_version": "5.0.0",
        "adj_signing_id": "1500000",
        "headers_id": "10",
        "algorithm": "adj9",
        # consumed DIRECTLY by adj9_pure.sign_request (c.get("head_phase") ->
        # region_head selector prefix).  adj8 has no equivalent: its head is
        # fully determined by the nonce.
        "head_phase": ["0x2b", "0x48"],
    },

    'supported_os': '8.0',

    "cert_sha1": "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
}

# ==========================================================================
# ours: be Customer -- xyz.be.customer, Adjust Signature SDK 3.67.0 (adj8)
# ==========================================================================
CUSTOMER = {
    'app_name': 'be Customer',
    'package_name': 'xyz.be.customer',
    'app_size': 23,
    'app_version_name': u'2.6.153',
    'app_version_code': u'206153',

    'tracker': 'adjust',
    'adjust': {
        "app_token": "7z9fjy072rgg",
        "sdk": u'android5.7.0',
        "native_version": "3.67.0",
        "adj_signing_id": "1400000",
        "headers_id": "9",
        "algorithm": "adj8",
    },

    'supported_os': '8.0',

    # SHA-1 of the APK signing cert (META-INF/BNDLTOOL.RSA of the
    # device-pulled base.apk); confirmed on-device by the LSPosed oracle.
    "cert_sha1": "07e6d5074866a3b8e1fb6efcb4714aff91624550",
    # adj8 (3.x) has no adj_verification -- that field is 5.x only.
    "adj_verification": None,
}

# ==========================================================================
# graddef -- com.grad.def, the yamistar capture's app (BOOKED adj8 flow:
# cap/yamistar_capture.json, network Mobavenue).  v2-signed only (no
# META-INF/*.RSA): its cert_sha1 needs one genuine blob captured on device
# to fill -- the signer refuses to sign with an empty cert.
# ==========================================================================
GRADDEF = {
    'app_name': 'graddef',
    'package_name': 'com.grad.def',
    'app_size': 24,
    'app_version_name': u'2.60.92',
    'app_version_code': u'26092',

    'tracker': 'adjust',
    'adjust': {
        "app_token": "ag7cwhs46ghs",
        "sdk": u'android5.6.1',
        "native_version": "3.67.0",
        "adj_signing_id": "1400000",
        "headers_id": "9",
        "algorithm": "adj8",
    },

    'supported_os': '8.0',

    "cert_sha1": "",
    "adj_verification": None,
}

CAMPAIGNS = {"penti": PENTI, "customer": CUSTOMER, "graddef": GRADDEF}


def get(name=None):
    """campaign dict by name; the default is ours."""
    return dict(CAMPAIGNS[name] if name else CUSTOMER)


def signer_fields(campaign):
    """The subset adj8_pure.sign_request needs, flattened out of the nested
    'adjust' block."""
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
