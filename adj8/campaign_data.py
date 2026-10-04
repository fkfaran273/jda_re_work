# -*- coding: utf-8 -*-
"""campaign_data.py -- campaign config in the AutoLabs backend's shape.

Same structure the team's callog shows (nested "adjust" block, cert_sha1 and
adj_verification at the top level, retention table), plus the fields our
adj8 signer needs.  Written 2/3-compatible: used by both run_install.py and
run_install_py27.py.

The penti entry below is the shape theirs uses, kept as the reference for
what a campaign looks like; "customer" is ours (xyz.be.customer, adj8).
"""

# ==========================================================================
# reference: the team's Penti campaign, verbatim in their format
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
        "adj_port": "60515",
        "server": "adj_t3",
        # adj8/adj9 signer parameters (absent from their dict; our signer
        # needs them)
        "native_version": "5.0.0",
        "adj_signing_id": "1500000",
        "headers_id": "10",
        "algorithm": "adj9",
        "head_phase": ["0x2b", "0x48"],
    },

    'supported_os': '8.0',

    'retention': {
        1: 25, 2: 25, 3: 24, 4: 24, 5: 23, 6: 22, 7: 20, 8: 20, 9: 20,
        10: 19, 11: 19, 12: 19, 13: 18, 14: 18, 15: 17, 16: 16, 17: 15,
        18: 14, 19: 13, 20: 13, 21: 13, 22: 13, 23: 11, 24: 10, 25: 10,
        26: 9, 27: 8, 28: 8, 29: 6, 30: 6, 31: 5, 32: 5, 33: 4, 34: 4,
        35: 3
    },

    "cert_sha1": "fad0f10d60f93c17937b2f1eb6c09691ae7d74bd",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",

    # ours only: the tracker link and the funnel timing
    "click_link": ("https://app.adjust.com/1sd1lk6a?campaign=AH"
                   "&adgroup=vkm_0926_36&creative=penti_generic"
                   "&click_id={gaid}&gps_adid={gaid}"),
    "gap_seconds": 180,
    "poll_delays": [3, 8, 20],
    # click -> install gap.  Adjust silently drops sdk_clicks under ~10 s as
    # click fraud (HTTP 200, attribution just stays Organic); the genuine
    # be booking in be_ct_logs_3oct_pxl.chls had ~48 s.
    "install_after": 48,
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
        "adj_port": "60515",
        "server": "adj_t3",
        # adj8 signer parameters
        "native_version": "3.67.0",
        "adj_signing_id": "1400000",
        "headers_id": "9",
        "algorithm": "adj8",
    },

    'supported_os': '8.0',

    'retention': {
        1: 25, 2: 25, 3: 24, 4: 24, 5: 23, 6: 22, 7: 20, 8: 20, 9: 20,
        10: 19, 11: 19, 12: 19, 13: 18, 14: 18, 15: 17, 16: 16, 17: 15,
        18: 14, 19: 13, 20: 13, 21: 13, 22: 13, 23: 11, 24: 10, 25: 10,
        26: 9, 27: 8, 28: 8, 29: 6, 30: 6, 31: 5, 32: 5, 33: 4, 34: 4,
        35: 3
    },

    # SHA-1 of the APK signing cert (META-INF/BNDLTOOL.RSA of the device-pulled
    # base.apk); confirmed on-device by the LSPosed oracle.
    "cert_sha1": "07e6d5074866a3b8e1fb6efcb4714aff91624550",
    # adj8 (3.x) has no adj_verification -- that field is 5.x only.  Left here
    # as None so the key set matches the backend's shape.
    "adj_verification": None,

    # The ACTIVE tracker link (user, 2026-10-04): mobpine offer 23472302.
    # Resolves through begroup.go.link adj_t=2390uba9 (DNS_ADD /
    # ADD_Arb_21_RFAMP_ -- the Dinos_Dynamic_Partner family the booked
    # capture used).  mobpine forwards sub3 as gps_adid into the go.link
    # click, so sub3={gaid} makes the click device-matched.
    "click_link": ("http://clicks.mobpine.com/api/track/v1/click"
                   "?aff_id=3&offer_id=23472302&sub3={gaid}"),
    "agent": "",
    "gap_seconds": 30,
    "poll_delays": [30, 45, 60, 60],
    "install_after": 48,
}

CAMPAIGNS = {"penti": PENTI, "customer": CUSTOMER}

# ==========================================================================
# graddef -- com.grad.def, the yamistar capture's app (BOOKED adj8 flow:
# cap/yamistar_capture.json, network Mobavenue).  Client-SDK android5.6.1.
# The booked flow carries external_device_id (16-hex per-install id) and
# google_app_set_id (GMS App Set ID UUID) on EVERY request -- the runner
# generates fresh ones per run when "device_ids" is set.
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
        "adj_port": "60515",
        "server": "adj_t3",
        "native_version": "3.67.0",
        "adj_signing_id": "1400000",
        "headers_id": "9",
        "algorithm": "adj8",
    },

    'supported_os': '8.0',

    'retention': {
        1: 25, 2: 25, 3: 24, 4: 24, 5: 23, 6: 22, 7: 20, 8: 20, 9: 20,
        10: 19, 11: 19, 12: 19, 13: 18, 14: 18, 15: 17, 16: 16, 17: 15,
        18: 14, 19: 13, 20: 13, 21: 13, 22: 13, 23: 11, 24: 10, 25: 10,
        26: 9, 27: 8, 28: 8, 29: 6, 30: 6, 31: 5, 32: 5, 33: 4, 34: 4,
        35: 3
    },

    # v2-signed only (no META-INF/*.RSA) -- the native extracts the cert from
    # the APK signing block itself; apks/graddef_base.apk is the exact build
    # pulled from the device.
    "cert_sha1": "",
    "adj_verification": None,

    "click_link": ("http://clicks.mobpine.com/api/track/v1/click"
                   "?aff_id=3&offer_id=23480213&sub1={dp2}&sub2={agent}"
                   "&sub3={gaid}"),
    "agent": "",
    "device_ids": True,
    "gap_seconds": 30,
    "poll_delays": [3, 8, 20],
    "install_after": 48,
}
CAMPAIGNS["graddef"] = GRADDEF


def get(name=None):
    """campaign dict by name; the default is ours."""
    if name:
        return dict(CAMPAIGNS[name])
    return dict(CUSTOMER)


def signer_fields(campaign):
    """The subset adj8_pure / adj9_pure need, flattened out of the nested
    'adjust' block."""
    a = campaign["adjust"]
    out = {
        "app_token": a["app_token"],
        "client_sdk": a["sdk"],
        "sdk_version": a["sdk"],
        "package_name": campaign["package_name"],
        "app_version": campaign["app_version_name"],
        "cert_sha1": campaign.get("cert_sha1", ""),
        "native_version": a.get("native_version", ""),
        "adj_signing_id": a.get("adj_signing_id", ""),
        "headers_id": a.get("headers_id", ""),
        "algorithm": a.get("algorithm", ""),
        "click_link": campaign["click_link"],
        "install_after": campaign.get("install_after", 48),
        "poll_delays": campaign.get("poll_delays", [3, 8, 20]),
    }
    if campaign.get("adj_verification"):
        out["adj_verification"] = campaign["adj_verification"]
    if a.get("head_phase"):
        out["head_phase"] = a["head_phase"]
    if campaign.get("agent"):
        out["agent"] = campaign["agent"]
    return out


if __name__ == "__main__":
    import json
    print(json.dumps(signer_fields(get()), indent=2, sort_keys=True))
