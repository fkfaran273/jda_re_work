"""campaign_data.py — the adj8-iOS campaign/device config in the AutoLabs
backend's shape (the nested `adjust` block, `cert_sha1` + `retention` at the top
level, `tracker: adjust`), mirroring adj8/campaign_data.py.

The signer only reads c["adjust"] = {sdk, adj_signing_id, headers_id, algorithm,
native_version}; everything else here is for the runner / dashboard.
"""
# -*- coding: utf-8 -*-

CAMPAIGNS = {
    # the app whose captures prove the signer
    "neomind": {
        "app_name": "neomindios",
        "bundle_id": "com.Neon.MindAI",
        "device_name": "iPhone10,1",
        "os_name": "ios",
        "os_version": "16.7.15",
        "os_build": "20H115",
        "head_phase": [0x09],
        "tracker": "adjust",
        "cert_sha1": "",                 # iOS: the record's cert slot is all zero
        "retention": {"click": "30d", "install": "30d", "session": "30d"},
        "adjust": {
            "app_token": "qpe858kgxfr4",
            "sdk": "web-bridge5.6.2@ios5.6.2",   # the FULL client-sdk value
            "adj_signing_id": "1400000",
            "headers_id": "9",
            "algorithm": "adj8",
            "native_version": "3.67.0",
            "adj_port": 443,
            "server": "adjust",
        },
        "click_link": "",                # fill from the Adjust dashboard
        "_note": "web-bridge app; the claims carry the whole client-sdk string",
    },

    # react-native build of the same SDK generation
    "wave": {
        "app_name": "waveapp",
        "bundle_id": "com.ma.waveapp",
        "device_name": "iPhone10,1",
        "os_name": "ios",
        "os_version": "16.7.15",
        "os_build": "20H115",
        "head_phase": [0x09],
        "tracker": "adjust",
        "cert_sha1": "",
        "retention": {"click": "30d", "install": "30d", "session": "30d"},
        "adjust": {
            "app_token": "mrpexk5wqp6o",
            "sdk": "react-native5.6.0@ios5.6.2",
            "adj_signing_id": "1400000",
            "headers_id": "9",
            "algorithm": "adj8",
            "native_version": "3.67.0",
            "adj_port": 443,
            "server": "adjust",
        },
        "click_link": "",
        "_note": "react-native build; same pool law, different client_sdk string",
    },

    # plain iOS SDK (no bridge)
    "niceone": {
        "app_name": "niceoneautoios",
        "bundle_id": "com.niceonesa",
        "device_name": "iPhone12,1",
        "os_name": "ios",
        "os_version": "26.3",
        "os_build": "23A344",
        "head_phase": [0x09],
        "tracker": "adjust",
        "cert_sha1": "",
        "retention": {"click": "30d", "install": "30d", "session": "30d"},
        "adjust": {
            "app_token": "1ri26ekrhwtc",
            "sdk": "ios5.6.2",
            "adj_signing_id": "1400000",
            "headers_id": "9",
            "algorithm": "adj8",
            "native_version": "3.67.0",
            "adj_port": 443,
            "server": "adjust",
        },
        "click_link": "",
        "_note": "plain SDK: client_sdk is the bare ios5.6.2",
    },
}


def campaign(name):
    """The signer consumes exactly this dict: c['adjust'] + head_phase."""
    return CAMPAIGNS[name]


if __name__ == "__main__":
    import json
    print(json.dumps(CAMPAIGNS, indent=1))
