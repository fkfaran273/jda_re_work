# -*- coding: utf-8 -*-
"""crosscheck.py -- same inputs on this interpreter, fixed nonce."""
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
FIXED = bytes(bytearray(range(12)))
os.urandom = lambda n: FIXED[:n] if n <= 12 else FIXED * 4

SEC = int(time.time()) - 5
FIELDS = {
    "bundle_id": "com.fdjservices.nirio", "app_token": "cv4d2hlazp4w",
    "app_version": "494", "app_version_short": "16.4.6",
    "att_status": "3", "created_at": "2026-10-09T15:00:00.111Z+0530",
    "sent_at": "2026-10-09T15:00:00.150Z+0530", "os_name": "ios",
    "os_version": "16.7.16", "device_name": "iPhone10,1",
    "device_type": "iPhone", "environment": "production",
    "idfa": "AAAABBBB-CCCC-4DDD-8EEE-FFFF00001111", "idfv": "11112222-3333",
    "primary_dedupe_token": "471fd96d-cbb5-4bae-80f2-13307b2d8e8a",
    "session_count": "1", "installed_at": "2026-10-09T14:59:00.000Z+0530",
    "retry_count": "0", "enqueue_size": "0",
    "foreground": "1", "needs_response_details": "1",
    "attribution_deeplink": "1", "offline_mode_enabled": "0",
    "send_in_background_enabled": "0", "started_at":
        "2026-10-09T14:40:00.000Z+0530",
}
KINDS = ("session", "click", "attribution", "event", "info")
out = []
for k in KINDS:
    if 'py27' in sys.argv or 'py27' in os.path.basename(sys.argv[0]):
        import adj7ios_pure_py27 as sg
    else:
        import adj7ios_pure as sg
    auth, blob = sg.sign_request(FIELDS, k, second=SEC,
                                 client_sdk="react-native5.4.4@ios5.4.6",
                                 headers_id="7", native_version="3.61.0")
    out.append("%s %s" % (k, blob.hex().upper() if hasattr(blob, 'hex')
                          else blob.encode('hex')))
open(os.path.join(HERE, 'crosscheck_%s.txt'
                  % ('py27' if 'py27' in sys.argv[0] else 'py3')),
     'w').write("\n".join(out))
print("\n".join(out)[:200])
