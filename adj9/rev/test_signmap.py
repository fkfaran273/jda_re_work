"""direct test of hyp_run3's sign_map"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# just run the script up to the mint step with debug
import hyp_run3
import desc10_law as D

# build the sign_map exactly like hyp_run3 does
import time
import uuid

gps = "test-gaid"
auid = "test-auid"
now = time.time()
vals = {
    "store_name_from_system": "com.android.vending",
    "gps_adid_attempt": "1", "api_level": "31",
    "hardware_name": "S2SE32.28-28-4", "app_version": "3.13.9",
    "app_token": "jut9tib0eeps", "installed_at": hyp_run3.plus0530(now - 2, 200),
    "created_at": hyp_run3.plus0530(now, 100), "wait_total": "0.0",
    "device_type": "phone", "language": "tr", "gps_adid": gps,
    "foreground": "1", "connectivity_type": "1",
    "device_manufacturer": "motorola", "display_width": "1080",
    "device_name": "moto g42", "needs_response_details": "1",
    "os_build": "S2SE32.28-28-4", "updated_at": hyp_run3.plus0530(now - 2, 200),
    "cpu_type": "arm64-v8a", "retry_count": "0", "screen_size": "normal",
    "screen_format": "long", "last_error": "0", "gps_adid_src": "service",
    "wait_time": "0.0", "os_version": "12", "first_error": "0",
    "android_uuid": auid, "sent_at": hyp_run3.plus0530(now, 130),
    "offline_mode_enabled": "0", "environment": "production",
    "screen_density": "high", "attribution_deeplink": "1",
    "session_count": "1", "display_height": "2237",
    "package_name": "com.penti.app",
    "initiating_package_name": "com.android.vending",
    "os_name": "android", "ui_mode": "1", "enqueue_size": "0",
    "tracking_enabled": "1",
}
sign_map = dict(vals)
sign_map.update({
    "activity_kind": "session",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
    "adj_signing_id": "1500000", "headers_id": "10",
    "native_version": "5.0.0", "algorithm": "adj9",
    "client_sdk": "android5.7.0",
})

# check the three failing keys
for k in ("created_at", "installed_at", "updated_at"):
    v = sign_map.get(k)
    print("%s: %s (type=%s, bool=%s)" % (k, repr(v)[:50], type(v).__name__, bool(v)))

try:
    raw = D.build_desc10(sign_map, "session")
    print("build_desc10 OK: %d chars" % len(raw))
except KeyError as e:
    print("KeyError:", e)
