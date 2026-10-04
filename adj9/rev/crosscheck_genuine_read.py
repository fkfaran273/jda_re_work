r"""crosscheck_genuine_read.py — step 6 of the offline crosscheck.

Replay GET /attribution for the gps 1e63c600 identity with the APP's OWN
genuine Signature blob (pulled from the fresh adj9_capture.log) instead of a
Python-minted one. If the record is genuinely non-organic, this read returns
the campaign; if the record is genuinely Organic, it returns wy7261z.
"""
import base64
import http.client
import json
import re
import sys
import time
import urllib.parse

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.path.insert(0, HERE)
import adj9_full_chain as F

GPS = "1e63c600-e86b-4e92-a6c3-63846dd6057c"
AUID = "f2089155-1916-4052-8a95-1370799ec241"
ADID = "6a8f535a13e23278c67aece378105c25"
UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g 42 Build/S2SE32.28-28-4)"

# the device is +0530 (330 min)
F.DEV, F.UA = dict(F.MOTO), F.MOTO_UA
F.OFF_MINUTES, F.OFF_LABEL = 330, "+0530"

cap = json.load(open(HERE + r"\crosscheck_ids.json"))
auths = cap["auths"]
print("genuine blobs available: %d" % len(auths), flush=True)

now = int(time.time())
attr_params = {
    'app_token': 'jut9tib0eeps', 'gps_adid': GPS, 'android_uuid': AUID,
    'activity_kind': 'attribution', 'initiated_by': 'sdk',
    'needs_response_details': '1', 'environment': 'production',
    'att_status': '3',
    'client_sdk': 'android5.7.0', 'os_name': 'android', 'os_version': '12',
    'device_name': 'moto g42', 'device_manufacturer': 'motorola',
    'api_level': '31', 'hardware_name': 'S2SE32.28-28-4',
    'os_build': 'S2SE32.28-28-4', 'app_version': '3.14.0', 'language': 'tr',
    'display_width': '1080', 'display_height': '2237', 'screen_density': 'high',
    'created_at': F.fmt(now, 100).decode(), 'sent_at': F.fmt(now, 150).decode(),
}

res = {"gps": GPS, "auid": AUID, "adid_expected": ADID, "reads": []}
for i, blob_b64 in enumerate([auths[-1], auths[0]]):
    auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % blob_b64)
    conn = http.client.HTTPSConnection("app.adjust.com", 443, timeout=30)
    conn.putrequest("GET", "/attribution?" + urllib.parse.urlencode(attr_params),
                    skip_host=1, skip_accept_encoding=1)
    conn.putheader("Client-SDK", "android5.7.0")
    conn.putheader("Authorization", auth)
    conn.putheader("User-Agent", UA)
    conn.putheader("Host", "app.adjust.com")
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read().decode('utf-8', 'replace')
    conn.close()
    print("[blob %d] HTTP %d %s" % (i, resp.status, body[:400]), flush=True)
    res["reads"].append({"blob_index": i, "ts": None, "http": resp.status,
                         "body": body})
    time.sleep(2)

json.dump(res, open(HERE + r"\crosscheck_genuine_read_result.json", "w"), indent=1)
print("saved crosscheck_genuine_read_result.json", flush=True)
