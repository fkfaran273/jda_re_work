"""attr_check.py — signed attribution lookup for a given gps_adid."""
import base64, datetime, json, struct, sys, time, urllib.parse, urllib.request, uuid, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header
D = json.load(open(os.path.join(HERE, "fin_descs.json")))
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
UA = "Dalvik/2.1.0 (Linux; U; Android 16; CPH2585 Build/CPH2585_16.0.5.702(EX01))"
GPS = sys.argv[1] if len(sys.argv) > 1 else "b60338da-6a23-4647-a9af-0026fa8c1b86"
AUID = sys.argv[2] if len(sys.argv) > 2 else str(uuid.uuid4())  # exact pair when known

def swap_eq(data, old, new):
    if len(old) == len(new) and data.count(old) >= 1:
        return data.replace(old, new)
    return data

sec = int(time.time()) + 35
dt = datetime.datetime.fromtimestamp(sec - 1, datetime.timezone.utc) + datetime.timedelta(hours=5, minutes=30)
c = dt.strftime("%Y-%m-%dT%H:%M:%S.666Z+0530").encode()
s = dt.strftime("%Y-%m-%dT%H:%M:%S.696Z+0530").encode()
by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"])) for d in D["descs"]}
import secrets
by[4] = (8, secrets.token_bytes(32))
by[0] = (36, bytes(144))
d10 = by[10][1].replace(b"2026-09-12T21:15:11.678Z+0200", c.replace(b"+0530", b"+0200"))
d10 = swap_eq(d10, b"f476b3d4-e0b1-4707-bc43-6153d17f7f8c", GPS.encode())
d10 = swap_eq(d10, b"d773f47f-fc0e-4994-9cf7-7c3cf5bb6368", AUID.encode())
d10 = swap_eq(d10, b"moto g42", b"CPH2585 ")
# base app_version IS 3.13.9 == installed on CPH2585: no swap needed
d10 = swap_eq(d10, b"12com.penti.app", b"16com.penti.app")
d10 = swap_eq(d10, b"31jut9tib0eeps", b"36jut9tib0eeps")
d10 = swap_eq(d10, b"com.android.vending12", b"com.android.vending16")
# HW slot 14ch vs qcom 4ch: no equal-length swap; base kept (server body-tolerant)
by[10] = (len(d10)//4, d10)
ex = FinEx(sec, [(by[i][0], 0, by[i][1]) for i in ORDER])
status = ex.run(max_steps=20_000_000)
from collections import defaultdict
sinks = defaultdict(dict)
for (a, n, v) in ex.emit_trace: sinks[a][n] = v
blob = b"".join(struct.pack(">I", sinks[0x5500000000].get(i, 0)) for i in range(48))
assert blob[:16] == make_header(sec), "header law broken"
print("mint", status, ex.steps, "sec", sec, flush=True)
sig = base64.b64encode(blob).decode()
auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig)
params = {"gps_adid_attempt": "1", "api_level": "36", "app_version": "3.13.9",
 "app_token": "jut9tib0eeps", "created_at": c.decode(), "device_type": "phone",
 "gps_adid": GPS, "foreground": "1", "device_name": "CPH2585", "needs_response_details": "1",
 "gps_adid_src": "service",
 "push_token": "emsp6HGsRJWM9avd-xXS5Y:APA91bFZPSOQh57RUHzVJjWwt16UALPH7mcy5IDUxdXiiXolDNry5NinRRdk5W0lLI2BnNyusb7DHeBhAbtTbHpYy4ziep7JUo2wuTgHkAR7Go4gFoVLKWI",
 "initiated_by": "backend", "os_version": "16", "android_uuid": AUID,
 "sent_at": s.decode(), "offline_mode_enabled": "0", "environment": "production",
 "attribution_deeplink": "1", "package_name": "com.penti.app", "os_name": "android",
 "ui_mode": "1", "tracking_enabled": "1"}
req = urllib.request.Request("https://app.adjust.com/attribution?" + urllib.parse.urlencode(params), method="GET")
req.add_header("Client-SDK", "android5.7.0")
req.add_header("Authorization", auth)
req.add_header("User-Agent", UA)
req.add_header("Accept-Encoding", "gzip")
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode("utf-8", "replace")
        print("STATUS", r.status)
        print(body[:2000])
        json.dump({"gps": GPS, "auid": AUID, "status": r.status, "body": body},
                  open(os.path.join(HERE, "attr_check_result.json"), "w"), indent=1)
except Exception as e:
    try: print("ERR", e.read().decode()[:2000])
    except Exception: print("ERR", str(e)[:500])
