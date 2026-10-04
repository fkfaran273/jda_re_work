"""nonorganic_test2.py — click FIRST then session then attribution (correct install order)."""
import base64, datetime, json, struct, sys, time, urllib.parse, urllib.request, uuid, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header
D = json.load(open(os.path.join(HERE, "fin_descs.json")))
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
GOLD = json.load(open(os.path.join(HERE, "golden_saz.json")))
S1P, S2P = GOLD["s1"]["params"], GOLD["s2"]["params"]
REFERRER = "adjust_reftag=cDio4ZXu5ibgl&utm_source=VKM+Digital+Yeni&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic"
def ts20(dt): return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200").encode()
def mint(second, created_new: bytes):
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"])) for d in D["descs"]}
    d10 = by[10][1].replace(b"2026-09-12T21:15:11.678Z+0200", created_new)
    by[10] = (len(d10)//4, d10)
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    status = ex.run(max_steps=20_000_000)
    from collections import defaultdict
    sinks = defaultdict(dict)
    for (s, n, v) in ex.emit_trace: sinks[s][n] = v
    blob = b"".join(struct.pack(">I", sinks[0x5500000000].get(i, 0)) for i in range(48))
    assert blob[:16] == make_header(second)
    return status, ex.steps, blob
UA = "Dalvik/2.1.0 (Linux; U; Android 11; DN2101 Build/RP1A.200720.011)"
def send(url, params, blob, method="POST"):
    sig = base64.b64encode(blob).decode()
    auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig)
    if method == "POST":
        req = urllib.request.Request(url, data=urllib.parse.urlencode(params).encode(), method="POST")
    else:
        req = urllib.request.Request(url + "?" + urllib.parse.urlencode(params), method="GET")
    # SAZ order: Client-SDK -> Authorization -> Content-Type -> User-Agent -> Accept-Encoding
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("Authorization", auth)
    if method == "POST": req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", UA)
    req.add_header("Accept-Encoding", "gzip")
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read().decode("utf-8", "replace")
    except Exception as e:
        try: return "ERR", e.read().decode("utf-8", "replace")[:2000]
        except Exception: return "ERR", str(e)[:2000]
gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
t0 = datetime.datetime.now(datetime.timezone.utc)
click_dt, install_dt = t0 - datetime.timedelta(minutes=3), t0 - datetime.timedelta(minutes=2, seconds=30)
sess_dt = t0 - datetime.timedelta(minutes=2)
print("gps", gps, "auid", auid)
# 1. CLICK first
sec1 = int(time.time()); c1new = ts20(click_dt)
st1, n1, b1 = mint(sec1, c1new)
print("click mint", st1, n1, b1.hex()[:16])
clk = dict(S2P)
clk.update({"gps_adid": gps, "android_uuid": auid, "created_at": c1new.decode(),
 "sent_at": ts20(datetime.datetime.now(datetime.timezone.utc)).decode(),
 "installed_at": install_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200"),
 "referrer": REFERRER, "source": "install_referrer", "referrer_api": "google",
 "click_time": click_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530"),
 "click_time_server": click_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530"),
 "install_begin_time": install_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530"),
 "install_begin_time_server": install_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530")})
s1, r1 = send("https://app.adjust.com/sdk_click", clk, b1)
print("CLICK:", s1, r1[:300]); time.sleep(3)
# 2. SESSION
sec2 = int(time.time()); c2new = ts20(sess_dt)
st2, n2, b2 = mint(sec2, c2new)
print("session mint", st2, n2, b2.hex()[:16])
ses = dict(S1P)
ses.update({"gps_adid": gps, "android_uuid": auid, "created_at": c2new.decode(),
 "sent_at": ts20(datetime.datetime.now(datetime.timezone.utc)).decode(),
 "installed_at": install_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200"),
 "updated_at": install_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200")})
s2, r2 = send("https://app.adjust.com/session", ses, b2)
print("SESSION:", s2, r2[:300]); time.sleep(3)
# 3. ATTRIBUTION — exact S4 23-param set, fresh ids only
sec3 = int(time.time()); c3now = datetime.datetime.now(datetime.timezone.utc); c3new = ts20(c3now)
st3, n3, b3 = mint(sec3, c3new)
attr = {"gps_adid_attempt": "1", "api_level": "30", "app_version": "3.12.1",
 "app_token": "jut9tib0eeps", "created_at": c3new.decode().replace("+0200", "+0530"),
 "device_type": "phone", "gps_adid": gps, "foreground": "1", "device_name": "DN2101",
 "needs_response_details": "1", "gps_adid_src": "service",
 "push_token": "emsp6HGsRJWM9avd-xXS5Y:APA91bFZPSOQh57RUHzVJjWwt16UALPH7mcy5IDUxdXiiXolDNry5NinRRdk5W0lLI2BnNyusb7DHeBhAbtTbHpYy4ziep7JUo2wuTgHkAR7Go4gFoVLKWI",
 "initiated_by": "backend", "os_version": "11", "android_uuid": auid,
 "sent_at": ts20(c3now).decode().replace("+0200", "+0530"),
 "offline_mode_enabled": "0", "environment": "production", "attribution_deeplink": "1",
 "package_name": "com.penti.app", "os_name": "android", "ui_mode": "1", "tracking_enabled": "1"}
s3, r3 = send("https://app.adjust.com/attribution", attr, b3, method="GET")
print("ATTR:", s3, r3[:2000])
json.dump({"gps": gps, "auid": auid, "referrer": REFERRER, "click": [s1, r1[:1000]],
 "session": [s2, r2[:1000]], "attr": [s3, r3[:2000]]}, open(os.path.join(HERE, "nonorganic_result2.json"), "w"), indent=1)
print("saved nonorganic_result2.json")
