"""tracker_chain2.py — match ALL: +0530, header=created+1 with future-second, tracker-time click."""
import base64, datetime, json, struct, sys, time, urllib.parse, urllib.request, uuid, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header
D = json.load(open(os.path.join(HERE, "fin_descs.json")))
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
GOLD = json.load(open(os.path.join(HERE, "golden_saz.json")))
S1P, S2P = GOLD["s1"]["params"], GOLD["s2"]["params"]
UA = "Dalvik/2.1.0 (Linux; U; Android 16; CPH2585 Build/CPH2585_16.0.5.702(EX01))"
# Live props from e5e7108f (CPH2585, non-rooted, the phone that got non-organic):
# release 16 / sdk 36 / display CPH2585_16.0.5.702(EX01) / ro.hardware qcom /
# app 3.13.9 (31309) / locale en-GB / mcc-mnc 40410 / wm override 1080x2376@480
DEV = {"api_level": "36", "os_version": "16", "device_name": "CPH2585",
 "device_manufacturer": "OnePlus", "hardware_name": "qcom",
 "os_build": "CPH2585_16.0.5.702(EX01)", "app_version": "3.13.9",
 "install_version": "3.13.9", "language": "en", "mcc": "404", "mnc": "10",
 "display_width": "1080", "display_height": "2376", "screen_density": "xxhigh"}
MINT_SKEW = 35  # FinEx ~35s here; aim header second ~= send time

def fmt0530(ts: int, ms: int) -> bytes:
    dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc) + datetime.timedelta(hours=5, minutes=30)
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z+0530").encode()

def swap_eq(data: bytes, old: bytes, new: bytes) -> bytes:
    if old is not None and new is not None and len(old) == len(new) and data.count(old) >= 1:
        return data.replace(old, new)
    print("  ! swap SKIP old=%r new=%r (len %s vs %s, found %d)" % (
        old, new, len(old) if old else -1, len(new) if new else -1,
        data.count(old) if old else -1))
    return data

ZERO0 = True  # slice 82: zero-filled #0 routes exit-clean + live-200; kills stale heap ptrs
HRAND = True  # hflip_test 2026-09-14: with ZERO0, 1-bit AND fully-random H both exit-clean 16117703; replay not needed

def mint(second, created_new: bytes, gps_new=None, uuid_new=None, install_new=None):
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"])) for d in D["descs"]}
    if HRAND:
        import secrets
        by[4] = (8, secrets.token_bytes(32))  # fresh random H per call (like real: H differs per canonical)
    if ZERO0:
        by[0] = (36, bytes(144))  # drop replayed heap pointers; zeros proven live-accepted
    # body holds +0200 whcap stamps; swap created slot (same 29-char length) — keep +0200 in body,
    # cleartext uses +0530 (server 200-proven tolerant); binding header=created+1 kept on wire second
    d10 = by[10][1].replace(b"2026-09-12T21:15:11.678Z+0200", created_new.replace(b"+0530", b"+0200"))
    if gps_new: d10 = swap_eq(d10, b"f476b3d4-e0b1-4707-bc43-6153d17f7f8c", gps_new)
    if uuid_new: d10 = swap_eq(d10, b"d773f47f-fc0e-4994-9cf7-7c3cf5bb6368", uuid_new)
    d10 = swap_eq(d10, b"moto g42", b"CPH2585 ")  # 8==8 device slot, space-padded (wire sends CPH2585)
    # base app_version IS 3.13.9 == CPH2585 installed version: no swap needed
    d10 = swap_eq(d10, b"12com.penti.app", b"16com.penti.app")  # os_version 12->16
    d10 = swap_eq(d10, b"31jut9tib0eeps", b"36jut9tib0eeps")  # api_level 31->36
    d10 = swap_eq(d10, b"com.android.vending12", b"com.android.vending16")  # store os_version
    # base HW slot "S2SE32.28-28-4" is 14ch, CPH2585 Build.HARDWARE "qcom" is 4ch:
    # no equal-length swap exists -> leave base bytes (server body-tolerant); wire sends qcom
    if install_new:
        ins0200 = install_new.replace(b"+0530", b"+0200")
        d10 = swap_eq(d10, b"2026-09-08T12:20:49.782Z+0200", ins0200)
        d10 = swap_eq(d10, b"2026-09-10T07:26:18.015Z+0200", ins0200)
    by[10] = (len(d10)//4, d10)
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    status = ex.run(max_steps=20_000_000)
    from collections import defaultdict
    sinks = defaultdict(dict)
    for (s, n, v) in ex.emit_trace: sinks[s][n] = v
    blob = b"".join(struct.pack(">I", sinks[0x5500000000].get(i, 0)) for i in range(48))
    assert blob[:16] == make_header(second)
    return status, ex.steps, blob

def send(url, params, blob, method="POST"):
    sig = base64.b64encode(blob).decode()
    auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",headers_id="10",native_version="5.0.0",adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig)
    if method == "POST":
        req = urllib.request.Request(url, data=urllib.parse.urlencode(params).encode(), method="POST")
    else:
        req = urllib.request.Request(url + "?" + urllib.parse.urlencode(params), method="GET")
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

def tracker_referrer(gps, click_id):
    # PLAIN marketing URL only: real browser clicks carry no click_id/idfa/callbacks.
    # Adjust mints its own click id server-side; our inventions may poison the click row.
    base = "https://app.adjust.com/1sd1lk6a"
    q = {"campaign": "AH", "adgroup": "vkm_0926_36", "creative": "penti_generic"}
    url = base + "?" + urllib.parse.urlencode(q)
    class NoRed(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl): return None
    op = urllib.request.build_opener(NoRed)
    try:
        op.open(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=30)
        return None, "no-redirect"
    except Exception as e:
        try:
            loc = e.headers.get("Location", "")
            ref = loc.split("referrer=", 1)[1] if "referrer=" in loc else ""
            return urllib.parse.unquote(ref), loc
        except Exception as e2: return None, str(e2)[:300]

gps, auid = str(uuid.uuid4()), str(uuid.uuid4())
click_id = "clk-" + uuid.uuid4().hex[:12]
t_track = int(time.time())
print("gps", gps, "auid", auid, "click_id", click_id, "track_t", t_track)
ref, loc = tracker_referrer(gps, click_id)
print("REFERRER:", ref)
assert ref and "adjust_reftag=" in ref
reftag = ref.split("adjust_reftag=", 1)[1].split("&")[0]
print("reftag", reftag)

# 1. CLICK — click_time = tracker time, created = future-second-1
sec1 = int(time.time()) + MINT_SKEW
c1 = fmt0530(sec1 - 1, 961)  # like SAZ .961
s1sent = fmt0530(sec1 - 1, 970)
ins1 = fmt0530(sec1 - 170, 774)  # ~3min before, .774 like SAZ
st1, n1, b1 = mint(sec1, c1, gps.encode(), auid.encode(), ins1)
print("click mint", st1, n1, "sec", sec1, "created", c1.decode())
clk = dict(S2P)
clk.update({"gps_adid": gps, "android_uuid": auid, "created_at": c1.decode(), "sent_at": s1sent.decode(),
  "installed_at": fmt0530(sec1 - 170, 774).decode(),  # ~3min before, .774 like SAZ
  "referrer": ref, "source": "install_referrer", "referrer_api": "google",
  "click_time": fmt0530(t_track, 0).decode(), "click_time_server": fmt0530(t_track + 1, 0).decode(),
  "install_begin_time": fmt0530(t_track + 5, 0).decode(), "install_begin_time_server": fmt0530(t_track + 6, 0).decode()})
clk.update(DEV)  # CPH2585 wire values; NOTE: real app sends no click_id -> dropped
s1, r1 = send("https://app.adjust.com/sdk_click", clk, b1)
print("CLICK:", s1, r1[:300])
print("  header_sec", sec1, "send_skew~", int(time.time()) - sec1)
time.sleep(3)
# 2. SESSION — created = future-second-1, sent +14ms same second like SAZ .928/.942
sec2 = int(time.time()) + MINT_SKEW
c2 = fmt0530(sec2 - 1, 928)
s2sent = fmt0530(sec2 - 1, 942)
ins2 = fmt0530(sec2 - 170, 774)
st2, n2, b2 = mint(sec2, c2, gps.encode(), auid.encode(), ins2)
print("session mint", st2, n2, "sec", sec2, "created", c2.decode())
ses = dict(S1P)
ses.update({"gps_adid": gps, "android_uuid": auid, "created_at": c2.decode(), "sent_at": s2sent.decode(),
 "installed_at": fmt0530(sec2 - 170, 774).decode(), "updated_at": fmt0530(sec2 - 170, 774).decode()})
ses.update(DEV)  # CPH2585 wire values
s2, r2 = send("https://app.adjust.com/session", ses, b2)
print("SESSION:", s2, r2[:300])
print("  header_sec", sec2, "send_skew~", int(time.time()) - sec2)
time.sleep(3)
# 2b. SDK_INFO — 21 params, source=push, like SAZ S3
sec2b = int(time.time()) + MINT_SKEW
c2b = fmt0530(sec2b - 1, 550)
s2bsent = fmt0530(sec2b - 1, 665)
st2b, n2b, b2b = mint(sec2b, c2b, gps.encode(), auid.encode(), None)
print("sdk_info mint", st2b, n2b, "sec", sec2b)
sdk_info = {"gps_adid_attempt": "1", "wait_time": "0.0", "app_token": "jut9tib0eeps",
 "created_at": c2b.decode(), "wait_total": "0.0", "first_error": "0",
 "gps_adid": gps, "source": "push", "foreground": "1",
 "android_uuid": auid, "sent_at": s2bsent.decode(),
 "offline_mode_enabled": "0", "environment": "production",
 "needs_response_details": "1", "attribution_deeplink": "1",
 "retry_count": "0", "last_error": "0", "gps_adid_src": "service",
 "push_token": "emsp6HGsRJWM9avd-xXS5Y:APA91bFZPSOQh57RUHzVJjWwt16UALPH7mcy5IDUxdXiiXolDNry5NinRRdk5W0lLI2BnNyusb7DHeBhAbtTbHpYy4ziep7JUo2wuTgHkAR7Go4gFoVLKWI",
 "enqueue_size": "1", "tracking_enabled": "1"}
s2b, r2b = send("https://app.adjust.com/sdk_info", sdk_info, b2b)
print("SDK_INFO:", s2b, r2b[:300])
print("  header_sec", sec2b, "send_skew~", int(time.time()) - sec2b)
time.sleep(3)
# 3. ATTRIBUTION — exact S4 23 params
sec3 = int(time.time()) + MINT_SKEW
c3 = fmt0530(sec3 - 1, 666)
s3sent = fmt0530(sec3 - 1, 696)
st3, n3, b3 = mint(sec3, c3, gps.encode(), auid.encode(), None)
attr = {"gps_adid_attempt": "1", "api_level": DEV["api_level"], "app_version": DEV["app_version"],
 "app_token": "jut9tib0eeps", "created_at": c3.decode(), "device_type": "phone",
 "gps_adid": gps, "foreground": "1", "device_name": DEV["device_name"], "needs_response_details": "1",
 "gps_adid_src": "service",
 "push_token": "emsp6HGsRJWM9avd-xXS5Y:APA91bFZPSOQh57RUHzVJjWwt16UALPH7mcy5IDUxdXiiXolDNry5NinRRdk5W0lLI2BnNyusb7DHeBhAbtTbHpYy4ziep7JUo2wuTgHkAR7Go4gFoVLKWI",
 "initiated_by": "backend", "os_version": DEV["os_version"], "android_uuid": auid,
 "sent_at": s3sent.decode(), "offline_mode_enabled": "0", "environment": "production",
 "attribution_deeplink": "1", "package_name": "com.penti.app", "os_name": "android",
 "ui_mode": "1", "tracking_enabled": "1"}
s3, r3 = send("https://app.adjust.com/attribution", attr, b3, method="GET")
print("ATTR:", s3, r3[:2000])
json.dump({"gps": gps, "auid": auid, "click_id": click_id, "reftag": reftag, "referrer": ref,
  "click": [s1, r1[:1000]], "session": [s2, r2[:1000]], "sdk_info": [s2b, r2b[:500]], "attr": [s3, r3[:2000]]},
  open(os.path.join(HERE, "tracker_chain2_result.json"), "w"), indent=1)
print("saved tracker_chain2_result.json")
