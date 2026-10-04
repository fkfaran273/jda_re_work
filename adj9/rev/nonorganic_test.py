"""nonorganic_test.py — real non-organic test: session -> sdk_click (custom referrer) -> attribution.

Strategy (per slices 81-84): server does NOT strictly verify body vs claims
(0/44 verifiable). Body must only TERMINATE (captured H + zeros/captured #0)
+ header law must hold (second = created_at+1). Cleartext params (referrer,
gps_adid) drive attribution. So we mint session-shaped bodies via FinEx for
each call's second and send endpoint-specific cleartext.
"""
import base64, datetime, json, struct, sys, time, urllib.parse, urllib.request, uuid, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fin_vm2 import FinEx
from header_gen import make_header

D = json.load(open(os.path.join(HERE, "fin_descs.json")))
BASE = {d["build_idx"]: d for d in D["descs"]}
ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
GOLD = json.load(open(os.path.join(HERE, "golden_saz.json")))
S1P = GOLD["s1"]["params"]
S2P = GOLD["s2"]["params"]

REFERRER = "adjust_reftag=cecj4NzaW9PxE&utm_source=VKM+Digital+Yeni&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic"

def ts_fmt(dt):
    # 29 chars like 2026-09-12T21:15:11.678Z+0200 (keep length!)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200")

def swap_ts(raw: bytes, olds, new: bytes) -> bytes:
    for o in olds:
        if raw.count(o) >= 1:
            assert len(o) == len(new), (o, new)
            raw = raw.replace(o, new)
    return raw

def mint(second, created_new: bytes):
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"])) for d in D["descs"]}
    d10 = by[10][1]
    d10 = swap_ts(d10, [b"2026-09-12T21:15:11.678Z+0200"], created_new)
    if d10.count(b"2026-09-12T21:15:11.738Z+0200"):
        # sent twin: +60ms, same second shape
        sent_new = created_new[:20] + b"738Z+0200" if False else None
    by[10] = (len(d10)//4, d10)
    descs = [(by[i][0], 0, by[i][1]) for i in ORDER]
    ex = FinEx(second, descs)
    status = ex.run(max_steps=20_000_000)
    from collections import defaultdict
    sinks = defaultdict(dict)
    for (sva, n, v) in ex.emit_trace:
        sinks[sva][n] = v
    f0 = sinks.get(0x5500000000, {})
    blob = b"".join(struct.pack(">I", f0.get(i, 0)) for i in range(48))
    assert blob[:16] == make_header(second), "header law broken"
    return status, ex.steps, blob

def send(url, params, blob, method="POST"):
    sig = base64.b64encode(blob).decode()
    auth = ('Signature signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig)
    if method == "POST":
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=data, method="POST")
    else:
        qs = urllib.parse.urlencode(params)
        req = urllib.request.Request(url + "?" + qs, method="GET")
    req.add_header("Authorization", auth)
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)")
    if method == "POST":
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except Exception as e:
        try:
            return "ERR", e.read().decode("utf-8", "replace")[:2000]
        except Exception:
            return "ERR", str(e)[:2000]

def main():
    gps = str(uuid.uuid4())
    auid = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc)
    sec_session = int(now.timestamp())
    created_s = ts_fmt(now - datetime.timedelta(seconds=1)).encode()
    print("fresh gps_adid", gps)
    print("fresh android_uuid", auid)
    print("session second", sec_session, "created", created_s.decode())

    st, steps, blob_s = mint(sec_session, created_s)
    print("session mint", st, steps, blob_s.hex()[:32])

    sess_params = dict(S1P)
    sess_params.update({
        "gps_adid": gps, "android_uuid": auid,
        "created_at": created_s.decode(),
        "sent_at": (now.strftime("%Y-%m-%dT%H:%M:%S.060Z+0200")),
        "installed_at": (now - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z+0200"),
        "updated_at": (now - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z+0200"),
    })
    c1, r1 = send("https://app.adjust.com/session", sess_params, blob_s)
    print("SESSION:", c1, r1[:500])
    time.sleep(2)

    sec_click = int(time.time())
    created_c = ts_fmt(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)).encode()
    st2, steps2, blob_c = mint(sec_click, created_c)
    print("click mint", st2, steps2, blob_c.hex()[:32])

    click_params = dict(S2P)
    now2 = datetime.datetime.now(datetime.timezone.utc)
    click_params.update({
        "gps_adid": gps, "android_uuid": auid,
        "created_at": created_c.decode(),
        "sent_at": now2.strftime("%Y-%m-%dT%H:%M:%S.970Z+0530") if False else now2.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200"),
        "installed_at": sess_params["installed_at"],
        "referrer": REFERRER,
        "source": "install_referrer",
        "referrer_api": "google",
        "click_time": now2.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530"),
        "click_time_server": now2.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530"),
        "install_begin_time": now2.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530"),
        "install_begin_time_server": now2.strftime("%Y-%m-%dT%H:%M:%S.000Z+0530"),
    })
    c2, r2 = send("https://app.adjust.com/sdk_click", click_params, blob_c)
    print("CLICK:", c2, r2[:500])
    time.sleep(2)

    sec_attr = int(time.time())
    created_a = ts_fmt(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)).encode()
    st3, steps3, blob_a = mint(sec_attr, created_a)
    print("attr mint", st3, steps3, blob_a.hex()[:32])

    attr_params = {
        "gps_adid": gps, "android_uuid": auid,
        "app_token": "jut9tib0eeps",
        "created_at": created_a.decode(),
        "sent_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z+0200"),
        "environment": "production", "os_name": "android",
        "package_name": "com.penti.app",
        "needs_response_details": "1",
        "attribution_deeplink": "1",
        "tracking_enabled": "1",
        "initiated_by": "backend",
        "gps_adid_attempt": "1", "gps_adid_src": "service",
        "api_level": "31", "os_version": "12",
        "device_type": "phone",
    }
    c3, r3 = send("https://app.adjust.com/attribution", attr_params, blob_a, method="GET")
    print("ATTRIBUTION:", c3, r3[:2000])

    out = {"gps_adid": gps, "android_uuid": auid, "referrer": REFERRER,
           "session": {"status": c1, "body": r1[:2000]},
           "click": {"status": c2, "body": r2[:2000]},
           "attribution": {"status": c3, "body": r3[:2000]}}
    json.dump(out, open(os.path.join(HERE, "nonorganic_result.json"), "w"), indent=1)
    print("saved nonorganic_result.json")
    # verdict
    try:
        j = json.loads(r3)
        print("attribution json keys:", list(j.keys()))
        print(json.dumps(j, indent=1)[:2000])
        tr = j.get("tracker_token") or j.get("tracker") or j.get("attribution", {})
        print("tracker_token:", j.get("tracker_token"), "tracker_name:", j.get("tracker_name"),
              "campaign:", (j.get("attribution") or {}).get("campaign") if isinstance(j.get("attribution"), dict) else None)
    except Exception as e:
        print("attribution not JSON:", e)

if __name__ == "__main__":
    main()
