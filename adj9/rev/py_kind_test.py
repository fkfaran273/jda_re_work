# py_kind_test.py - WHICH RECORD does the app sign for an /attribution poll?
#
# py_ladder measured: our 21-key ATTRIBUTION-law re-mint of a genuine /attribution
# payload (identical claim values, identical second) is NOT recognized (200),
# while the genuine blob is (400). py_h4 measured: #4 = the real keystore MAC is
# not recognized either. So the difference is inside the signed record.
#
# This arm asks the one remaining *kind* question: perhaps the app signs the
# SESSION record (27 keys - the law that IS byte-verified, slices 96/106) even
# when polling /attribution, with the install-time facts filled from the device's
# own constants. One mint, one send, authoritative tag.
#
#   python py_kind_test.py
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.stdout.reconfigure(line_buffering=True)
import adj9_forge as F
from desc10_law import desc10_keys

UA = "Dalvik/2.1.0 (Linux; U; Android 12; moto g42 Build/S2SE32.28-28-4)"
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OUT = os.path.join(HERE, "py_kind_result.json")
# the device's own install-time constants (device/gold6.json + the SDK header set)
FILL = {"adj_signing_id": "1500000", "client_sdk": "android5.7.0",
        "headers_id": "10", "native_version": "5.0.0",
        "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
        "hardware_name": "S2SE32.28-28-4", "os_build": "S2SE32.28-28-4",
        "store_name_from_system": "com.android.vending",
        "initiating_package_name": "com.android.vending",
        "installed_at": "2026-09-14T17:52:12.431Z+0530",
        "updated_at": "2026-09-14T17:52:12.431Z+0530",
        "session_count": "1"}


def send(params, blob):
    req = urllib.request.Request(
        "https://app.adjust.com/attribution?%s" % urllib.parse.urlencode(params),
        method="GET")
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("Authorization", F.auth_header(blob))
    req.add_header("User-Agent", UA)
    req.add_header("Accept-Encoding", "identity")
    try:
        with DIRECT.open(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)


def tag(c):
    return "RECOGNIZED(400)" if c == 400 else (
        "not-recognized(200)" if c == 200 else "HTTP %s" % c)


def main():
    G = json.load(open(os.path.join(HERE, "fresh_genuine.json"), encoding="utf-8"))
    val = {k: v[0] for k, v in urllib.parse.parse_qs(
        G["query"].split("?", 1)[1], keep_blank_values=True).items()}
    blob_gen = bytes.fromhex(G["blob_hex"])
    second = 1789474915

    val_s = dict(FILL)
    val_s.update(val)
    val_s["activity_kind"] = "session"
    keys = desc10_keys("session", val_s)
    missing = [k for k in keys if not val_s.get(k)]
    print("session-law claim set: %d values; missing: %s"
          % (len(keys), missing or "NONE"))
    if missing:
        return 1
    t0 = time.time()
    st, blob_s, desc, unp = F.make_signature_law(val_s, "session", second=second)
    print("mint kind=session : status=%s #10=%dB (unpadded %d) %.1fs"
          % (st, len(desc), unp, time.time() - t0))
    d = [i for i in range(48)
         if blob_s[i * 4:i * 4 + 4] != blob_gen[i * 4:i * 4 + 4]]
    print("  vs genuine blob: differing=%d/48" % len(d))

    res = {"desc10_len": len(desc), "unpadded": unp, "diff": len(d)}
    for label, blob in (("CONTROL genuine verbatim", blob_gen),
                        ("OUR mint, record = SESSION law", blob_s)):
        c, b = send(val, blob)
        print("  %-34s -> %-20s %s" % (label, tag(c),
                                       b.strip().replace("\r\n", "")[:90]))
        res[label] = {"http": c, "verdict": tag(c), "body": b[:300]}
        time.sleep(2)
    json.dump(res, open(OUT, "w"), indent=1)
    print("\nsaved %s" % OUT)


if __name__ == "__main__":
    main()