"""sign_fresh.py — end-to-end offline adj9 signed request (build mode).

Stable claims (harvested once, device/adj9-wh4) + fresh timestamps +
harvested H + chosen #0 -> FinEx merge -> Random3 header -> 192B blob
-> POST /session -> verdict. Prints each stage result.
"""
import base64
import datetime
import json
import random
import struct
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict

sys.path.insert(0, ".")
from fin_vm2 import FinEx

HERE = "C:/Users/Apps/Downloads/com.penti.app/adj9/rev"
DEV = "C:/Users/Apps/Downloads/com.penti.app/adj9/device"

D = json.load(open(HERE + "/fin_descs.json"))
BASE = {d["build_idx"]: d for d in D["descs"]}
CERT = bytes.fromhex("fad0f10d60f93c17937b2f1eb6c09691ae7d74bd")

# Stable per-device/request claims (harvested once from adj9_wh4 sign_input).
STABLE = {
    "app_token": "jut9tib0eeps",
    "android_uuid": "415606ad-7002-479b-b691-305aace409ba",
    "api_level": "31",
    "app_version": "3.13.9",
    "device_name": "moto g42",
    "device_type": "phone",
    "environment": "production",
    "gps_adid": "f476b3d4-e0b1-4707-bc43-6153d17f7f8c",
    "hardware_name": "S2SE32.28-28-4",
    "os_build": "S2SE32.28-28-4",
    "os_name": "android",
    "os_version": "12",
    "package_name": "com.penti.app",
    "store_name_from_system": "com.android.vending",
    "installed_at": "2026-09-08T12:20:49.782Z+0200",
    "updated_at": "2026-09-10T07:26:18.015Z+0200",
    "adj_verification": "KlcAG2cbAAsKSl1KVi0FGiJbDHMI",
}
# Harvested 32B H (replayable per slice 81).
H = bytes.fromhex(json.load(open(DEV + "/triples_tail7.json"))["sess_H"])


def fetch_block(created):
    parts = [STABLE["adj_verification"].encode(), STABLE["android_uuid"].encode(),
             STABLE["api_level"].encode(), STABLE["app_token"].encode(),
             STABLE["app_version"].encode(), created.encode(),
             STABLE["device_name"].encode(), STABLE["device_type"].encode(),
             STABLE["environment"].encode(), STABLE["gps_adid"].encode()]
    raw = b"".join(parts)
    return raw + b"\0" * ((-len(raw)) % 4)


def build_params(created, sent):
    p = json.load(open(HERE + "/whcap_params.json")) \
        if __import__("os").path.exists(HERE + "/whcap_params.json") else {}
    try:
        p = json.load(open(DEV + "/whcap_params.json"))
    except Exception:
        pass
    p = dict(p)
    for k, v in STABLE.items():
        p.setdefault(k, v)
    p["created_at"] = created
    p["sent_at"] = sent
    return p


def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    sec = int(now.timestamp())
    created = now.strftime("%Y-%m-%dT%H:%M:%S.000Z+0200")
    sent = now.strftime("%Y-%m-%dT%H:%M:%S.060Z+0200")
    print("1. claims ts:", created, flush=True)

    d0 = bytearray(144)
    d0[140:144] = struct.pack(">I", random.getrandbits(32))
    fetch = fetch_block(created)
    L10 = len(fetch) // 4
    by = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
          for d in D["descs"]}
    by[0] = (36, bytes(d0))
    by[4] = (8, H)
    by[10] = (L10, fetch)
    by[7] = (1, struct.pack(">I", (L10 << 2) | 0))
    order = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
    descs = [(by[i][0], 0, by[i][1]) for i in order]

    t0 = time.time()
    ex = FinEx(sec, descs)
    status = ex.run(max_steps=20_000_000)
    print("2. merge: %s steps=%d nrand=%d (%.1fs)" %
          (status, ex.steps, ex.nrand, time.time() - t0), flush=True)
    sinks = defaultdict(dict)
    for (sva, n, v) in ex.emit_trace:
        sinks[sva][n] = v
    am = sinks.get(0x5500000000, {})
    blob = b"".join(struct.pack(">I", am.get(i, 0)) for i in range(48))
    print("3. blob:", len(blob), "B, head:", blob.hex()[:32], flush=True)

    from vm_final import Random3
    r = Random3(sec)
    draws = [r.next() & 0xFFFFFFFF for _ in range(8)]
    hdr_ok = (struct.unpack(">4I", blob[:16]) ==
              tuple(draws[2 * i] ^ draws[2 * i + 1] for i in range(4)))
    print("4. header law:", hdr_ok, flush=True)

    params = build_params(created, sent)
    sig_b64 = base64.b64encode(blob).decode()
    auth = ('signature="%s",adj_signing_id="1500000",algorithm="adj9",'
            'headers_id="10",native_version="5.0.0",'
            'adj_verification="KlcAG2cbAAsKSl1KVi0FGiJbDHMI"' % sig_b64)
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request("https://app.adjust.com/session",
                                 data=data, method="POST")
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Client-SDK", "android5.7.0")
    req.add_header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 12; "
                                 "moto g42 Build/S2SE32.28-28-4)")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()[:200]
            print("5. SUBMIT:", r.status, body, flush=True)
    except Exception as e:
        print("5. SUBMIT FAILED:", e, flush=True)
        try:
            print("   body:", e.read()[:200], flush=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()
