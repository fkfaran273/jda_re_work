"""_info_stamps2.py -- wider retry search for rows 4/5: created_at over a wide
range, push_token present/absent, source variants.
"""
import json, struct, sys
sys.path.insert(0, r"C:\Users\Apps\Downloads\com.penti.app\manual_run")
import adj9_pure as P
import adj9_decode as D

rows = json.load(open(r"C:\Users\Apps\Downloads\com.penti.app\manual_run\event_vectors.json"))
info = [r for r in rows if r["map"]["activity_kind"] == "info"]
for r in info:
    blob = bytes.fromhex(r["blob"])
    rec = D.whiten_body_inverse(blob[16:160], blob[:16])
    r["head"] = rec[3:19]
    r["cert"] = rec[25:45]
    r["block"] = rec[46:78]
    r["seed"] = struct.unpack(">I", rec[20:24])[0]

PROFILE_KEYS = ["adj_verification", "android_uuid", "app_token", "created_at",
                "environment", "gps_adid", "gps_adid_src", "push_token"]
TAIL_KEYS = ["source", "tracking_enabled"]
BLOCK2 = "infoandroid5.7.0105.0.0"
PIN = "1500000"

def claims_for(val, keys_p=PROFILE_KEYS, keys_t=TAIL_KEYS):
    parts = [val[k] for k in keys_p if val.get(k)] + [PIN] + \
            [val[k] for k in keys_t if val.get(k)] + [BLOCK2]
    return "".join(parts).encode("latin1")

base = dict(info[0]["map"])

for r in info[1:]:
    hit = None
    for sec in range(40, 100):
        mm = 40 + sec // 60
        ss = sec % 60
        for ms in range(1000):
            for push in (True, False):
                val = dict(base)
                val["created_at"] = "2026-09-09T13:%02d:%02d.%03dZ+0200" % (mm, ss, ms)
                if not push:
                    del val["push_token"]
                c = claims_for(val)
                if P.record_block(r["head"], r["seed"], c, r["cert"]) == r["block"]:
                    hit = (val["created_at"], push)
                    break
            if hit:
                break
        if hit:
            break
    print("row ts=%d hit=%s" % (r["ts"], hit))
