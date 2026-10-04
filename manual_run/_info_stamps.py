"""_info_stamps.py -- rows 4/5 are retries of the same info package; the only
claimed field that can differ between retries is created_at.  Solve their
created_at millisecond stamps with the block oracle, using the row-3 law.
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

def claims_for(val):
    parts = [val[k] for k in PROFILE_KEYS] + [PIN] + [val[k] for k in TAIL_KEYS] + [BLOCK2]
    return "".join(parts).encode("latin1")

base = dict(info[0]["map"])

# sanity: row 3 with its own map
c3 = claims_for(base)
print("row3 ok:", P.record_block(info[0]["head"], info[0]["seed"], c3,
                                info[0]["cert"]) == info[0]["block"])

for r in info[1:]:
    hit = None
    for sec in range(48, 56):
        for ms in range(1000):
            val = dict(base)
            val["created_at"] = "2026-09-09T13:40:%02d.%03dZ+0200" % (sec, ms)
            c = claims_for(val)
            if P.record_block(r["head"], r["seed"], c, r["cert"]) == r["block"]:
                hit = val["created_at"]
                break
        if hit:
            break
    print("row ts=%d created_at=%s" % (r["ts"], hit))
