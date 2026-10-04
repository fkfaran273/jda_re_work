"""_info_search2.py -- per-row oracle search over the collapsed space, plus
expanded variants: PIN position, 'algorithm' pinned, double activity_kind,
extra pinned value strings at any position.
"""
import itertools, json, struct, sys
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

POOL10 = sorted(["adj_verification", "android_uuid", "app_token", "created_at",
                 "environment", "gps_adid", "gps_adid_src", "push_token",
                 "source", "tracking_enabled"])
PIN = "1500000"
BLOCK2 = "infoandroid5.7.0105.0.0"

def block_ok(row, claims):
    if isinstance(claims, str):
        claims = claims.encode("latin1")
    return P.record_block(row["head"], row["seed"], claims, row["cert"]) == row["block"]

def search_row(row, label):
    val = row["map"]
    V = lambda ks: "".join(val[k] for k in ks)
    hits = []
    # P/T split space with PIN between, PIN optional handled by empty P/T
    for states in itertools.product(range(3), repeat=10):
        pk = [POOL10[i] for i in range(10) if states[i] == 0]
        tk = [POOL10[i] for i in range(10) if states[i] == 1]
        for use_pin in (True, False):
            mid = PIN if use_pin else ""
            claims = V(pk) + mid + V(tk) + BLOCK2
            if block_ok(row, claims):
                hits.append(("PT", use_pin, pk, tk))
        # also global-sorted with PIN at each slot
        ks = sorted(pk + tk)
        for pos in range(len(ks) + 1):
            claims = V(ks[:pos]) + PIN + V(ks[pos:]) + BLOCK2
            if block_ok(row, claims):
                hits.append(("PINslot", pos, ks))
    print("%s: hits=%d" % (label, len(hits)))
    for h in hits[:10]:
        print("   ", h)
    return hits

for i, r in enumerate(info):
    search_row(r, "info row ts=%d" % r["ts"])
