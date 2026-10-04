import json, os, sys, time, struct, secrets
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from canon_pack import pack                       # canonical builder (map -> text)
from fin_vm2 import FinEx
from collections import defaultdict
import importlib.util as ilu

def load(name):
    sp = ilu.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    m = ilu.module_from_spec(sp); sp.loader.exec_module(m); return m

chain = load("adj9_full_chain")                   # DEV, make_header, send/UA
DEV = chain.DEV
D = json.load(open(os.path.join(HERE, "fin_descs.json")))
TMPL = {d["build_idx"]: (d["len_dw"], bytes.fromhex(d["data_hex"]))
        for d in D["descs"]}
GOLD = json.load(open(os.path.join(HERE, "golden_saz.json")))
S1P = GOLD["s1"]["params"]

OFF_MIN = chain.OFF_MIN if hasattr(chain, "OFF_MIN") else 330
OFF_LBL = "+0530"

def fmt(ts, ms):
    import datetime as dt
    d = dt.datetime.fromtimestamp(ts, dt.timezone.utc) + dt.timedelta(minutes=OFF_MIN)
    return d.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z{OFF_LBL}").encode()

# ---- u2-style inject: fields the SDK adds to the map before signing -------
def inject(p, kind, second):
    p = dict(p)
    p["client_sdk"] = "android5.7.0"
    p["adj_verification"] = "KlcAG2cbAAsKSl1KVi0FGiJbDHMI"
    if kind == "attr":
        p["headers_id"] = "10"
        p["algorithm"] = "adj9"
        p["adj_signing_id"] = "1500000"
        p["native_version"] = "5.0.0"
    else:
        p["headers_id"] = "10"
        p["adj_signing_id"] = "1500000"
        p["native_version"] = "5.0.0"
        p["algorithm"] = "adj9"
    return p

def build_desc10(p, kind, second, ins):
    """Slot #10 = packed canonical of the map; separators/framing ruled out
    by pack_verify on 15 corpus blobs (fmtA)."""
    canon = pack(p)
    # claims wrap: adjacent-dword length prefix + text + 2 pads (VM framing,
    # see make_signature: #7=len(d10) tracks any length; text itself is d10)
    d10 = canon
    return d10

def mint_query(kind, second, p, ins):
    """Full 48-dword blob from a per-query canonical."""
    by = dict(TMPL)
    d10 = build_desc10(p, kind, second, ins)
    H = secrets.token_bytes(32)                   # random H (device does same)
    by[4] = (8, H)
    by[0] = (36, bytes(144))                      # ZERO0 env telemetry
    by[7] = (1, struct.pack(">I", len(d10)))
    by[10] = (len(d10) // 4, d10)
    ORDER = [0, 9, 8, 4, 2, 7, 10, 5, 1, 6, 3]
    ex = FinEx(second, [(by[i][0], 0, by[i][1]) for i in ORDER])
    st = ex.run(max_steps=20_000_000)
    sinks = defaultdict(dict)
    for (s, n, v) in ex.emit_trace:
        sinks[s][n] = v
    blob = b"".join(struct.pack(">I", sinks[0x5500000000].get(i, 0))
                    for i in range(48))
    assert blob[:16] == chain.make_header(second)
    return blob

def api_attr_v2(gps, auid, ins=None, ptoken=None, initiated="backend"):
    second = int(time.time())
    insd = (ins or fmt(second - 170, 774)).decode()
    p = {"initiated_by": initiated, "gps_adid_attempt": "1",
         "api_level": DEV["api_level"], "app_version": DEV["app_version"],
         "app_token": "jut9tib0eeps", "os_version": DEV["os_version"],
         "created_at": fmt(second - 1, 666).decode(), "device_type": "phone",
         "gps_adid": gps, "foreground": "1", "android_uuid": auid,
         "sent_at": fmt(second - 1, 696).decode(), "offline_mode_enabled": "0",
         "device_name": DEV["device_name"], "environment": "production",
         "needs_response_details": "1", "attribution_deeplink": "1",
         "package_name": "com.penti.app", "os_name": "android", "ui_mode": "1",
         "gps_adid_src": "service", "tracking_enabled": "1"}
    if ptoken:
        p["push_token"] = ptoken
    pinj = inject(p, "attr", second)
    blob = mint_query("attr", second, pinj, insd)
    return chain.send("https://app.adjust.com/attribution", p, blob,
                      method="GET")

if __name__ == "__main__":
    gps = sys.argv[1] if len(sys.argv) > 1 else "0e789180-17da-440b-b1c3-0349d40e0e93"
    auid = sys.argv[2] if len(sys.argv) > 2 else "205e93a4-56f9-41fd-bfa0-1edbe4245529"
    st, txt = api_attr_v2(gps, auid)
    print("FORGE-POLL", st, txt[:300])