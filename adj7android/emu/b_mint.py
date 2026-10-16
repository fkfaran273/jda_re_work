# b_mint.py — cache deterministic mints from sign_emu.Emu (my own runner).
# Usage: python b_mint.py [--params JSON] [--second N] [--tag name]
# Caches to b_mints.json so later scripts don't re-pay 30-90 s per mint.
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sign_emu import Emu

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "b_mints.json")

P1 = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
      "activity_kind": "session", "client_sdk": "android5.6.0"}
P2 = {"app_token": "smxi7gqwu39c", "package_name": "in.hanafintech",
      "activity_kind": "attribution", "client_sdk": "android5.6.0",
      "gps_adid": "3891465c-0f39-4e95-9846-39aa605c7a93"}


def load():
    if os.path.exists(CACHE):
        return json.load(open(CACHE))
    return {}


def key(params, second):
    return json.dumps([params, second], sort_keys=True)


def mint(params, second, use_cache=True):
    db = load()
    k = key(params, second)
    if use_cache and k in db:
        return bytes.fromhex(db[k])
    t0 = time.time()
    e = Emu()
    out = e.run(payload=bytes(32), mapobj=dict(params), second=second)
    if out is None:
        raise RuntimeError("mint failed")
    db[k] = out.hex()
    json.dump(db, open(CACHE, "w"))
    sys.stderr.write("minted %dB in %.1fs\n" % (len(out), time.time() - t0))
    return out


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", default=None)
    ap.add_argument("--second", type=int, required=True)
    ap.add_argument("--set", dest="which", default="p1",
                    help="p1|p2|raw json via --params")
    A = ap.parse_args()
    p = json.loads(A.params) if A.params else (P1 if A.which == "p1" else P2)
    b = mint(p, A.second)
    print("blob(%d) %s" % (len(b), b.hex().upper()))
    print("header:", b[:16].hex().upper())
    print("body  :", b[16:272].hex()[:64], "...")
    print("tag   :", b[272:304].hex().upper())
