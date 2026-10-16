# adj7android emu signer CLI — signs one request via the unicorn emulation of
# the genuine 3.62.0 libsigner.so (byte-identical across hanaf/hunch/mitra).
#
#   python sign_emu_cli.py --app hanaf --kind session --second 1791358552 \
#          --params-file params.json
#   python sign_emu_cli.py --app hunch --kind attribution --second N \
#          --params "k1=v1,k2=v2"
import sys, os, json, argparse, urllib.parse, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "emu"))
from sign_emu import Emu

APPS = json.load(open(os.path.join(HERE, "apps.json")))

def sign(app, params, kind, second=None, nonce=None):
    cfg = APPS[app]
    p = dict(params)
    p.setdefault("activity_kind", kind)
    p.setdefault("client_sdk", cfg["client_sdk"])
    p.setdefault("app_token", cfg["app_token"])
    p.setdefault("package_name", cfg["package_name"])
    e = Emu(apk_path=os.path.join(HERE, cfg["apk"]),
            package=cfg["package_name"])
    if nonce:
        e.nonce12 = bytes.fromhex(nonce) if isinstance(nonce, str) else nonce
    blob = e.run(payload=bytes(32), mapobj=p,
                 second=second if second is not None else int(time.time()))
    if blob is None:
        raise RuntimeError("nSign returned NULL")
    return ('Signature signature="%s",adj_signing_id="1300000",'
            'algorithm="adj7",headers_id="8",native_version="3.62.0"'
            % blob.hex().upper()), blob

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, choices=list(APPS))
    ap.add_argument("--kind", default="session")
    ap.add_argument("--second", type=int, default=None)
    ap.add_argument("--nonce", default=None, help="12-B hex to force")
    ap.add_argument("--params", default="",
                    help="k=v pairs comma separated (urldecoded)")
    ap.add_argument("--params-file", default=None)
    A = ap.parse_args()
    params = {}
    if A.params_file:
        params = json.load(open(A.params_file))
    if A.params:
        for kv in A.params.split(","):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
    hdr, blob = sign(A.app, params, A.kind, A.second, A.nonce)
    print(hdr)
    print("blob:", blob.hex().upper())
