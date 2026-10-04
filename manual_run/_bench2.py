"""Alternating A/B benchmark: pristine original vs working adj9_signature."""
import importlib, os, struct, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import _gate

def build(mod, kind):
    cfg = _gate.load_cfg(); mod.configure_app(cfg)
    import json
    dev = json.load(open(os.path.join(HERE, "device_data.json"), encoding="utf-8"))
    if kind == "session":
        params = mod.build_session_request(_gate.GAID, _gate.UUID, dev, cfg, _gate.T_CLICK)
    else:
        params = mod.build_click_request(_gate.GAID, _gate.UUID, dev, cfg, _gate.T_CLICK,
                                         "https://play.google.com/store/apps/details"
                                         "?id=com.penti.app&referrer=utm_source%3Dgoogle")
    return params

def mint(mod, params, kind):
    t = time.perf_counter()
    blob, sec, info = mod.sign_request(params, kind, second=_gate.SECOND, seed=_gate.SEED)
    return time.perf_counter() - t, blob, info

ORIG = importlib.import_module("_orig_adj9_signature")
NEW = importlib.import_module("adj9_signature")

kind = sys.argv[1] if len(sys.argv) > 1 else "session"
po, pn = build(ORIG, kind), build(NEW, kind)
res = {"orig": [], "new": []}
blobs = {}
for rep in range(2):                      # two passes, alternating order
    order = ("orig", "new") if rep == 0 else ("new", "orig")
    for who in order:
        mod, p = (ORIG, po) if who == "orig" else (NEW, pn)
        dt, blob, info = mint(mod, p, kind)
        res[who].append(dt)
        blobs.setdefault(who, blob)
        assert blobs[who] == blob, "non-deterministic!"
print("kind =", kind)
for who in ("orig", "new"):
    ts = res[who]
    print("  %-5s best %.2fs  runs %s" % (who, min(ts), ["%.2f" % t for t in ts]))
print("  speedup (best-of-2): %.2fx" % (min(res["orig"]) / min(res["new"])))
print("  blobs identical:", blobs["orig"] == blobs["new"])
