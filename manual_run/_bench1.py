"""Time ONE module in its own process: python -u _bench1.py <orig|new> <kind>"""
import importlib, json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import _gate
which, kind = sys.argv[1], sys.argv[2]
mod = importlib.import_module("_orig_adj9_signature" if which == "orig" else "adj9_signature")
cfg = _gate.load_cfg(); mod.configure_app(cfg)
dev = json.load(open(os.path.join(HERE, "device_data.json"), encoding="utf-8"))
if kind == "session":
    p = mod.build_session_request(_gate.GAID, _gate.UUID, dev, cfg, _gate.T_CLICK)
else:
    p = mod.build_click_request(_gate.GAID, _gate.UUID, dev, cfg, _gate.T_CLICK,
                                "https://play.google.com/store/apps/details?id=com.penti.app&referrer=utm_source%3Dgoogle")
t = time.perf_counter()
blob, sec, info = mod.sign_request(p, kind, second=_gate.SECOND, seed=_gate.SEED)
dt = time.perf_counter() - t
import hashlib
print("%s %s %.3f %d %s" % (which, kind, dt, info["steps"], hashlib.sha256(blob).hexdigest()[:16]))
