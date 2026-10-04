import json, sys
sys.path.insert(0, ".")
import fill_probe

D = {"sec": 1789240512, "time_sec": 1789240512, "nsec": 500000000, "usec": 500000,
     "width": 1080, "height": 2400}
SPECS = [
    {"tag": "base2"},                                        # determinism re-run with hook
    {"tag": "nsec+1",      "cfg": {"nsec": 500000001}},
    {"tag": "nsec-1",      "cfg": {"nsec": 499999999}},
    {"tag": "nsec+1000",   "cfg": {"nsec": 500001000}},
    {"tag": "nsec+1ms",    "cfg": {"nsec": 501000000}},
    {"tag": "nsec+2ms",    "cfg": {"nsec": 502000000}},
    {"tag": "sec+1",       "cfg": {"sec": 1789240513, "time_sec": 1789240513}},
    {"tag": "usec+1",      "cfg": {"usec": 500001}},
    {"tag": "width+1",     "cfg": {"width": 1081}},
    {"tag": "height+1",    "cfg": {"height": 2401}},
    {"tag": "prop_model",  "cfg": {"props": dict(fill_probe.E.DEF_CFG["props"], **{"ro.product.model": "M2101K9GX"})}},
    {"tag": "env_val",     "cfg": {"strvals": dict(fill_probe.E.DEF_CFG["strvals"], environment="sandbox")}},
    {"tag": "hmac_flip",   "cfg": {"hmac": bytes([fill_probe.E.DEF_CFG["hmac"][0] ^ 1]) + fill_probe.E.DEF_CFG["hmac"][1:]}},
    {"tag": "androidid",   "cfg": {"strvals": dict(fill_probe.E.DEF_CFG["strvals"], android_id="9a7c4e2b1d5f8036")}},
]
fill_probe.main_runs(SPECS)
