import json, sys
sys.path.insert(0, ".")
import fill_probe

D = fill_probe.E.DEF_CFG
SPECS = [
    # T identical to base (sec+1, usec-1): if region == base, F = F(T) only
    {"tag": "Tsame", "cfg": {"sec": 1789240513, "usec": 499999}},
    # config bridge: does the T-invariant base move with cert/package/pid/tls/guard?
    {"tag": "sha1_vary", "cfg": {"cert_sha1": bytes((i * 5 + 2) & 0xFF for i in range(20))}},
    {"tag": "cert_vary", "cfg": {"cert": bytes((i * 3 + 9) & 0xFF for i in range(1054))}},
    {"tag": "pkg_vary",  "cfg": {"package": "com.other.app"}},
    {"tag": "pidtid",    "cfg": {"pid": 12346, "tid": 12347}},
    {"tag": "tls_vary",  "cfg": {"tls_base": 0x111110000}},
    {"tag": "guard_vary","cfg": {"stack_guard": 0x1122334455667789}},
    {"tag": "srand2",    "cfg": {"srand_seed": 2}},
]
fill_probe.main_runs(SPECS)
