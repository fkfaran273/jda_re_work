import json, sys
sys.path.insert(0, ".")
import fill_probe

SPECS = []
for d in (2, 3, 4, 5, 10, 100, 1000, 10000):
    SPECS.append({"tag": "T+%d" % d, "cfg": {"usec": 500000 + d}})
SPECS.append({"tag": "T-1sec", "cfg": {"sec": 1789240511, "time_sec": 1789240511}})
fill_probe.main_runs(SPECS)
