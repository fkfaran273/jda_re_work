# session_param_diff.py - compare OUR crafted /session param set with the app's
# own genuine (booking) session map keys, from wh4_records sign_inputs.
import json
import os
import sys

HERE = r"C:\Users\Apps\Downloads\com.penti.app\adj9\rev"
sys.path.insert(0, HERE)
import adj9_full_chain as F

W = json.load(open(os.path.join(HERE, "wh4_records.json"), encoding="utf-8"))
si = W["sign_inputs"][W["golden_sign_input_idx"]]
app_keys = sorted(p.split("\x01")[0] for p in si["order"].split("\x02")
                  if "\x01" in p)

ours = set(F.S1P.keys()) | set(F.DEV.keys()) | {
    "gps_adid", "android_uuid", "created_at", "sent_at", "installed_at",
    "updated_at"}
ours -= {"no_sim", "install_version"}

app = set(app_keys)
print("app genuine session keys: %d | ours: %d" % (len(app), len(ours)))
print("\nMISSING FROM OURS (in the app's session, not sent by us):")
for k in sorted(app - ours):
    print("   ", k)
print("\nEXTRA IN OURS (we send what the app does not):")
for k in sorted(ours - app):
    print("   ", k)
print("\nS1P has %d keys; DEV(%s) has %d keys"
      % (len(F.S1P), F.DEV.get("device_name"), len(F.DEV)))